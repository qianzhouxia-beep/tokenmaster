"""TokenMaster v5 M2 + M3 - FastAPI webhook backend.

Endpoints:
    GET  /                            health check
    POST /create-order                create checkout (sku + email + payment_method)
    GET  /orders/{order_id}           look up an order
    POST /paypal-webhook              PayPal checkout/order events (signed)
    POST /nowpayments-webhook         NOWPayments IPN (HMAC-SHA512)
    POST /test-redeem                 M3 sandbox: mint 1 redemption code

Signature verification uses pure Python (`requests` for cert fetch + `cryptography`
for RSA-SHA256) - no paypal-checkout-sdk / paypalrestsdk to avoid the Java
transitive. Details in m2-spec.md.

M3 (auto-redeem) lives in `redeem.py` — this file imports `redeem.create_redemption`
and wires it into the PayPal + NOWPayments webhook paths.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid

import requests
import zlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field

import db
import newapi_auth
import redeem

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("tokenmaster.webhook")

PAYPAL_API_BASE = os.environ.get("PAYPAL_API_BASE", "https://api-m.paypal.com")

PAYPAL_CLIENT_ID = os.environ.get("PAYPAL_CLIENT_ID", "")
PAYPAL_CLIENT_SECRET = os.environ.get("PAYPAL_CLIENT_SECRET", "")
PAYPAL_WEBHOOK_ID = os.environ.get("PAYPAL_WEBHOOK_ID", "")
NOWPAYMENTS_API_KEY = os.environ.get("NOWPAYMENTS_API_KEY", "")
NOWPAYMENTS_IPN_SECRET = os.environ.get("NOWPAYMENTS_IPN_SECRET", "")
NEW_API_BASE_URL = os.environ.get("NEW_API_BASE_URL", "https://api-tokenmaster.com")
# v6.1: session-cookie and root-credential resolution now lives in
# `newapi_auth.py` so `redeem.py` can share the same auto-login logic
# without an import cycle. NEW_API_ROOT_USERNAME / NEW_API_ROOT_PASSWORD
# enable auto-login as a fallback when the static session cookie is
# missing or expired (HTTP 401), eliminating the 30-day manual rotation.
_paypal_token = {"access_token": None, "expires_at":0}

# v6.18: PayPal client timeout 3s. v6.17 set it to 5s; in production the
# Zeabur → api-m.paypal.com round-trip + Cloudflare 502 early-bail on
# ~3s boundary means anything > ~3s gets converted to 502 by the Cloudflare
# proxy before our handler can return a real 5xx. 3s gives the upstream
# two TCP retransmits worth of headroom and still fits inside the early-502
# window so we control the failure mode.
PAYPAL_TIMEOUT_S = 3

# v6.18: fallback payment_url returned by /create-order + /checkout/redirect
# when the PayPal / NOWPayments call fails. Frontend can still navigate the
# user to the PayPal sandbox homepage so the page is not stuck on a blank
# 502. Toggled by the JSON body's `fallback: true` flag.
_FALLBACK_PAYMENT_URL = "https://www.sandbox.paypal.com/"

# v6 c-path: New API QuotaPerUnit (default 500_000 = 1 USD). Fetched at startup
# from /api/option/?key=QuotaPerUnit with the admin session cookie. Falls back
# to 500_000 if fetch fails (no cookie / 401 / network).
_quota_per_unit: int = 500_000

app = FastAPI(title="TokenMaster v5 Webhook", version="v5")


# v6.18: global exception handler — converts any unhandled 5xx to a JSON
# payload with a short traceback_id so the operator can correlate it to a
# `log.exception` line in stderr. Without this, FastAPI returns a bare
# {"detail": "Internal Server Error"} which makes root-causing the Zeabur
# 502 impossible from outside.
@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception):
    tb_id = uuid.uuid4().hex[:8]
    log.exception(
        "unhandled exception tb_id=%s path=%s method=%s",
        tb_id, request.url.path, request.method,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "internal", "traceback_id": tb_id},
    )

# v6.14: CORS for the landing page (which lives on api-tokenmaster.com
# via Cloudflare reverse proxy) to call /create-order on the webhook
# service (pay.api-tokenmaster.com). Without this, the browser blocks
# the cross-origin fetch from the iframe.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://api-tokenmaster.com",
        "https://pay.api-tokenmaster.com",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.on_event("startup")
def _startup() -> None:
    db.init_db()
    # v5 M5: also serve the landing page as static files at /landing/* so
    # one Zeabur service owns both the marketing site and the webhook API.
    # The landing files are vendored under webhook/landing/ at deploy time
    # (see deploy/deploy-v5.md for the deploy bundle layout).
    import pathlib
    landing_dir = pathlib.Path(__file__).parent / "landing"
    if landing_dir.is_dir():
        app.mount("/landing", StaticFiles(directory=str(landing_dir), html=True), name="landing")
        log.info("landing static mounted at /landing (dir=%s)", landing_dir)
    else:
        log.warning("landing dir not found at %s — /landing will 404", landing_dir)
    # v6.4: also mount /assets (hero.png, logo.png, enterprise-security.png) so
    # landing.html's absolute <img src="/assets/hero.png?v=1"> resolves.
    assets_dir = pathlib.Path(__file__).parent / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")
        log.info("assets static mounted at /assets (dir=%s)", assets_dir)
    else:
        log.warning("assets dir not found at %s — /assets will 404", assets_dir)
    # v6.13: site root mount for footer links (about/contact/docs/docs-api/
    # models/privacy/terms). We restrict the served directory to a sibling
    # `site/` folder and copy the 7 html files there at deploy time — that
    # way app.py, .env, db.py, redeem.py, and the rest of webhook-deploy
    # internals can NEVER be exposed even if someone guesses a path.
    site_dir = pathlib.Path(__file__).parent / "site"
    if site_dir.is_dir():
        # v6.16: mount at /site/* (not /) so it never collides with the
        # /create-order, /orders/{id}, /checkout/redirect, /paypal-webhook,
        # /nowpayments-webhook, /api/*, /test-redeem API routes.
        app.mount("/site", StaticFiles(directory=str(site_dir), html=True), name="site")
        log.info("site static mounted at /site (dir=%s)", site_dir)
    else:
        log.warning("site dir not found at %s — footer links will 404", site_dir)
    # v6 c-path: fetch QuotaPerUnit for USD→quota conversion. Best-effort; on
    # any failure (no cookie / 401 / network) we keep the 500_000 default.
    global _quota_per_unit
    _quota_per_unit = _fetch_quota_per_unit()
    log.info("webhook service ready v5 (c-path QuotaPerUnit=%d)", _quota_per_unit)


@app.get("/")
def health() -> dict:
    return {"status": "ok", "version": "v5"}


# v6.28.5: serve the TokenMaster brand logo as /favicon.ico so the browser
# tab + bookmark + address-bar icon shows the brand instead of New API's
# default one. We re-use assets/logo.png (PNG body, content-type declared as
# image/x-icon — browsers accept PNG bytes for favicons when served with
# an .ico name).
@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    from fastapi.responses import FileResponse
    logo_path = pathlib.Path(__file__).parent / "assets" / "logo.png"
    if not logo_path.is_file():
        raise HTTPException(404, "logo not found")
    return FileResponse(
        path=str(logo_path),
        media_type="image/x-icon",
        headers={"Cache-Control": "public, max-age=86400"},
    )


class CreateOrderIn(BaseModel):
    email: EmailStr
    sku_id: str
    payment_method: str
    newapi_username: str | None = None  # v6.28: New API username (when buyer is signed in)


class CreateOrderOut(BaseModel):
    order_id: str
    payment_url: str
    provider_order_id: str
    payment_method: str
    usd_amount: int


def _paypal_get_access_token() -> str:
    if _paypal_token["access_token"] and _paypal_token["expires_at"] > time.time() +60:
        return _paypal_token["access_token"]
    if not PAYPAL_CLIENT_ID or not PAYPAL_CLIENT_SECRET:
        raise HTTPException(500, "PayPal creds missing in env")
    auth = base64.b64encode(f"{PAYPAL_CLIENT_ID}:{PAYPAL_CLIENT_SECRET}".encode()).decode()
    r = requests.post(
        f"{PAYPAL_API_BASE}/v1/oauth2/token",
        headers={"Authorization": f"Basic {auth}", "Accept": "application/json"},
        data={"grant_type": "client_credentials"},
        timeout=PAYPAL_TIMEOUT_S,
    )
    r.raise_for_status()
    body = r.json()
    _paypal_token["access_token"] = body["access_token"]
    _paypal_token["expires_at"] = time.time() + int(body.get("expires_in",3600))
    return _paypal_token["access_token"]


def _paypal_create_checkout(sku, email):
    token = _paypal_get_access_token()
    payload = {
        "intent": "CAPTURE",
        "purchase_units": [
            {
                "amount": {"currency_code": "USD", "value": f"{sku['usd']:.2f}"},
                "description": sku["label"],
                "custom_id": email,
            }
        ],
        "application_context": {
            "brand_name": "TokenMaster",
            "shipping_preference": "NO_SHIPPING",
            "user_action": "PAY_NOW",
            # v6.25: return_url + cancel_url are required for PayPal to
            # know where to land the buyer AFTER the approval step. Without
            # these, the browser sometimes drops the user on
            # sandbox.paypal.com/home instead of the approve page, and the
            # buyer (qian) sees "I logged in but where is the Approve
            # button?". PayPal appends ?token=EC-XXXXX to return_url and
            # we use it to capture the order. Cancel just bounces the
            # buyer back to the landing page.
            "return_url": "https://pay.api-tokenmaster.com/paypal-return",
            "cancel_url": "https://pay.api-tokenmaster.com/paypal-cancel",
        },
    }
    r = requests.post(
        f"{PAYPAL_API_BASE}/v2/checkout/orders",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        json=payload,
        timeout=PAYPAL_TIMEOUT_S,
    )
    r.raise_for_status()
    body = r.json()
    oid = body["id"]
    approve = next(
        (link["href"] for link in body.get("links", []) if link.get("rel") == "approve"),
        None,
    )
    if not approve:
        raise HTTPException(502, f"PayPal approve link missing: {body}")
    return oid, approve


def _paypal_capture_order(token: str):
    """Capture (finalize) a PayPal order after the buyer approved.
    Returns (paypal_order_id, capture_status) or (None, None) on failure.
    v6.25: this is what /paypal-return calls so the buyer doesn't have
    to click 'Continue' a second time after PayPal bounces them back."""
    try:
        access = _paypal_get_access_token()
        r = requests.post(
            f"{PAYPAL_API_BASE}/v2/checkout/orders/{token}/capture",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access}",
            },
            json={},
            timeout=PAYPAL_TIMEOUT_S,
        )
        r.raise_for_status()
        body = r.json()
        return body.get("id"), body.get("status")
    except Exception as e:
        log.exception("paypal capture failed: %s", e)
        return None, None


def _nowpayments_create_payment(sku, email, order_id):
    if not NOWPAYMENTS_API_KEY:
        raise HTTPException(500, "NOWPayments API key missing in env")
    payload = {
        "price_amount": float(sku["usd"]),
        "price_currency": "USD",
        "pay_currency": "usdt",
        "order_id": order_id,
        "order_description": sku["label"],
        "ipn_callback_url": os.environ.get(
            "NOWPAYMENTS_IPN_URL", "https://pay.api-tokenmaster.com/nowpayments-webhook"
        ),
        "email": email,
    }
    r = requests.post(
        "https://api.nowpayments.io/v1/payment",
        headers={"x-api-key": NOWPAYMENTS_API_KEY, "Content-Type": "application/json"},
        json=payload,
        timeout=20,
    )
    r.raise_for_status()
    body = r.json()
    return str(body["payment_id"]), body.get("invoice_url") or body.get("payment_url", "")


@app.post("/create-order", response_model=CreateOrderOut)
def create_order(payload: CreateOrderIn) -> CreateOrderOut:
    if payload.sku_id not in db.SKUS:
        raise HTTPException(400, f"unknown sku_id: {payload.sku_id}")
    sku = db.SKUS[payload.sku_id]
    method = payload.payment_method.lower()
    if method not in ("paypal", "nowpayments"):
        raise HTTPException(400, "payment_method must be 'paypal' or 'nowpayments'")

    temp_order = db.create_order(
        payload.email,
        payload.sku_id,
        method,
        newapi_username=(payload.newapi_username or None),
    )

    try:
        if method == "paypal":
            pp_id, pp_url = _paypal_create_checkout(sku, payload.email)
            db.attach_provider_id(temp_order["id"], "paypal", pp_id)
            return CreateOrderOut(
                order_id=temp_order["id"],
                payment_url=pp_url,
                provider_order_id=pp_id,
                payment_method="paypal",
                usd_amount=sku["usd"],
            )
        else:
            np_id, np_url = _nowpayments_create_payment(sku, payload.email, temp_order["id"])
            db.attach_provider_id(temp_order["id"], "nowpayments", np_id)
            return CreateOrderOut(
                order_id=temp_order["id"],
                payment_url=np_url,
                provider_order_id=np_id,
                payment_method="nowpayments",
                usd_amount=sku["usd"],
            )
    except HTTPException:
        raise
    except Exception as e:
        # v6.18: instead of 502 (which the Cloudflare proxy is already
        # serving on its own after ~3s, swallowing our log.exception),
        # return 200 with a fallback payment_url + error so the browser
        # can navigate the user to the PayPal sandbox homepage. Frontend
        # sees `fallback: true` and renders "provider unavailable, please
        # retry" instead of a blank 502 page.
        log.exception("create-order failed (returning fallback 200)")
        db.mark_failed(temp_order["id"], reason=f"create-error:{type(e).__name__}")
        return JSONResponse(
            status_code=200,
            content={
                "order_id": temp_order["id"],
                "payment_url": _FALLBACK_PAYMENT_URL,
                "provider_order_id": "",
                "payment_method": method,
                "usd_amount": sku["usd"],
                "fallback": True,
                "error": "provider unavailable, please retry",
            },
        )


# v6.16: GET /checkout/redirect — server-side 302 to PayPal / NOWPayments
# URL. This is a robust fallback when the browser fails to fetch POST
# (CORS, sandboxed iframe, CSP, ad-blocker, etc.) — a plain form GET or
# a window.location = url navigation always works, no preflight, no body.
@app.get("/checkout/redirect")
def checkout_redirect(
    sku_id: str,
    email: str,
    payment_method: str,
    newapi_username: str = None,
) -> "Response":
    from fastapi.responses import RedirectResponse  # local import keeps top tidy

    if sku_id not in db.SKUS:
        raise HTTPException(400, f"unknown sku_id: {sku_id}")
    sku = db.SKUS[sku_id]
    method = payment_method.lower()
    if method not in ("paypal", "nowpayments"):
        raise HTTPException(400, "payment_method must be 'paypal' or 'nowpayments'")
    if not email or "@" not in email:
        raise HTTPException(400, "valid email required")

    # v6.28: accept optional newapi_username from the session-aware modal
    # (frontend already verified the user is signed in and has this email
    # on file). We store it alongside the order so:
    #   1. /orders/{id} can surface which New API account paid
    #   2. c-path auto-mint can be tied to that user (future)
    #   3. refund / support lookups can pivot on username
    newapi_username = (newapi_username or "").strip() or None
    if newapi_username and len(newapi_username) > 64:
        raise HTTPException(400, "newapi_username too long")
    temp_order = db.create_order(email, sku_id, method, newapi_username=newapi_username)
    try:
        if method == "paypal":
            pp_id, pp_url = _paypal_create_checkout(sku, email)
            db.attach_provider_id(temp_order["id"], "paypal", pp_id)
        else:
            np_id, np_url = _nowpayments_create_payment(sku, email, temp_order["id"])
            db.attach_provider_id(temp_order["id"], "nowpayments", np_id)
            pp_url = np_url
    except HTTPException:
        raise
    except Exception as e:
        # v6.18: same fallback contract as /create-order — return 302 to
        # the PayPal sandbox homepage so the user gets a working browser
        # navigation instead of a 502 page. Frontend can detect the
        # fallback by comparing the Location header to a known PayPal
        # origin if it needs to.
        log.exception("checkout/redirect failed (returning fallback 302)")
        db.mark_failed(temp_order["id"], reason=f"create-error:{type(e).__name__}")
        return RedirectResponse(url=_FALLBACK_PAYMENT_URL, status_code=302)

    return RedirectResponse(url=pp_url, status_code=302)


@app.get("/orders/{order_id}")
def get_order(order_id: str) -> dict:
    row = db.get_order(order_id)
    if not row:
        raise HTTPException(404, f"order {order_id} not found")
    return row


# ── v6.25: PayPal post-approval return + cancel ──────────────────────────
# After the buyer approves on PayPal, PayPal appends ?token=EC-XXXXX to
# return_url and redirects the browser here. We then capture the order
# (server-side) so the buyer doesn't have to click a second time, and
# render a tiny "processing payment…" page that polls /orders/{id} until
# the webhook marks it paid and the buyer sees the redemption code.
@app.get("/paypal-return")
def paypal_return(token: str) -> HTMLResponse:
    from fastapi.responses import HTMLResponse  # local import
    pp_id, _ = _paypal_capture_order(token)
    row = db.find_by_paypal(pp_id) if pp_id else None
    if not row:
        return HTMLResponse(
            "<h1>Order pending</h1>"
            "<p>We could not match your PayPal approval to a TokenMaster order. "
            "If you were charged, please contact billing@api-tokenmaster.com.</p>",
            status_code=200,
        )
    # v6.34: c-path is the primary fulfillment (webhook c-path grant
    # quota to user's New API account, no code needed).
    # We keep paypal-return as a fallback only when the webhook hasn't
    # fired in 8s. This protects against the case where PayPal sandbox
    # doesn't deliver a webhook (delayed/missed) but the user is
    # already on the return page. The page text also clarifies that
    # fulfillment is "direct to your New API account" not "code by
    # email" — that wording was misleading since v6.19.
    if row.get("status") == "pending":
        # Wait briefly for the webhook to flip status, then fall back
        # to direct quota grant if it still hasn't.
        import asyncio
        for _ in range(8):
            await asyncio.sleep(1) if False else None  # sync sleep below
            break
        import time as _t
        _t.sleep(8)
        row = db.get_order(row["id"]) or row
        if row.get("status") == "pending":
            log.warning(
                "paypal-return: webhook did not fire in 8s for order %s, "
                "falling back to direct quota grant",
                row["id"],
            )
            marker = _grant_quota_via_admin_api(row)
            if marker is None:
                log.error("paypal-return c-path grant failed for %s", row["id"])
            else:
                db.mark_paid(row["id"], marker)
                row = db.get_order(row["id"])
                log.info("paypal-return c-path grant ok for %s: %s", row["id"], marker)
    return HTMLResponse(
        f"""<!doctype html>
<html><head><title>TokenMaster - Payment received</title>
<meta charset='utf-8'>
<style>body{{font-family:system-ui;max-width:560px;margin:48px auto;padding:0 16px;}}</style>
</head><body>
<h1>Payment received ✓</h1>
<p>Your 20M tokens are being delivered to your New API account. This page will update when ready.</p>
<p>Order id: <code>{row['id']}</code></p>
<div id="status">Verifying payment…</div>
<script>
async function poll() {{
  for (let i = 0; i < 60; i++) {{
    const r = await fetch('/orders/{row['id']}');
    if (r.ok) {{
      const o = await r.json();
      if (o.status === 'completed' || o.status === 'paid') {{
        document.getElementById('status').innerHTML =
          'Done ✓. Your New API account has been credited 20M tokens. <br>Close this tab and go back to <a href="https://api-tokenmaster.com/">api-tokenmaster.com</a> to use them.';
        return;
      }}
      if (o.status === 'failed') {{
        document.getElementById('status').innerHTML =
          'Fulfillment failed. Please contact billing@api-tokenmaster.com if you were charged.';
        return;
      }}
    }}
    await new Promise(r => setTimeout(r, 2000));
  }}
  document.getElementById('status').textContent =
    'Still waiting. If you were charged, your tokens will appear in your New API account shortly.';
}}
poll();
</script>
</body></html>""",
        status_code=200,
    )


@app.get("/paypal-cancel")
def paypal_cancel() -> HTMLResponse:
    from fastapi.responses import HTMLResponse
    return HTMLResponse(
        "<h1>Payment cancelled</h1>"
        "<p>You can <a href='https://api-tokenmaster.com/landing/'>go back to TokenMaster</a> "
        "and try again any time.</p>",
        status_code=200,
    )


# ── PayPal signature verification (no SDK, no Java) ──────────────────────


def _fetch_paypal_cert(cert_url: str) -> bytes:
    allowed_hosts = {"api-m.paypal.com", "api.paypal.com", "api.sandbox.paypal.com"}
    if not any(cert_url.startswith(f"https://{h}") for h in allowed_hosts):
        raise HTTPException(400, f"untrusted PayPal cert URL: {cert_url}")
    r = requests.get(cert_url, timeout=10)
    r.raise_for_status()
    return r.content


def _verify_paypal_signature(headers: dict, body: bytes) -> bool:
    cert_url = headers.get("paypal-cert-url", "")
    transmission_id = headers.get("paypal-transmission-id", "")
    transmission_time = headers.get("paypal-transmission-time", "")
    transmission_sig_b64 = headers.get("paypal-transmission-sig", "")
    auth_algo = headers.get("paypal-auth-algo", "SHA256withRSA")
    if not all([cert_url, transmission_id, transmission_time, transmission_sig_b64]):
        log.warning("paypal webhook missing signature headers: %s", list(headers.keys()))
        return False
    try:
        cert_pem = _fetch_paypal_cert(cert_url)
    except Exception as e:
        log.warning("paypal cert fetch failed: %s", e)
        return False
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        pubkey = cert.public_key()
    except Exception as e:
        log.warning("paypal cert parse failed: %s", e)
        return False

    crc = zlib.crc32(body)
    expected = (
        f"{auth_algo}|{cert_url}|{transmission_id}|{transmission_time}|"
        f"{PAYPAL_WEBHOOK_ID}|{crc}"
    )
    try:
        pubkey.verify(
            base64.b64decode(transmission_sig_b64),
            expected.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        log.info("paypal signature verify failed: %s", e)
        return False


@app.post("/paypal-webhook")
async def paypal_webhook(request: Request) -> JSONResponse:
    raw = await request.body()
    headers = {k.lower(): v for k, v in request.headers.items()}

    if not _verify_paypal_signature(headers, raw):
        log.warning("paypal webhook signature rejected")
        raise HTTPException(400, "invalid paypal signature")

    try:
        event = json.loads(raw)
    except Exception as e:
        raise HTTPException(400, f"bad json: {e}")

    event_type = event.get("event_type", "")
    resource = event.get("resource", {}) or {}

    if event_type not in ("PAYMENT.CAPTURE.COMPLETED", "CHECKOUT.ORDER.APPROVED"):
        log.info("paypal event ignored: %s", event_type)
        return JSONResponse({"status": "ignored", "event_type": event_type})

    if event_type == "CHECKOUT.ORDER.APPROVED":
        pp_id = resource.get("id")
    else:
        pp_id = (
            resource.get("supplementary_data", {}).get("related_ids", {}).get("order_id")
            or resource.get("id")
        )
    order = db.find_by_paypal(pp_id) if pp_id else None
    if not order:
        log.warning("paypal webhook for unknown paypal_order_id=%s", pp_id)
        return JSONResponse({"status": "no-matching-order", "paypal_id": pp_id})

    if event_type == "PAYMENT.CAPTURE.COMPLETED":
        # v6 c-path: grant quota directly to user's New API account.
        # Replaces b-path (mint redemption code) per L1 2026-06-09 decision.
        marker = _grant_quota_via_admin_api(order)
        if marker is None:
            # c-path failed (no cookie, 401, user lookup miss, or New API
            # PUT error). Mark the order failed and return 500 to PayPal
            # so it retries the webhook per its own retry policy.
            db.mark_failed(order["id"], reason="c-path:admin-api-failed")
            log.error("paypal order %s c-path failed -> 500 to paypal for retry", order["id"])
            return JSONResponse(
                {"status": "c-path-failed", "order_id": order["id"]},
                status_code=500,
            )
        db.mark_paid(order["id"], marker)
        log.info("paypal order %s paid via c-path -> %s", order["id"], marker)

    return JSONResponse({"status": "ok", "order_id": order["id"], "event_type": event_type})


# ── NOWPayments HMAC verify + handler ────────────────────────────────────


def _verify_nowpayments_hmac(raw_body: bytes, signature_header: str) -> bool:
    if not NOWPAYMENTS_IPN_SECRET:
        log.warning("NOWPAYMENTS_IPN_SECRET not configured")
        return False
    mac = hmac.new(
        NOWPAYMENTS_IPN_SECRET.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha512,
    ).hexdigest()
    return hmac.compare_digest(mac.lower(), (signature_header or "").lower())


@app.post("/nowpayments-webhook")
async def nowpayments_webhook(
    request: Request,
    x_nowpayments_signature: str | None = Header(default=None),
) -> JSONResponse:
    raw = await request.body()
    if not _verify_nowpayments_hmac(raw, x_nowpayments_signature or ""):
        log.warning("nowpayments IPN signature rejected")
        raise HTTPException(400, "invalid nowpayments signature")

    try:
        payload = json.loads(raw)
    except Exception as e:
        raise HTTPException(400, f"bad json: {e}")

    payment_status = payload.get("payment_status", "")
    if payment_status not in ("finished", "confirmed"):
        log.info("nowpayments status ignored: %s", payment_status)
        return JSONResponse({"status": "ignored", "payment_status": payment_status})

    np_id = str(payload.get("payment_id", ""))
    order = db.find_by_nowpayments(np_id) if np_id else None
    if not order:
        log.warning("nowpayments IPN for unknown payment_id=%s", np_id)
        return JSONResponse({"status": "no-matching-order", "payment_id": np_id})

    code = _mint_redemption_code(order)
    db.mark_paid(order["id"], code)
    log.info("nowpayments payment %s paid -> code %s", np_id, (code[:8] + "***") if code else "<empty>")

    return JSONResponse({"status": "ok", "order_id": order["id"], "payment_id": np_id})


# ── Redemption code mint (M3 — calls New API via redeem.py) ──────────────


def _mint_redemption_code(order: dict) -> str:
    """Mint a New API redemption code for the order's SKU.

    Thin adapter that maps the `order` row to `(sku_id, email)` for the
    `redeem.create_redemption` contract. On `SessionExpiredError` or
    `ValueError` (unknown SKU) we fall back to a TM-FALLBACK placeholder
    so the order can still complete its DB lifecycle; the operator must
    then refresh the session / re-code the order manually. Any other
    error is re-raised so callers can decide.
    """
    # v6.19: use sku_id (e.g. "starter_v6") rather than usd_amount. The old
    # mapping passed `str(usd_amount)` which doesn't match the new 6-tier
    # QUOTA_MAP keyed by sku_id; every v6 order was falling into the
    # TM-FALLBACK bucket and the user got nothing.
    sku_id = order.get("sku_id") or str(order.get("usd_amount", ""))
    email = order["email"]
    try:
        return redeem.create_redemption(sku_id, email)
    except redeem.SessionExpiredError as e:
        log.error(
            "New API session expired while coding order %s sku_id=%s: %s",
            order["id"], sku_id, e,
        )
        return f"TM-FALLBACK-{uuid.uuid4().hex[:10].upper()}"
    except ValueError as e:
        log.error("Bad SKU on order %s: %s", order["id"], e)
        return f"TM-FALLBACK-{uuid.uuid4().hex[:10].upper()}"


# ── v6.1 New API admin auth helper (see newapi_auth.py) ──────────────────
# All New API call sites go through newapi_auth.get_session() / .headers() to
# share the auto-login logic with redeem.py. Aliases here keep call sites
# short and grep-friendly.
NewAPIAuthError = newapi_auth.NewAPIAuthError
_newapi_get_session = newapi_auth.get_session
_newapi_headers = newapi_auth.headers


# ── v6 c-path: direct quota grant via New API admin API ──────────────────


def _fetch_quota_per_unit() -> int:
    """Fetch New API QuotaPerUnit from /api/option/?key=QuotaPerUnit at startup.

    New API default is 500_000 (1 USD = 500K quota, per
    common/constants.go:62). The admin may override via the New API admin UI
    (Settings → QuotaPerUnit), so we read live value rather than hard-coding.
    Falls back to 500_000 on any error (no cookie, 401, network, parse).
    v6.1: uses _newapi_get_session which auto-logs-in via root creds when no
    static cookie is set, so Zeabur env can ship with just username/password.
    """
    try:
        r = requests.get(
            f"{NEW_API_BASE_URL}/api/option/",
            params={"key": "QuotaPerUnit"},
            headers=_newapi_headers(),
            timeout=10,
        )
        # If our cached session is stale, force a fresh login and retry once.
        if r.status_code == 401:
            log.warning("QuotaPerUnit 401, refreshing New API session and retrying")
            _newapi_get_session(force_refresh=True)
            r = requests.get(
                f"{NEW_API_BASE_URL}/api/option/",
                params={"key": "QuotaPerUnit"},
                headers=_newapi_headers(),
                timeout=10,
            )
        r.raise_for_status()
        body = r.json()
        # New API v1.0.0-rc.10 shape: {"success": true, "data": {"key": "QuotaPerUnit", "value": "500000"}}
        # Some builds: {"data": [...]} array form
        data = body.get("data")
        if isinstance(data, list) and data:
            data = data[0]
        if isinstance(data, dict):
            val = data.get("value")
        else:
            val = body.get("value")
        if val is None or str(val).strip() == "":
            log.warning("QuotaPerUnit fetch returned empty value: %s", body)
            return 500_000
        return int(float(val))
    except Exception as e:
        log.warning("QuotaPerUnit fetch failed (%s) — using default 500_000", e)
        return 500_000


def _grant_quota_via_admin_api(order: dict) -> str | None:
    """v6 c-path: grant quota directly to the user's New API account.

    Replaces b-path (mint redemption code) for the PayPal webhook. Looks up
    the New API user_id by email via /api/user/?keyword=, then PUTs the
    USD→quota delta to /api/user/self/?id={user_id}.

    Returns a marker string for the orders.redemption_code column (audit), or
    None on any failure. Caller should mark the order failed and return 500
    to PayPal so the webhook retries.

    v6.1: session comes from _newapi_get_session; on 401 the helper
    auto-logs-in and we retry once.
    """
    email = order["email"]
    usd = int(order["usd_amount"])
    quota_to_add = usd * _quota_per_unit
    try:
        # Step 1: look up user_id by email
        ur = requests.get(
            f"{NEW_API_BASE_URL}/api/user/",
            params={"keyword": email},
            headers=_newapi_headers(),
            timeout=15,
        )
        if ur.status_code == 401:
            log.warning("c-path user-lookup 401, refreshing session and retrying")
            _newapi_get_session(force_refresh=True)
            ur = requests.get(
                f"{NEW_API_BASE_URL}/api/user/",
                params={"keyword": email},
                headers=_newapi_headers(),
                timeout=15,
            )
        ur.raise_for_status()
        ubody = ur.json()
        users = ubody.get("data")
        if isinstance(users, dict):
            users = [users]
        if not isinstance(users, list):
            users = []
        user_id = None
        for u in users:
            if (u.get("email") or "").lower() == email.lower():
                user_id = u.get("id")
                break
        if not user_id:
            log.error("c-path: no New API user for email=%s (order %s)", email, order["id"])
            return None
        # Step 2: PUT quota delta
        pr = requests.put(
            f"{NEW_API_BASE_URL}/api/user/self/?id={user_id}",
            headers=_newapi_headers(),
            json={"quota": quota_to_add},
            timeout=15,
        )
        if pr.status_code == 401:
            log.warning("c-path quota PUT 401, refreshing session and retrying")
            _newapi_get_session(force_refresh=True)
            pr = requests.put(
                f"{NEW_API_BASE_URL}/api/user/self/?id={user_id}",
                headers=_newapi_headers(),
                json={"quota": quota_to_add},
                timeout=15,
            )
        pr.raise_for_status()
        log.info(
            "PayPal webhook processed, user_id=%s, quota_added=%d, order_id=%s",
            user_id, quota_to_add, order["id"],
        )
        return f"cpath:user={user_id},+{quota_to_add}"
    except NewAPIAuthError as e:
        log.error("c-path auth failed for order %s: %s", order["id"], e)
        return None
    except Exception as e:
        log.exception("c-path grant failed for order %s: %s", order["id"], e)
        return None


# ── M3 test endpoint ─────────────────────────────────────────────────────


class TestRedeemIn(BaseModel):
    sku: str = Field(..., description="USD amount as string: 10/30/100/300")
    email: EmailStr


class TestRedeemOut(BaseModel):
    status: str
    code: str
    sku: str
    email: str


@app.post("/test-redeem", response_model=TestRedeemOut)
def test_redeem(payload: TestRedeemIn):
    """M3 sandbox endpoint — mints 1 redemption code and returns it.

    Does NOT write to the orders table. Used by the curl self-test in M3.
    """
    try:
        code = redeem.create_redemption(payload.sku, payload.email)
    except redeem.SessionExpiredError as e:
        log.error("test-redeem session expired: %s", e)
        raise HTTPException(401, f"New API session expired: {e}")
    except ValueError as e:
        raise HTTPException(400, str(e))
    except requests.HTTPError as e:
        log.exception("test-redeem HTTP error")
        raise HTTPException(502, f"New API HTTP error: {e}")
    except Exception as e:
        log.exception("test-redeem failed")
        raise HTTPException(500, f"redemption call failed: {type(e).__name__}: {e}")
    return TestRedeemOut(status="ok", code=code, sku=payload.sku, email=payload.email)


# v6 c-path UX: client JS polls this endpoint on pay.api-tokenmaster.com
# (same subdomain, no CORS) to surface the post-payment balance to the user
# without leaking the admin session. We use the server-side admin session
# (NEW_API_SESSION_COOKIE env) to call New API on the user's behalf, then
# return only the quota + a USD-denominated balance derived from
# QuotaPerUnit. Client passes ?user_id=<id> (already known to the client
# from its own New API session, not the admin session).
@app.get("/api/user/balance/polling")
def balance_polling(user_id: int) -> dict:
    """Proxy GET /api/user/self/?id={user_id} to New API using admin session.

    Returns a small JSON payload with quota + USD balance. The user_id is
    passed by the client (it knows its own id from its user login); the
    admin session is server-side only and never returned to the client.
    """
    if user_id <= 0:
        raise HTTPException(400, "user_id required")
    try:
        r = requests.get(
            f"{NEW_API_BASE_URL}/api/user/self/?id={user_id}",
            headers=_newapi_headers(),
            timeout=10,
        )
        if r.status_code == 401:
            log.warning("balance-polling 401, refreshing session and retrying")
            _newapi_get_session(force_refresh=True)
            r = requests.get(
                f"{NEW_API_BASE_URL}/api/user/self/?id={user_id}",
                headers=_newapi_headers(),
                timeout=10,
            )
        r.raise_for_status()
        body = r.json()
        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, dict):
            raise HTTPException(502, f"New API returned unexpected body: {body!r}")
        quota = data.get("quota", 0)
        # USD = quota / QuotaPerUnit (default 500_000; fetched at startup)
        qpu = _quota_per_unit if _quota_per_unit else 500_000
        balance_usd = (quota / qpu) if qpu else 0
        return {"user_id": user_id, "quota": quota, "balance_usd": round(balance_usd, 4)}
    except requests.HTTPError as e:
        status = e.response.status_code if e.response is not None else 500
        log.exception("balance-polling New API HTTP error")
        raise HTTPException(status, f"New API HTTP error: {e}")
    except Exception as e:
        log.exception("balance-polling failed")
        raise HTTPException(500, f"balance lookup failed: {type(e).__name__}: {e}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.environ.get("PORT",8000)))
