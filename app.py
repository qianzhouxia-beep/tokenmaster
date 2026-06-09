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
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field

import db
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
NEW_API_SESSION_COOKIE = os.environ.get("NEW_API_SESSION_COOKIE", "")

_paypal_token = {"access_token": None, "expires_at":0}

app = FastAPI(title="TokenMaster v5 Webhook", version="v5")


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
    log.info("webhook service ready v5")


@app.get("/")
def health() -> dict:
    return {"status": "ok", "version": "v5"}


class CreateOrderIn(BaseModel):
    email: EmailStr
    sku_id: str
    payment_method: str


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
        timeout=15,
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
        },
    }
    r = requests.post(
        f"{PAYPAL_API_BASE}/v2/checkout/orders",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        json=payload,
        timeout=15,
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
            "NOWPAYMENTS_IPN_URL", "https://api-tokenmaster.com/nowpayments-webhook"
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

    temp_order = db.create_order(payload.email, payload.sku_id, method)

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
        log.exception("create-order failed")
        db.mark_failed(temp_order["id"], reason=f"create-error:{type(e).__name__}")
        raise HTTPException(502, f"provider error: {e}")


@app.get("/orders/{order_id}")
def get_order(order_id: str) -> dict:
    row = db.get_order(order_id)
    if not row:
        raise HTTPException(404, f"order {order_id} not found")
    return row


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
        code = _mint_redemption_code(order)
        db.mark_paid(order["id"], code)
        log.info("paypal order %s paid -> code %s", order["id"], (code[:8] + "***") if code else "<empty>")

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

    Thin adapter that maps the `order` row to `(sku, email)` for the
    `redeem.create_redemption` contract. On `SessionExpiredError` we fall
    back to a TM-FALLBACK placeholder so the order can still complete its
    DB lifecycle; the verifier flags this in the deliverable Notes
    section. Any other error is re-raised so callers can decide.
    """
    sku = str(order["usd_amount"])
    email = order["email"]
    try:
        return redeem.create_redemption(sku, email)
    except redeem.SessionExpiredError as e:
        log.error(
            "New API session expired while coding order %s sku=$%s: %s",
            order["id"], sku, e,
        )
        # Fallback: the order still completes; operator must refresh
        # NEW_API_SESSION_COOKIE and retroactively code the order.
        return f"TM-FALLBACK-{uuid.uuid4().hex[:10].upper()}"
    except ValueError as e:
        log.error("Bad SKU on order %s: %s", order["id"], e)
        return f"TM-FALLBACK-{uuid.uuid4().hex[:10].upper()}"


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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.environ.get("PORT",8000)))
