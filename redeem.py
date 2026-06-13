"""TokenMaster v5 M3 — New API redemption code minter.

Called from the webhook handlers in `app.py` once a PayPal or NOWPayments
payment clears. Mints a single New API redemption code for the order's SKU
quota, then the caller stashes the code in `orders.redemption_code`.

Wire contract (per v5 spec lines 47-51):
    POST {NEW_API_BASE_URL}/api/redemption/
    Cookie: session=<admin-session>
    Content-Type: application/json

    {"name": "Topup $30", "count": 1, "quota": 300000, "expired_time": -1}

Response shape (observed on New API v1.0.0-rc.10):
    {"success": true, "data": "<redemption-code>"}
    (or `code` field on some versions; we accept either)

Failure modes (v6.1):
    SessionExpiredError     - admin session rejected (401) even after auto-
                             login attempt, or no credentials at all.
                             Backward-compatible alias of NewAPIAuthError so
                             existing `except redeem.SessionExpiredError`
                             handlers in app.py keep working.
    Unknown SKU             - raises ValueError (programming bug, not network)
    Other HTTP error        - raises requests.HTTPError
    Missing env cookie + no root password -> raises SessionExpiredError

Email is currently a no-op beyond logging — the v5 spec defers real SMTP to
v6 (SendGrid) and v5 just prints `[MOCK EMAIL]` to the log.
"""
from __future__ import annotations

import logging
import os
import smtplib
import ssl
from email.message import EmailMessage

import requests

import newapi_auth

log = logging.getLogger("tokenmaster.redeem")

NEW_API_BASE_URL = newapi_auth.NEW_API_BASE_URL

# SKU_ID -> New API quota. 1 quota = 0.001 USD, per v5 spec line 68.
# Keys are SKU_IDs (not USD amount) so the order row's `sku_id` field
# is the single source of truth and we never mismatch price to quota.
# Mirrors db.SKUS; keep these two in sync.
QUOTA_MAP: dict[str, int] = {
    # legacy 4 tiers
    "starter":   100_000,
    "indie":     300_000,
    "team":      1_000_000,
    "pro":       3_000_000,
    # v6 3 tiers (15/35/80 USD)
    "starter_v6": 20_000_000,
    "indie_v6":   50_000_000,
    "team_v6":    150_000_000,
}


# Backward-compatible alias. v6.1 unified the auth error class in
# newapi_auth.NewAPIAuthError; we re-export it under the old name so
# `except redeem.SessionExpiredError` blocks in app.py don't need to change.
SessionExpiredError = newapi_auth.NewAPIAuthError


def create_redemption(sku: str, email: str) -> str:
    """Mint a single New API redemption code for the given USD SKU.

    Args:
        sku: USD amount as a string, e.g. "10" / "30" / "100" / "300".
        email: Customer email (logged for audit + the v6 SendGrid step).

    Returns:
        The redemption code string from New API.

    Raises:
        SessionExpiredError: New API rejected the admin session (HTTP 401
                             even after refresh) or no credentials in env.
        ValueError: sku not in QUOTA_MAP.
        requests.HTTPError: New API returned other non-2xx status.
        RuntimeError: New API returned 2xx but the body had no code.
    """
    if sku not in QUOTA_MAP:
        raise ValueError(
            f"unknown sku: {sku!r}; expected one of {sorted(QUOTA_MAP)}"
        )

    quota = QUOTA_MAP[sku]
    # v6.21: New API v1.0.0-rc.10 validates `expired_time` strictly: if non-zero
    # and < now → reject with "服务器时间与当前时间不符". The old code passed
    # -1 thinking "never expires", but -1 < any positive now → rejected.
    # Use a real far-future timestamp (10 years out) instead. epoch seconds
    # for 2036-01-01 = 2082758400.
    payload = {
        "name": f"Topup ${sku}",
        "count": 1,
        "quota": quota,
        "expired_time": 2082758400,
    }
    url = f"{NEW_API_BASE_URL}/api/redemption/"
    log.info(
        "create_redemption: POST %s sku=$%s quota=%d email=%s",
        url, sku, quota, email,
    )

    # v6.1: _newapi_headers() may itself raise SessionExpiredError if no
    # static cookie AND no NEW_API_ROOT_PASSWORD are configured. Let it
    # propagate — the caller's existing `except redeem.SessionExpiredError`
    # block handles it.
    r = requests.post(
        url,
        headers=newapi_auth.headers(),
        json=payload,
        timeout=15,
    )

    if r.status_code == 401:
        # The session we sent was rejected. Force a fresh login (clears the
        # in-memory cache so the next call hits /api/user/login) and retry
        # once. If login also fails, newapi_auth will raise
        # SessionExpiredError on the second headers() call.
        log.warning(
            "create_redemption 401 for sku=$%s, refreshing session and retrying",
            sku,
        )
        newapi_auth.get_session(force_refresh=True)
        r = requests.post(
            url,
            headers=newapi_auth.headers(),
            json=payload,
            timeout=15,
        )
        if r.status_code == 401:
            raise SessionExpiredError(
                f"New API rejected session even after refresh (HTTP 401) for "
                f"sku=${sku}; check NEW_API_ROOT_USERNAME / NEW_API_ROOT_PASSWORD"
            )

    r.raise_for_status()
    body = r.json()

    # New API v1.0.0-rc.10: {"success": true, "data": "<code>"}
    # Some builds: {"code": "<code>"} or {"data": ["<code>"]}
    code = body.get("data") or body.get("code") or ""
    if isinstance(code, list) and code:
        code = code[0]
    if not (isinstance(code, str) and code):
        raise RuntimeError(
            f"New API 2xx but no usable code in body: {body!r}"
        )

    # v6.19: real email send. Falls back to log-only mock if SMTP env
    # not configured (so dev / CI can still run without email creds).
    _send_code_email(email, sku, code)
    return code


def _send_code_email(email: str, sku: str, code: str) -> None:
    """Send the redemption code to the customer.

    SMTP env (all optional; missing = log-only fallback):
        SMTP_HOST      e.g. smtp.sendgrid.net
        SMTP_PORT      587 (default) or 465
        SMTP_USERNAME  e.g. apikey
        SMTP_PASSWORD  e.g. SG.xxxxx
        SMTP_FROM      e.g. "TokenMaster <noreply@api-tokenmaster.com>"
        SMTP_USE_TLS   "1" (default STARTTLS on port 587)
    """
    host = os.environ.get("SMTP_HOST", "").strip()
    user = os.environ.get("SMTP_USERNAME", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "").strip()
    sender = os.environ.get("SMTP_FROM", "noreply@api-tokenmaster.com").strip()
    wallet_host = NEW_API_BASE_URL.replace("https://", "").replace("http://", "")

    if not (host and user and password):
        log.info(
            "[EMAIL MOCK] SMTP not configured; would have sent to=%s code=%s*** sku=$%s "
            "(set SMTP_HOST/SMTP_USERNAME/SMTP_PASSWORD to enable real send)",
            email, code[:8], sku,
        )
        return

    port = int(os.environ.get("SMTP_PORT", "587"))
    use_tls = os.environ.get("SMTP_USE_TLS", "1") != "0"

    msg = EmailMessage()
    msg["Subject"] = f"Your TokenMaster code (${sku} topup)"
    msg["From"] = sender
    msg["To"] = email
    msg.set_content(
        f"Thanks for your TokenMaster purchase!\n\n"
        f"Plan: ${sku} topup\n"
        f"Redemption code: {code}\n\n"
        f"Redeem at https://{wallet_host}/wallet (Settings → Redeem).\n"
        f"The code grants the full quota to your account instantly.\n\n"
        f"Questions? Reply to this email.\n"
    )

    try:
        if port == 465:
            # SSL (typical for smtp.larksuite.com, smtp.gmail.com alt, etc.)
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, timeout=10, context=ctx) as s:
                s.login(user, password)
                s.send_message(msg)
        else:
            # STARTTLS (default)
            with smtplib.SMTP(host, port, timeout=10) as s:
                s.ehlo()
                if use_tls:
                    s.starttls(context=ssl.create_default_context())
                    s.ehlo()
                s.login(user, password)
                s.send_message(msg)
        log.info("email sent: to=%s code=%s*** sku=$%s via %s:%d", email, code[:8], sku, host, port)
    except smtplib.SMTPAuthenticationError as e:
        # Most common Lark/Gmail/QQ error: wrong password. App-password
        # required for IMAP/SMTP, NOT the user's login password.
        log.error(
            "email SMTP AUTH FAILED for to=%s code=%s host=%s:%d. "
            "If using Lark/Gmail/QQ, SMTP_PASSWORD must be the application-specific "
            "password (not the login password). err=%s",
            email, code[:8], host, port, e,
        )
    except Exception as e:
        # Don't fail the whole redemption just because email failed. The
        # code is already minted and saved in DB; the operator can re-send
        # manually from the orders table.
        log.error("email send FAILED for to=%s code=%s: %s", email, code[:8], e)


if __name__ == "__main__":
    # Manual smoke test: `python redeem.py 30 test@example.com`
    import sys
    sku = sys.argv[1] if len(sys.argv) > 1 else "30"
    email = sys.argv[2] if len(sys.argv) > 2 else "test@example.com"
    try:
        code = create_redemption(sku, email)
        print(f"OK code={code}")
    except SessionExpiredError as e:
        print(f"SESSION_EXPIRED: {e}")
        sys.exit(2)
    except Exception as e:
        print(f"ERROR {type(e).__name__}: {e}")
        sys.exit(1)
