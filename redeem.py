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

import requests

import newapi_auth

log = logging.getLogger("tokenmaster.redeem")

NEW_API_BASE_URL = newapi_auth.NEW_API_BASE_URL

# USD price -> New API quota (1 quota = 0.001 USD, per v5 spec line 68).
# Keys are STRINGS so callers can pass `order["usd_amount"]` directly
# (`str(int)`) without a separate mapping table in app.py.
QUOTA_MAP: dict[str, int] = {
    "10": 100_000,
    "30": 300_000,
    "100": 1_000_000,
    "300": 3_000_000,
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
    payload = {
        "name": f"Topup ${sku}",
        "count": 1,
        "quota": quota,
        "expired_time": -1,
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

    # Mock email send — v6 will replace this with SendGrid SMTP.
    log.info(
        "[MOCK EMAIL] to=%s subject='Your TokenMaster code' body='Redeem at "
        "https://%s/wallet with code %s'",
        email, NEW_API_BASE_URL.replace("https://", "").replace("http://", ""), code,
    )
    log.info("email sent (mock): code=%s*** to=%s sku=$%s", code[:8], email, sku)
    return code


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
