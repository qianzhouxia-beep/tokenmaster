"""TokenMaster v5 M3 — New API redemption code minter.

Called from the webhook handlers in `app.py` once a PayPal or NOWPayments
payment clears. Mints a single New API redemption code for the order's SKU
quota, then the caller stashes the code in `orders.redemption_code`.

Wire contract (per v5 spec lines 47-51):
    POST {NEW_API_BASE_URL}/api/redemption/
    Cookie: session={NEW_API_SESSION_COOKIE}
    Content-Type: application/json

    {"name": "Topup $30", "count": 1, "quota": 300000, "expired_time": -1}

Response shape (observed on New API v1.0.0-rc.10):
    {"success": true, "data": "<redemption-code>"}
    (or `code` field on some versions; we accept either)

Failure modes:
    401 Unauthorized       -> raises SessionExpiredError (caller logs + marks
                              order failed:session_expired)
    Unknown SKU            -> raises ValueError (programming bug, not network)
    Other HTTP error       -> raises requests.HTTPError
    Missing env cookie     -> raises SessionExpiredError (cannot even try)

Email is currently a no-op beyond logging — the v5 spec defers real SMTP to
v6 (SendGrid) and v5 just prints `[MOCK EMAIL]` to the log.
"""
from __future__ import annotations

import logging
import os
import time

import requests

log = logging.getLogger("tokenmaster.redeem")

NEW_API_BASE_URL = os.environ.get("NEW_API_BASE_URL", "https://api-tokenmaster.com")
NEW_API_SESSION_COOKIE = os.environ.get("NEW_API_SESSION_COOKIE", "")
# v6 d-path: admin login fallback when session cookie expires (12:35+ 401 bug).
# 用 root user + password auto-login 拿新 session, 避免 30-day cookie 失效.
NEW_API_ROOT_USERNAME = os.environ.get("NEW_API_ROOT_USERNAME", "root")
NEW_API_ROOT_PASSWORD = os.environ.get("NEW_API_ROOT_PASSWORD", "")

# USD price -> New API quota.
# v6 d-path: 老板 L1 2026-06-11 11:30 拍板 新套餐 15/35/80 USD = 20M/50M/150M tokens
# 公式: quota = USD * 1M / 15 (1 token = 1 quota)
# Keys are STRINGS so callers can pass `order["usd_amount"]` directly
# (`str(int)`) without a separate mapping table in app.py.
QUOTA_MAP: dict[str, int] = {
    # 老 4 档 (保留兼容, 1 quota = 0.001 USD)
    "10": 100_000,
    "30": 300_000,
    "100": 1_000_000,
    "300": 3_000_000,
    # v6 新套餐 (1 quota = 1 token)
    "15": 20_000_000,
    "35": 50_000_000,
    "80": 150_000_000,
}


class SessionExpiredError(Exception):
    """Raised when the New API admin session cookie is rejected (HTTP 401)
    or is missing from the environment entirely.

    The webhook caller should mark the order `failed:session_expired` and
    alert the operator — manual session refresh is required before the
    backlog of completed orders can be retroactively coded.
    """


def create_redemption(sku: str, email: str) -> str:
    """Mint a single New API redemption code for the given USD SKU.

    Args:
        sku: USD amount as a string, e.g. "10" / "30" / "100" / "300".
        email: Customer email (logged for audit + the v6 SendGrid step).

    Returns:
        The redemption code string from New API.

    Raises:
        SessionExpiredError: New API returned 401, or no cookie in env.
        ValueError: sku not in QUOTA_MAP.
        requests.HTTPError: New API returned other non-2xx status.
        RuntimeError: New API returned 2xx but the body had no code.
    """
    if sku not in QUOTA_MAP:
        raise ValueError(
            f"unknown sku: {sku!r}; expected one of {sorted(QUOTA_MAP)}"
        )
    if not NEW_API_SESSION_COOKIE:
        log.warning("NEW_API_SESSION_COOKIE empty in env, will fallback to admin login (sku=$%s)", sku)
    quota = QUOTA_MAP[sku]
    payload = {
        "name": f"Topup ${sku}",
        "count": 1,
        "quota": quota,
        "expired_time": 0,  # 0 = 永不过期 (v6 d-path: -1 已被 New API 拒)
    }
    url = f"{NEW_API_BASE_URL}/api/redemption/"
    log.info(
        "create_redemption: POST %s sku=$%s quota=%d email=%s",
        url, sku, quota, email,
    )

    # v6 d-path: 先试 session cookie (老路径), 401 后自动 admin login fallback
    # admin 路径: login root → session cookie + New-Api-User: 1 → mint redemption
    # New API 不接受 Bearer token, 必须是 session + header
    r = requests.post(
        url,
        headers={
            "Cookie": f"session={NEW_API_SESSION_COOKIE}",
            "New-Api-User": "1",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        json=payload,
        timeout=15,
    )

    if r.status_code == 401 and NEW_API_ROOT_PASSWORD:
        log.warning("session cookie 401, fallback to admin login (sku=$%s)", sku)
        s = requests.Session()
        r_login = s.post(
            f"{NEW_API_BASE_URL}/api/user/login",
            json={"username": NEW_API_ROOT_USERNAME, "password": NEW_API_ROOT_PASSWORD},
            timeout=10,
        )
        if not (r_login.status_code == 200 and r_login.json().get("success")):
            raise SessionExpiredError(
                f"admin login failed for sku=${sku}: {r_login.text[:200]}"
            )
        r = s.post(
            url,
            headers={
                "New-Api-User": "1",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json=payload,
            timeout=15,
        )

    if r.status_code == 401:
        raise SessionExpiredError(
            f"New API rejected session AND admin login (HTTP 401) for sku=${sku}; "
            f"check NEW_API_ROOT_PASSWORD in .env"
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
