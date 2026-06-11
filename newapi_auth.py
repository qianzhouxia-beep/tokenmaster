"""TokenMaster v6.1 — New API admin auth helper.

Shared between `app.py` and `redeem.py` to provide a single, cached source
of New API admin session cookies. Falls back from the static
`NEW_API_SESSION_COOKIE` env to on-the-fly root-login when the static cookie
is missing or rejected, so the webhook can survive the 30-day New API
session-cookie rotation without operator intervention.

Public API:
    NewAPIAuthError       - raised when no usable session can be obtained
    get_session(force_refresh=False) -> str   - valid admin session cookie
    headers() -> dict                          - common request headers
"""
from __future__ import annotations

import logging
import os
import time

import requests

log = logging.getLogger("tokenmaster.newapi_auth")

NEW_API_BASE_URL = os.environ.get("NEW_API_BASE_URL", "https://api-tokenmaster.com")
NEW_API_SESSION_COOKIE = os.environ.get("NEW_API_SESSION_COOKIE", "")
NEW_API_ROOT_USERNAME = os.environ.get("NEW_API_ROOT_USERNAME", "root")
NEW_API_ROOT_PASSWORD = os.environ.get("NEW_API_ROOT_PASSWORD", "")

# Module-level session cache. Keyed by cookie value + fetched_at epoch.
_session_cache: dict = {"cookie": "", "fetched_at": 0.0}


class NewAPIAuthError(Exception):
    """Raised when the webhook cannot get a valid New API admin session.

    Covers: (a) no static cookie AND no NEW_API_ROOT_PASSWORD, (b) admin
    login returned non-2xx, (c) login response had no session cookie in
    Set-Cookie. Callers should mark the order failed and (for 401 on a
    previously-working cookie) alert the operator — the root password may
    need to be rotated.
    """


def _login() -> str:
    """Log in to New API as root and return a fresh session cookie value."""
    if not NEW_API_ROOT_PASSWORD:
        raise NewAPIAuthError(
            "NEW_API_ROOT_PASSWORD empty — cannot auto-login; "
            "set it in env or provide NEW_API_SESSION_COOKIE"
        )
    url = f"{NEW_API_BASE_URL}/api/user/login"
    log.info("New API admin login: POST %s user=%s", url, NEW_API_ROOT_USERNAME)
    try:
        r = requests.post(
            url,
            json={"username": NEW_API_ROOT_USERNAME, "password": NEW_API_ROOT_PASSWORD},
            timeout=10,
        )
    except requests.RequestException as e:
        raise NewAPIAuthError(f"New API login network error: {e}") from e
    if r.status_code != 200:
        raise NewAPIAuthError(
            f"New API login HTTP {r.status_code}: {r.text[:200]}"
        )
    # Set-Cookie can appear once or multiple times. requests only exposes the
    # first via r.headers.get, so iterate all header items for safety.
    cookie_val = ""
    for hdr_name, hdr_val in r.headers.items():
        if hdr_name.lower() != "set-cookie":
            continue
        for part in hdr_val.split(";"):
            part = part.strip()
            if part.startswith("session="):
                cookie_val = part[len("session="):]
                break
        if cookie_val:
            break
    if not cookie_val:
        raise NewAPIAuthError(
            f"New API login 200 but no session cookie in response headers: "
            f"keys={list(r.headers.keys())}"
        )
    log.info("New API admin login OK (cookie len=%d)", len(cookie_val))
    return cookie_val


def get_session(*, force_refresh: bool = False) -> str:
    """Return a valid New API admin session cookie, auto-logging in if needed.

    Resolution order:
      1. `force_refresh=True` (used after a 401) clears the cache and continues.
      2. Cached cookie (from a prior call in this process lifetime) wins.
      3. `NEW_API_SESSION_COOKIE` env is used as a fast-path static cookie
         (no login needed). Still cached so refresh-on-401 can override.
      4. Otherwise call `_login()` and cache the result.

    Raises NewAPIAuthError when no static cookie is configured and auto-login
    is disabled (no password) or fails.
    """
    if force_refresh:
        _session_cache["cookie"] = ""
        _session_cache["fetched_at"] = 0.0
    cached = _session_cache.get("cookie", "")
    if cached:
        return cached
    if NEW_API_SESSION_COOKIE:
        _session_cache["cookie"] = NEW_API_SESSION_COOKIE
        _session_cache["fetched_at"] = time.time()
        return NEW_API_SESSION_COOKIE
    fresh = _login()
    _session_cache["cookie"] = fresh
    _session_cache["fetched_at"] = time.time()
    return fresh


def headers() -> dict:
    """Common New API request headers (Cookie session + New-Api-User + JSON)."""
    return {
        "Cookie": f"session={get_session()}",
        "New-Api-User": "1",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
