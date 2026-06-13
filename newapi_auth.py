"""TokenMaster v6.36 — New API admin auth helper.

Shared between `app.py` and `redeem.py` to provide a single, cached source
of New API admin session cookies. Resolution order:
  1. Cached cookie (in-process).
  2. `NEW_API_SESSION_COOKIE` env (fast-path, validated against
     `GET /api/user/?keyword=root` — if 401, drop it and try _login).
  3. `_login()` with `NEW_API_ROOT_USERNAME` / `NEW_API_ROOT_PASSWORD`
     (auto-fallback when no static cookie is configured or it has
     expired).

v6.36 fix: the previous version always trusted `NEW_API_SESSION_COOKIE`
when set, which silently failed when the cookie expired (New API sessions
are 30-day rolling) or was never updated. Now we actively probe the
static cookie before returning it: a 401 from the probe forces a
re-login. This survives the 30-day rotation without operator
intervention in the common case, and gives the operator a clear log
line when the root password itself has been rotated (login returns
"Invalid parameters" and we surface that error).

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
_session_cache: dict = {"cookie": "", "fetched_at": 0.0, "validated": False}


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
        # v6.36: log the full body so the operator can see the i18n error
        # (commonly "Invalid parameters" when the root password is stale
        # after an admin rotation in the New API admin UI).
        body_snippet = (r.text or "")[:200]
        raise NewAPIAuthError(
            f"New API login HTTP {r.status_code}: {body_snippet}"
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


def _probe_cookie(cookie_val: str) -> bool:
    """Verify a New API session cookie is still valid.

    Returns True if the cookie authenticates against
    `GET /api/user/?keyword=root` (any 2xx, since the response shape is
    build-dependent). Returns False on 401 (cookie rejected — expired,
    rotated, or never valid). Any other failure (network, 5xx) is treated
    as "probe inconclusive" and returns True so the caller can keep
    using the cookie; the next real request will hit a 401 and trigger
    `force_refresh` recovery.
    """
    if not cookie_val:
        return False
    try:
        r = requests.get(
            f"{NEW_API_BASE_URL}/api/user/",
            params={"keyword": NEW_API_ROOT_USERNAME},
            headers={
                "Cookie": f"session={cookie_val}",
                "New-Api-User": "1",
                "Accept": "application/json",
            },
            timeout=8,
        )
    except requests.RequestException as e:
        log.warning("New API cookie probe network error: %s", e)
        return True  # be optimistic on transient errors
    if r.status_code == 401:
        return False
    return True


def get_session(*, force_refresh: bool = False) -> str:
    """Return a valid New API admin session cookie, auto-logging in if needed.

    Resolution order:
      1. `force_refresh=True` (used after a 401) clears the cache and
         forces a fresh probe/login path.
      2. Cached cookie (from a prior call in this process lifetime) wins.
      3. `NEW_API_SESSION_COOKIE` env is used as a fast-path static
         cookie. We probe it on first use (and again whenever a 401
         forces `force_refresh=True`); a 401 from the probe drops the
         static cookie and falls through to `_login()`.
      4. Otherwise call `_login()` and cache the result.

    Raises NewAPIAuthError when no static cookie is configured and
    auto-login is disabled (no password) or fails.
    """
    if force_refresh:
        _session_cache["cookie"] = ""
        _session_cache["fetched_at"] = 0.0
        _session_cache["validated"] = False
    cached = _session_cache.get("cookie", "")
    if cached and _session_cache.get("validated"):
        return cached
    if NEW_API_SESSION_COOKIE:
        if _probe_cookie(NEW_API_SESSION_COOKIE):
            _session_cache["cookie"] = NEW_API_SESSION_COOKIE
            _session_cache["fetched_at"] = time.time()
            _session_cache["validated"] = True
            return NEW_API_SESSION_COOKIE
        log.warning(
            "NEW_API_SESSION_COOKIE rejected (401) — falling back to root "
            "password login"
        )
    fresh = _login()
    _session_cache["cookie"] = fresh
    _session_cache["fetched_at"] = time.time()
    _session_cache["validated"] = True
    return fresh


def headers() -> dict:
    """Common New API request headers (Cookie session + New-Api-User + JSON)."""
    return {
        "Cookie": f"session={get_session()}",
        "New-Api-User": "1",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
