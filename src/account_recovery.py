"""Automated email login and signup recovery for Arena (arena.ai)."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import email as email_lib
import html
import imaplib
import os
import re
import secrets
import time
from typing import Any, Callable, Optional

from playwright.async_api import async_playwright

from .auth import (
    _combine_split_arena_auth_cookies,
    _decode_arena_auth_session_token,
    _persist_refreshed_auth_token,
    _upsert_browser_session_into_config,
    is_arena_auth_token_expired,
)
from .recaptcha import find_chrome_executable

_ACCOUNT_RECOVERY_LOCK: asyncio.Lock = asyncio.Lock()
_EMAIL_BLOCKED_MARKERS = (
    "email domain is not permitted",
    "email address cannot be used to sign up",
)


def is_anonymous_arena_auth_token(token: str) -> bool:
    """Return True if `token` decodes to an anonymous Supabase session."""
    session = _decode_arena_auth_session_token(token)
    user = session.get("user") if isinstance(session, dict) else None
    return isinstance(user, dict) and user.get("is_anonymous") is True


def is_signed_in_arena_auth_token(token: str) -> bool:
    """Return True if `token` is a non-expired, non-anonymous base64 session."""
    session = _decode_arena_auth_session_token(token)
    if not isinstance(session, dict):
        return False
    user = session.get("user")
    return (
        str(session.get("access_token") or "").strip().count(".") >= 2
        and not is_arena_auth_token_expired(token)
        and not (isinstance(user, dict) and user.get("is_anonymous") is True)
    )


def extract_arena_verification_url(*parts: str) -> Optional[str]:
    """Extract Arena's email verification callback URL from text/HTML email bodies."""
    content = html.unescape("\n".join(str(p or "") for p in parts))
    urls = [u.rstrip(".,);]}") for u in re.findall(r"https?://[^\s\"'<>]+", content)]
    for marker in ("arena.ai/nextjs-api/callback/email", "arena.ai/auth/set-password"):
        for url in urls:
            if marker in url:
                return url
    return None


def _extract_arena_auth_from_cookies(cookies: list[dict[str, Any]]) -> str:
    """Return combined split `arena-auth-prod-v1.<n>` cookies or non-empty base cookie."""
    return _combine_split_arena_auth_cookies(cookies) or next(
        (
            str(c.get("value") or "").strip()
            for c in cookies or []
            if str(c.get("name") or "") == "arena-auth-prod-v1" and str(c.get("value") or "").strip()
        ),
        "",
    )


@asynccontextmanager
async def _arena_email_page(address: str, headless: bool):
    """Launch Chrome, open Arena's email dialog, submit `address`, and yield `(page, context)`."""
    launch_kwargs: dict[str, Any] = {
        "headless": bool(headless),
        "args": ["--disable-blink-features=AutomationControlled", "--window-position=-2400,-2400"],
    }
    chrome_exe = find_chrome_executable()
    if chrome_exe:
        launch_kwargs["executable_path"] = chrome_exe

    async with async_playwright() as p:
        browser = await p.chromium.launch(**launch_kwargs)
        try:
            context = await browser.new_context()
            page = await context.new_page()
            await page.goto("https://arena.ai/", wait_until="domcontentloaded", timeout=90000)
            login_btn = page.get_by_role("button", name=re.compile(r"^log in$", re.I)).first
            await login_btn.wait_for(state="visible", timeout=20000)
            await login_btn.click(timeout=15000)
            email_input = page.get_by_placeholder("Your email")
            await email_input.wait_for(state="visible", timeout=20000)
            await email_input.fill(address)
            await page.get_by_role("button", name="Continue with email").click()
            yield page, context
        finally:
            await browser.close()


async def _capture_session_from_page(page, context, cfg: dict[str, Any]) -> Optional[str]:
    """Capture cookies, UA, and deployment ID from the browser and return a valid signed-in token."""
    cookies = [dict(c) for c in await context.cookies(["https://arena.ai/"])]
    token = _extract_arena_auth_from_cookies(cookies)
    try:
        ua, dpl = await page.evaluate(
            "() => [navigator.userAgent || '', document.documentElement.getAttribute('data-dpl-id') || '']"
        )
    except Exception:
        ua, dpl = "", ""
    _upsert_browser_session_into_config(cfg, cookies, user_agent=str(ua).strip() or None)
    if str(dpl).strip():
        cfg["arena_web_deployment"] = str(dpl).strip()
    return token if token and is_signed_in_arena_auth_token(token) else None


def _poll_imap_for_verification_url(
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    target_address: str,
    timeout_seconds: float = 120.0,
) -> Optional[str]:
    """Poll an IMAP mailbox for Arena's signup verification link."""
    deadline = time.monotonic() + max(5.0, float(timeout_seconds))
    seen_ids: set[bytes] = set()
    while time.monotonic() < deadline:
        conn = None
        try:
            conn = imaplib.IMAP4_SSL(host, int(port))
            conn.login(user, password)
            conn.select("INBOX")
            status, data = conn.search(None, '(FROM "arena")')
            ids = data[0].split() if status == "OK" and data and data[0] else []
            for msg_id in reversed(ids[-10:]):
                if msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)
                st, msg_data = conn.fetch(msg_id, "(RFC822)")
                if st != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
                    continue
                msg = email_lib.message_from_bytes(msg_data[0][1])
                if target_address and target_address.lower() not in str(msg.get("To") or "").lower():
                    continue
                parts = [
                    (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
                    for part in msg.walk()
                    if part.get_content_type() in ("text/plain", "text/html")
                ]
                url = extract_arena_verification_url(*parts)
                if url:
                    return url
        except Exception:
            pass
        finally:
            if conn is not None:
                try:
                    conn.logout()
                except Exception:
                    pass
        time.sleep(3.0)
    return None


async def login_arena_email_account(
    address: str,
    password: str,
    *,
    config: Optional[dict[str, Any]] = None,
    headless: bool = False,
) -> Optional[str]:
    """Log into an existing Arena email/password account via Playwright Chrome."""
    address, password = str(address or "").strip(), str(password or "").strip()
    if not address or not password:
        return None
    cfg = config if isinstance(config, dict) else {}
    async with _arena_email_page(address, headless) as (page, context):
        await page.get_by_role("heading", name=re.compile(r"Log In to your account", re.I)).wait_for(
            state="visible", timeout=20000
        )
        await page.locator("input[type='password']").first.fill(password)
        await page.locator("[role='dialog']").get_by_role("button", name=re.compile(r"^log in$", re.I)).first.click()
        await page.wait_for_timeout(5000)
        return await _capture_session_from_page(page, context, cfg)


async def signup_arena_email_account(
    address: str,
    *,
    password: Optional[str] = None,
    wait_for_verification_url: Callable[[str, float], Any],
    config: Optional[dict[str, Any]] = None,
    headless: bool = False,
) -> tuple[Optional[str], str]:
    """Sign up a new Arena account with a permitted email address and verification callback."""
    address = str(address or "").strip()
    pw = str(password or "").strip() or ("Lmab_" + secrets.token_hex(10) + "A1!")
    if not address:
        return None, pw
    cfg = config if isinstance(config, dict) else {}
    started_at = time.time()

    async with _arena_email_page(address, headless) as (page, context):
        await page.wait_for_timeout(2500)
        dialog_text = (await page.locator("[role='dialog']").inner_text()).lower()
        for marker in _EMAIL_BLOCKED_MARKERS:
            if marker in dialog_text:
                raise ValueError(f"Arena rejected email domain for {address}: {marker}")

        create_btn = page.get_by_role("button", name="Create Account", exact=True)
        await create_btn.wait_for(state="visible", timeout=20000)
        name_field = page.get_by_role("textbox", name=re.compile(r"Full Name", re.I))
        if await name_field.count():
            await name_field.fill("Bridge User")
        await create_btn.click()
        await page.get_by_role("heading", name=re.compile(r"Verify your email address", re.I)).wait_for(
            state="visible", timeout=30000
        )

        verif_url = wait_for_verification_url(address, started_at)
        if asyncio.iscoroutine(verif_url):
            verif_url = await verif_url
        if not verif_url:
            return None, pw

        await page.goto(str(verif_url), wait_until="domcontentloaded", timeout=90000)
        pw_fields = page.locator("input[type='password']")
        await pw_fields.first.wait_for(state="visible", timeout=30000)
        await pw_fields.nth(0).fill(pw)
        if await pw_fields.count() >= 2:
            await pw_fields.nth(1).fill(pw)
        await page.get_by_role("button", name=re.compile(r"^finish$", re.I)).first.click()
        await page.wait_for_timeout(6000)
        return await _capture_session_from_page(page, context, cfg), pw


async def recover_arena_auth_session(
    old_token: str = "",
    config: Optional[dict[str, Any]] = None,
) -> Optional[str]:
    """Recover a signed-in session via saved email credentials or IMAP-backed signup."""
    from . import main as _main

    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("LM_ALLOW_RECOVERY_IN_TESTS"):
        return None

    async with _ACCOUNT_RECOVERY_LOCK:
        cfg = config if isinstance(config, dict) else _main.get_config()
        cfg = cfg if isinstance(cfg, dict) else {}
        account = cfg.get("managed_account") if isinstance(cfg.get("managed_account"), dict) else {}
        env_or_cfg = lambda env, key, default="": str(os.environ.get(env) or cfg.get(key) or default).strip()

        email_addr = str(account.get("address") or os.environ.get("LM_ARENA_EMAIL") or "").strip()
        email_pw = str(account.get("password") or os.environ.get("LM_ARENA_PASSWORD") or "").strip()
        token: Optional[str] = None
        new_managed_account: Optional[dict] = None

        if email_addr and email_pw:
            try:
                _main.debug_print(f"🔐 Attempting Arena email re-login for {email_addr}...")
                token = await login_arena_email_account(email_addr, email_pw, config=cfg)
            except Exception as exc:
                _main.debug_print(f"⚠️ Arena email re-login failed: {type(exc).__name__}: {exc}")

        if not token:
            imap_host = env_or_cfg("LM_IMAP_HOST", "imap_host")
            imap_user = env_or_cfg("LM_IMAP_USER", "imap_user")
            imap_pass = env_or_cfg("LM_IMAP_PASSWORD", "imap_password")
            imap_port = int(env_or_cfg("LM_IMAP_PORT", "imap_port", "993"))
            signup_email = env_or_cfg("LM_SIGNUP_EMAIL", "signup_email", imap_user)
            if imap_host and imap_user and imap_pass and signup_email:
                try:
                    _main.debug_print(f"🆕 Attempting Arena email auto-signup for {signup_email}...")
                    wait_verif = lambda addr, _since: asyncio.to_thread(
                        _poll_imap_for_verification_url,
                        host=imap_host,
                        port=imap_port,
                        user=imap_user,
                        password=imap_pass,
                        target_address=addr,
                    )
                    token, used_pw = await signup_arena_email_account(
                        signup_email, wait_for_verification_url=wait_verif, config=cfg
                    )
                    if token:
                        new_managed_account = {
                            "provider": "email",
                            "address": signup_email,
                            "password": used_pw,
                            "created_at": int(time.time()),
                            "status": "active",
                        }
                except Exception as exc:
                    _main.debug_print(f"⚠️ Arena email auto-signup failed: {type(exc).__name__}: {exc}")

        if token and is_signed_in_arena_auth_token(token):
            _main.EPHEMERAL_ARENA_AUTH_TOKEN = token
            _persist_refreshed_auth_token(cfg, old_token, token, managed_account=new_managed_account)
            _main.debug_print("✅ Recovered signed-in arena-auth-prod-v1 session.")
            return token
        return None
