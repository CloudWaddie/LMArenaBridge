"""
Browser warmup and anti-detection utilities for LMArenaBridge.

Implements behavioral patterns to avoid Cloudflare bot detection:
- Natural page navigation with delays
- Scroll simulation
- Mouse movement patterns
- Random timing jitter
"""

import asyncio
import random
from typing import Optional


def _m():
    from . import main

    return main


async def warmup_browser_session(page, config: Optional[dict] = None) -> bool:
    """
    Warm up a browser session with natural human-like behavior before making API requests.

    Based on Scrapfly 2026 recommendations for bypassing Cloudflare behavioral detection.

    Returns True if warmup succeeded, False if it failed (e.g., stuck on challenge page).
    """
    cfg = config or {}
    warmup_enabled = cfg.get("browser_warmup_enabled", True)

    if not warmup_enabled:
        return True

    try:
        _m().debug_print("🔥 Warming up browser session...")

        current_url = ""
        try:
            current_url = page.url
        except Exception:
            pass

        if not current_url or current_url == "about:blank":
            _m().debug_print("  📍 Navigating to arena.ai homepage...")
            try:
                await page.goto("https://arena.ai", wait_until="domcontentloaded", timeout=30000)
            except Exception as e:
                _m().debug_print(f"  ⚠️ Homepage navigation failed: {e}")
                return False

        await asyncio.sleep(random.uniform(1.5, 3.0))

        try:
            title = await page.title()
            if "just a moment" in title.lower() or "cloudflare" in title.lower():
                _m().debug_print("  ⚠️ Stuck on Cloudflare challenge page")
                return False
        except Exception:
            pass

        _m().debug_print("  📜 Simulating page reading (scroll)...")
        try:
            await page.evaluate("""
                () => {
                    window.scrollTo({
                        top: Math.min(300, document.body.scrollHeight * 0.3),
                        behavior: 'smooth'
                    });
                }
            """)
        except Exception:
            pass

        await asyncio.sleep(random.uniform(1.0, 2.0))

        try:
            await page.evaluate("""
                () => {
                    window.scrollTo({
                        top: Math.min(600, document.body.scrollHeight * 0.5),
                        behavior: 'smooth'
                    });
                }
            """)
        except Exception:
            pass

        await asyncio.sleep(random.uniform(0.8, 1.5))

        _m().debug_print("  🖱️ Simulating mouse movement...")
        try:
            await page.mouse.move(random.randint(100, 400), random.randint(100, 300))
            await asyncio.sleep(random.uniform(0.3, 0.6))
            await page.mouse.move(random.randint(200, 600), random.randint(150, 400))
        except Exception:
            pass

        await asyncio.sleep(random.uniform(0.5, 1.0))

        _m().debug_print("  ✅ Browser warmup complete")
        return True

    except Exception as e:
        _m().debug_print(f"  ⚠️ Browser warmup failed: {e}")
        return False


async def random_delay(min_seconds: float = 0.5, max_seconds: float = 2.0) -> None:
    """
    Add random delay to avoid timing pattern detection.

    Args:
        min_seconds: Minimum delay in seconds
        max_seconds: Maximum delay in seconds
    """
    delay = random.uniform(min_seconds, max_seconds)
    await asyncio.sleep(delay)


async def simulate_human_typing(page, selector: str, text: str, typing_speed_wpm: int = 60) -> None:
    """
    Type text into an input field with human-like timing.

    Args:
        page: Playwright page object
        selector: CSS selector for input field
        text: Text to type
        typing_speed_wpm: Words per minute (average human: 40-60 WPM)
    """
    chars_per_second = (typing_speed_wpm * 5) / 60
    delay_per_char = 1.0 / chars_per_second

    try:
        element = await page.query_selector(selector)
        if not element:
            return

        await element.click()
        await asyncio.sleep(random.uniform(0.1, 0.3))

        for char in text:
            await element.type(char)
            jitter = random.uniform(0.8, 1.2)
            await asyncio.sleep(delay_per_char * jitter)

    except Exception:
        pass


def get_random_viewport() -> dict:
    """
    Return a random but realistic viewport size.

    Common desktop resolutions to avoid fingerprinting.
    """
    viewports = [
        {"width": 1920, "height": 1080},
        {"width": 1366, "height": 768},
        {"width": 1536, "height": 864},
        {"width": 1440, "height": 900},
        {"width": 1280, "height": 720},
    ]
    return random.choice(viewports)


def get_random_user_agent() -> str:
    """
    Return a random but realistic Chrome user agent.

    Using recent Chrome versions (2026).
    """
    chrome_versions = [
        "122.0.0.0",
        "123.0.0.0",
        "124.0.0.0",
    ]
    version = random.choice(chrome_versions)

    user_agents = [
        f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36",
        f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36",
        f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36",
    ]

    return random.choice(user_agents)
