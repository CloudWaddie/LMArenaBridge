"""
AI-powered reCAPTCHA v2 image challenge solver using YOLO vision models.

Wraps vision-ai-recaptcha-solver (AsyncRecaptchaSolver) for async use.
Auto-downloads models from Hugging Face on first run.
Acts as a fallback when simple invisible v2 minting fails.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

VISION_SOLVER_AVAILABLE: bool = False
_import_error: Optional[str] = None

try:
    from vision_ai_recaptcha_solver import AsyncRecaptchaSolver, SolverConfig, SolveResult

    VISION_SOLVER_AVAILABLE = True
except ImportError as _exc:
    _import_error = str(_exc)
    VISION_SOLVER_AVAILABLE = False


def _m():
    from . import main
    return main


VISION_SOLVER_CONFIG_KEY = "vision_recaptcha_solver"


class VisionSolverConfig:
    enabled: bool
    headless: bool
    timeout: float
    max_attempts: int
    server_port: int
    conf_threshold: float
    detection_conf_threshold: float
    browser_path: Optional[str]
    proxy: Optional[str]
    download_dir: Optional[str]

    def __init__(self, config: Optional[dict] = None):
        cfg = config or {}
        solver_cfg = cfg.get(VISION_SOLVER_CONFIG_KEY, {}) if isinstance(cfg, dict) else {}
        if not isinstance(solver_cfg, dict):
            solver_cfg = {}

        self.enabled = bool(solver_cfg.get("enabled", True))
        self.headless = bool(solver_cfg.get("headless", True))
        self.timeout = float(solver_cfg.get("timeout", 180.0))
        self.max_attempts = int(solver_cfg.get("max_attempts", 3))
        self.server_port = int(solver_cfg.get("server_port", 0)) or 0
        self.conf_threshold = float(solver_cfg.get("conf_threshold", 0.7))
        self.detection_conf_threshold = float(solver_cfg.get("detection_conf_threshold", 0.6))
        self.browser_path = str(solver_cfg.get("browser_path") or "").strip() or None
        self.proxy = str(solver_cfg.get("proxy") or "").strip() or None
        dl_dir = str(solver_cfg.get("download_dir") or "").strip()
        self.download_dir = dl_dir if dl_dir else None


async def solve_recaptcha_v2_challenge(
    website_key: str,
    website_url: str = "https://arena.ai/",
    solver_config: Optional[VisionSolverConfig] = None,
) -> Optional[str]:
    """
    Solve a reCAPTCHA v2 image challenge using YOLO vision models.
    Returns the reCAPTCHA response token, or None on failure.
    """
    if not VISION_SOLVER_AVAILABLE:
        err = _import_error or "vision-ai-recaptcha-solver not installed"
        _m().debug_print(f"⚠️ Vision solver unavailable: {err}")
        return None

    if solver_config is None:
        solver_config = VisionSolverConfig()

    if not solver_config.enabled:
        _m().debug_print("⚠️ Vision solver disabled by config")
        return None

    _m().debug_print("🤖 Vision AI reCAPTCHA solver starting...")

    kwargs: dict = {
        "timeout": solver_config.timeout,
        "headless": solver_config.headless,
        "max_attempts": solver_config.max_attempts,
        "conf_threshold": solver_config.conf_threshold,
        "detection_conf_threshold": solver_config.detection_conf_threshold,
        "bypass_domain_check": True,
        "use_ssl": True,
        "verbose": _m().DEBUG if hasattr(_m(), "DEBUG") else False,
    }

    if solver_config.server_port > 0:
        kwargs["server_port"] = solver_config.server_port
    if solver_config.browser_path:
        browser_path = Path(solver_config.browser_path)
        if browser_path.exists():
            kwargs["browser_path"] = str(browser_path)
        else:
            _m().debug_print(f"⚠️ Vision solver configured browser_path not found: {solver_config.browser_path}")
    if solver_config.proxy:
        kwargs["proxy"] = solver_config.proxy
    if solver_config.download_dir:
        kwargs["download_dir"] = Path(solver_config.download_dir)

    try:
        config = SolverConfig(**kwargs)
        async with AsyncRecaptchaSolver(config) as solver:
            result: SolveResult = await solver.solve(
                website_key=website_key,
                website_url=website_url,
                is_invisible=False,
                is_enterprise=True,
                bypass_domain_check=True,
            )
            if result and result.token:
                _m().debug_print(
                    f"✅ Vision solver success! "
                    f"type={result.captcha_type.value}, "
                    f"time={result.time_taken:.1f}s, "
                    f"attempts={result.attempts}"
                )
                return result.token
            _m().debug_print("⚠️ Vision solver returned no token")
            return None
    except asyncio.TimeoutError:
        _m().debug_print("❌ Vision solver timed out")
        return None
    except Exception as e:
        _m().debug_print(f"❌ Vision solver error: {type(e).__name__}: {e}")
        return None
