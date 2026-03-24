from __future__ import annotations

import platform
import shutil
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Callable, Optional

try:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    HAS_PLAYWRIGHT = True
except Exception:
    HAS_PLAYWRIGHT = False
    PlaywrightError = Exception
    sync_playwright = None


def _log(logger: Optional[Callable[[str], None]], message: str) -> None:
    if callable(logger):
        logger(message)


def _normalize_url(url: str) -> str:
    value = str(url or "").strip()
    if not value:
        return value
    if not urllib.parse.urlparse(value).scheme:
        return f"https://{value}"
    return value


def _try_playwright_install(logger: Optional[Callable[[str], None]]) -> bool:
    cmd = [sys.executable, "-m", "playwright", "install", "chromium"]
    try:
        _log(logger, "Screenshot: Playwright browser missing, installing chromium...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.returncode == 0
    except Exception as exc:
        _log(logger, f"Screenshot: Playwright install failed: {exc}")
        return False


def _capture_with_playwright(
    url: str,
    output_path: Path,
    *,
    logger: Optional[Callable[[str], None]],
    width: int,
    height: int,
) -> bool:
    if not HAS_PLAYWRIGHT:
        return False

    attempts = [
        {"channel": "msedge"} if platform.system().lower().startswith("win") else {},
        {"channel": "chrome"},
        {},
    ]
    seen = set()
    for options in attempts:
        key = tuple(sorted(options.items()))
        if key in seen:
            continue
        seen.add(key)
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    headless=True,
                    args=[
                        "--ignore-certificate-errors",
                        "--disable-web-security",
                        "--disable-dev-shm-usage",
                    ],
                    **options,
                )
                context = browser.new_context(
                    viewport={"width": width, "height": height},
                    ignore_https_errors=True,
                    java_script_enabled=True,
                )
                page = context.new_page()
                page.goto(url, wait_until="domcontentloaded", timeout=45000)
                try:
                    page.wait_for_load_state("networkidle", timeout=6000)
                except Exception:
                    pass
                page.wait_for_timeout(1500)
                page.screenshot(path=str(output_path), full_page=False)
                context.close()
                browser.close()
                return output_path.exists() and output_path.stat().st_size > 0
        except PlaywrightError as exc:
            _log(logger, f"Screenshot: Playwright launch failed ({options or 'bundled'}): {exc}")
        except Exception as exc:
            _log(logger, f"Screenshot: Playwright capture failed ({options or 'bundled'}): {exc}")
    return False


def _capture_with_browser_cli(
    url: str,
    output_path: Path,
    *,
    logger: Optional[Callable[[str], None]],
    width: int,
    height: int,
) -> bool:
    binaries = [
        "msedge",
        "chrome",
        "google-chrome",
        "chromium",
        "chromium-browser",
    ]
    for binary in binaries:
        browser = shutil.which(binary)
        if not browser:
            continue
        cmd = [
            browser,
            "--headless",
            "--disable-gpu",
            "--hide-scrollbars",
            "--ignore-certificate-errors",
            f"--window-size={width},{height}",
            f"--screenshot={output_path}",
            url,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            if result.returncode == 0 and output_path.exists() and output_path.stat().st_size > 0:
                return True
            _log(logger, f"Screenshot: browser CLI failed via {binary}: {result.stderr.strip()}")
        except Exception as exc:
            _log(logger, f"Screenshot: browser CLI error via {binary}: {exc}")
    return False


def capture_homepage_screenshot(
    url: str,
    output_path: str | Path,
    *,
    logger: Optional[Callable[[str], None]] = None,
    viewport_width: int = 1440,
    viewport_height: int = 820,
) -> Optional[Path]:
    normalized_url = _normalize_url(url)
    if not normalized_url:
        return None

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    if _capture_with_playwright(
        normalized_url,
        destination,
        logger=logger,
        width=viewport_width,
        height=viewport_height,
    ):
        return destination

    if HAS_PLAYWRIGHT and _try_playwright_install(logger):
        time.sleep(1)
        if _capture_with_playwright(
            normalized_url,
            destination,
            logger=logger,
            width=viewport_width,
            height=viewport_height,
        ):
            return destination

    if _capture_with_browser_cli(
        normalized_url,
        destination,
        logger=logger,
        width=viewport_width,
        height=viewport_height,
    ):
        return destination

    return None
