"""Runtime compatibility layer for module-based builds.

This module replaces the old ``engine_combined`` dependency with a small
runtime shim that exposes the symbols expected by ``heartbeat_app.modules``.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

try:
    from rich.console import Console

    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

    class _PlainConsole:
        def print(self, *args: Any, **kwargs: Any) -> None:
            text = " ".join(str(arg) for arg in args)
            safe = text.encode("ascii", errors="replace").decode("ascii")
            print(safe)

    console = _PlainConsole()

try:
    import ollama as _ollama

    HAS_OLLAMA = True
except ImportError:
    _ollama = None
    HAS_OLLAMA = False

try:
    import mitmproxy  # noqa: F401

    HAS_MITMPROXY = True
except ImportError:
    HAS_MITMPROXY = False


OLLAMA_HOST = "http://127.0.0.1:11434"
MODEL_NAME = "llama3.1:8b"
REPORT_DIR = Path("pentest_reports")
REPORT_DIR.mkdir(exist_ok=True, parents=True)
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DeepSec/7.0"


def _normalize_command(command: str) -> str:
    """Translate simple POSIX redirections into something PowerShell tolerates."""
    return command.replace("2>/dev/null", " 2>$null")


def _run_cmd(command: str, timeout: int = 60, check: bool = False) -> dict[str, Any]:
    """Run shell command and return a stable dict contract used across modules."""
    prepared = _normalize_command(command)
    completed = subprocess.run(
        prepared,
        shell=True,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    output = (completed.stdout or "") + (completed.stderr or "")
    result = {
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "output": output.strip(),
        "command": prepared,
    }
    if check and completed.returncode != 0:
        raise subprocess.CalledProcessError(
            completed.returncode,
            prepared,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    return result


run_cmd = _run_cmd


def _print_tools_status() -> None:
    console.print("\n[cyan]━━ TOOLS STATUS ━━[/cyan]")
    for tool in (
        "nmap",
        "ffuf",
        "gobuster",
        "sqlmap",
        "nuclei",
        "nikto",
        "whatweb",
        "wafw00f",
        "subfinder",
        "amass",
    ):
        state = "installed" if shutil.which(tool) else "missing"
        color = "green" if state == "installed" else "yellow"
        console.print(f"  [{color}]{tool}: {state}[/{color}]")


print_tools_status = _print_tools_status


def shell_join(parts: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in parts)


__all__ = [
    "console",
    "HAS_RICH",
    "HAS_OLLAMA",
    "HAS_MITMPROXY",
    "OLLAMA_HOST",
    "MODEL_NAME",
    "REPORT_DIR",
    "DEFAULT_UA",
    "_ollama",
    "_run_cmd",
    "run_cmd",
    "_print_tools_status",
    "print_tools_status",
    "shell_join",
]
