"""Shared imports, constants, and runtime helpers for module-based builds."""

from __future__ import annotations

import collections
import hashlib
import json
import os
import random
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..engine import *
from .. import engine as _engine

try:
    from rich import box
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    box = None
    Panel = None
    Table = None


MAX_URLS = 120
MIN_CONFIDENCE = 70
BASELINE_REPEATS = 2
MAX_WORKERS = 4


def temp_file(name: str) -> str:
    return str(Path(tempfile.gettempdir()) / name)


_run_cmd = getattr(_engine, "_run_cmd", None) or getattr(_engine, "run_cmd", None)


def print_tools_status() -> None:
    """Compatibility wrapper for tool availability output."""
    fn = getattr(_engine, "_print_tools_status", None) or getattr(_engine, "print_tools_status", None)
    if callable(fn):
        fn()
        return

    out = getattr(_engine, "console", None)
    if out is None:
        return
    out.print("\n[cyan]━━ TOOLS STATUS ━━[/cyan]")
    for tool in ("nmap", "ffuf", "gobuster", "sqlmap", "nuclei", "nikto"):
        state = "installed" if shutil.which(tool) else "missing"
        color = "green" if state == "installed" else "yellow"
        out.print(f"  [{color}]{tool}: {state}[/{color}]")


def create_ollama_client():
    """Return an Ollama client instance if available, otherwise None."""
    lib = getattr(_engine, "_ollama", None) or getattr(_engine, "ollama", None)
    if lib is None:
        return None
    try:
        host = getattr(_engine, "OLLAMA_HOST", "http://127.0.0.1:11434")
        return lib.Client(host=host)
    except Exception:
        return None


__all__ = [name for name in globals() if not name.startswith("_")] + ["_run_cmd"]
