import shutil

from ..engine import *
from .. import engine as _engine


def print_tools_status() -> None:
	"""Compatibility wrapper for tool availability output."""
	fn = getattr(_engine, "_print_tools_status", None) or getattr(_engine, "print_tools_status", None)
	if callable(fn):
		fn()
		return

	# Fallback if engine symbol is unavailable in current build.
	out = getattr(_engine, "console", None)
	if out is None:
		return
	out.print("\n[cyan]━━ TOOLS STATUS ━━[/cyan]")
	for tool in ("nmap", "ffuf", "gobuster", "sqlmap", "nuclei", "nikto"):
		state = "installed" if shutil.which(tool) else "missing"
		color = "green" if state == "installed" else "yellow"
		out.print(f"  [{color}]• {tool}: {state}[/{color}]")

__all__ = [name for name in globals() if not name.startswith("_")]
