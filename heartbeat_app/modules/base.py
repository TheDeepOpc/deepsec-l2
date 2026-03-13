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

__all__ = [name for name in globals() if not name.startswith("_")]
