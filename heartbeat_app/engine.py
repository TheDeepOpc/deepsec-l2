"""Direct engine source import with backward-compatible private exports."""

from . import engine_combined as _engine_combined
from .engine_combined import *

_run_cmd = getattr(_engine_combined, "_run_cmd", None)
_print_tools_status = getattr(_engine_combined, "_print_tools_status", None)
_ollama = getattr(_engine_combined, "_ollama", None)

__all__ = [name for name in globals() if not name.startswith("_")] + [
	"_run_cmd",
	"_print_tools_status",
	"_ollama",
]
