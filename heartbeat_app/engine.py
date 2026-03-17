"""Direct engine source import with backward-compatible private exports.

This module provides backward compatibility by attempting to load engine_combined,
but gracefully handles cases where it's not available (e.g., when only modules/ is present).
"""

# Try to import engine_combined for backward compatibility
_engine_combined = None
try:
	from . import engine_combined as _engine_combined
	from .engine_combined import *
except ImportError:
	# engine_combined.py not available - using modules/ instead
	# Provide minimal compatibility shims
	pass

# Provide compatibility exports
_run_cmd = None
_print_tools_status = None
_ollama = None

if _engine_combined is not None:
	_run_cmd = getattr(_engine_combined, "_run_cmd", None)
	_print_tools_status = getattr(_engine_combined, "_print_tools_status", None)
	_ollama = getattr(_engine_combined, "_ollama", None)

# Export all public symbols
__all__ = [name for name in globals() if not name.startswith("_")] + [
	"_run_cmd",
	"_print_tools_status",
	"_ollama",
]

