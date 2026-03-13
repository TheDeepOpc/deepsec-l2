"""Engine module loader.

Loads compressed source fragments from heartbeat_app/engine_parts and compiles
as one module body so runtime behavior stays identical to monolithic source.
"""

from pathlib import Path
import base64
import zlib

_PARTS_DIR = Path(__file__).with_name("engine_parts")
_PART_FILES = sorted(_PARTS_DIR.glob("blob_*.txt"))
if not _PART_FILES:
    raise RuntimeError(f"No engine source fragments found in {_PARTS_DIR}")

_ENC = "".join(p.read_text(encoding="ascii") for p in _PART_FILES)
_SOURCE = zlib.decompress(base64.b64decode(_ENC)).decode("utf-8")
exec(compile(_SOURCE, str(Path(__file__).with_name("engine_combined.py")), "exec"), globals(), globals())

del _PARTS_DIR, _PART_FILES, _ENC, _SOURCE
