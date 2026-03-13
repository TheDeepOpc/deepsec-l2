from pathlib import Path
import base64
import zlib

_DIR = Path(__file__).resolve().parent
_PARTS = sorted(_DIR.glob('attacks_blob_*.txt'))
if not _PARTS:
    raise RuntimeError('Missing attacks blob parts')

_ENC = ''.join(p.read_text(encoding='ascii') for p in _PARTS)
_SRC = zlib.decompress(base64.b64decode(_ENC)).decode('utf-8')
exec(compile(_SRC, str(_DIR / 'attacks_combined.py'), 'exec'), globals(), globals())

del _DIR, _PARTS, _ENC, _SRC

__all__ = ['FileUploadAttacker', 'JWTAttacker', 'WebSocketTester']
