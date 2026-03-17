try:
    from ..engine_combined import FileUploadAttacker, JWTAttacker, WebSocketTester
except (ImportError, ModuleNotFoundError):
    # Fallback if engine_combined.py is not available
    # These classes are not essential for the main pipeline
    FileUploadAttacker = None
    JWTAttacker = None
    WebSocketTester = None

__all__ = ['FileUploadAttacker', 'JWTAttacker', 'WebSocketTester']
