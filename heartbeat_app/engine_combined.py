"""Backward-compatible shim for legacy imports.

Older local tests import ``heartbeat_app.engine_combined.CascadeDetector``.
This module keeps that path working in the modular build.
"""

from __future__ import annotations

from typing import Any, Dict, List


class CascadeDetector:
    """Detects when a result set is dominated by redirects/noise responses."""

    CASCADE_STATUSES = {301, 302, 307, 308, 403, 404}
    DEFAULT_THRESHOLD = 0.60

    @classmethod
    def detect_cascading_redirects(
        cls,
        results: List[Dict[str, Any]],
        threshold: float = DEFAULT_THRESHOLD,
    ) -> Dict[str, Any]:
        total = len(results or [])
        if total == 0:
            return {
                "is_cascading": False,
                "cascade_percent": 0.0,
                "should_halt": False,
                "reason": "No results to evaluate.",
            }

        noisy = 0
        for item in results:
            try:
                status = int((item or {}).get("status", 0))
            except (TypeError, ValueError):
                status = 0
            if status in cls.CASCADE_STATUSES:
                noisy += 1

        cascade_percent = noisy / total
        is_cascading = cascade_percent >= max(0.0, min(1.0, threshold))
        reason = (
            f"{cascade_percent:.1%} of responses are redirect/error-like."
            if is_cascading
            else f"Only {cascade_percent:.1%} redirect/error-like responses."
        )
        return {
            "is_cascading": is_cascading,
            "cascade_percent": cascade_percent,
            "should_halt": is_cascading,
            "reason": reason,
        }


__all__ = ["CascadeDetector"]
