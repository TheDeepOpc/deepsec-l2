"""
403 Bypass Analyzer
This module provides tools to analyze 403 Forbidden responses to determine
if they are bypassable. It distinguishes between hard file-level blocks and
soft directory-level blocks that might have accessible children.
"""

class BypassAnalyzer:
    """
    Analyzes 403 Forbidden responses to determine if they are bypassable.
    """

    def analyze_403(self, url: str, response_headers: dict, response_body: str) -> dict:
        """
        Analyzes a 403 response and recommends the next action.

        Returns a decision dictionary:
        {
            "action": "FUZZ_CHILDREN" | "ATTEMPT_BYPASS" | "SKIP",
            "reason": "AI's explanation for the decision.",
            "confidence": float
        }
        """
        # 1. URL tuzilishini tahlil qilish: Bu faylmi yoki papka?
        # Simple check for file extensions or paths ending not with /
        is_file = any(url.lower().endswith(ext) for ext in [
            '.php', '.bak', '.config', '.log', '.zip', '.txt', '.html', '.js', '.css'
        ]) or not url.endswith('/')

        # 2. Javob tanasini (body) tahlil qilish:
        body = response_body.lower()
        is_generic = "forbidden" in body or "access denied" in body
        is_login_wall = "login" in body or "authenticate" in body or "signin" in body

        # 3. AI QAROR QABUL QILADI:
        if is_login_wall:
            return {
                "action": "SKIP",
                "reason": "403 is an authentication wall. Requires login.",
                "confidence": 0.98
            }

        if is_file:
            # Agar bu aniq fayl bo'lsa, uni aylanib o'tishga harakat qilish befoyda.
            # Lekin header/method bypass harakat qilib ko'rish mumkin.
            return {
                "action": "ATTEMPT_BYPASS",
                "reason": f"Path appears to be a protected file. Fuzzing children is not logical, but attempting header/method bypasses.",
                "confidence": 0.60
            }
        
        if not is_generic:
             # Agar 403 sahifasi noodatiy bo'lsa, bu yerda bypass imkoniyati bor
             return {
                 "action": "ATTEMPT_BYPASS",
                 "reason": "Non-generic 403 page detected. Attempting header/method bypasses.",
                 "confidence": 0.75
             }

        # Agar bu papka bo'lsa va javob oddiy "Forbidden" bo'lsa, ichidagi fayllarni qidirish kerak.
        return {
            "action": "FUZZ_CHILDREN",
            "reason": "Path appears to be a directory. Fuzzing for child paths is recommended.",
            "confidence": 0.90
        }
