from .base import *

class AIEngine:
    # AI output validation schema — type and range for each field
    VALID_RISKS   = {"Critical", "High", "Medium", "Low", "Info"}
    VALID_OWASP   = {"A01","A02","A03","A04","A05","A06","A07","A08","A09","A10"}

    def __init__(self):
        self._cache: dict[str, Any] = {}

    def _validate_ai_output(self, result: dict) -> dict:
        """Validates AI output — fixes or sets safe defaults."""
        if not isinstance(result, dict):
            return {}
        # confidence — must be int in range 0..100
        if "confidence" in result:
            try:
                conf = int(result["confidence"])
                result["confidence"] = max(0, min(100, conf))
            except (ValueError, TypeError):
                result["confidence"] = 0
        # risk — must be one of known values
        if "risk" in result:
            if result["risk"] not in self.VALID_RISKS:
                result["risk"] = "Medium"
        # owasp_id — A01-A10
        if "owasp_id" in result:
            if result["owasp_id"] not in self.VALID_OWASP:
                result["owasp_id"] = "A05"
        # is_fp — bool
        if "is_fp" in result:
            result["is_fp"] = bool(result["is_fp"])
        # found — bool
        if "found" in result:
            result["found"] = bool(result["found"])
        # is_real_bac — bool
        if "is_real_bac" in result:
            result["is_real_bac"] = bool(result["is_real_bac"])
        # String fields — truncate
        for key in ("title", "evidence", "reason", "remediation", "exploit_cmd"):
            if key in result and isinstance(result[key], str):
                result[key] = result[key][:500]
        return result

    def _extract_json_payload(self, text: str):
        """Parse first valid JSON object/array from mixed model output."""
        if not text:
            return None
        decoder = json.JSONDecoder()
        for ch in ("{", "["):
            start = text.find(ch)
            if start == -1:
                continue
            try:
                obj, _end = decoder.raw_decode(text[start:])
                return obj
            except Exception:
                continue
        return None

    def _call(self, prompt: str, cache: bool = True) -> Optional[dict]:
        if not HAS_OLLAMA:
            return None
        key = hashlib.md5(prompt.encode()).hexdigest()
        if cache and key in self._cache:
            return self._cache[key]
        try:
            _client = create_ollama_client()
            if _client is None:
                return None
            resp = _client.chat(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": FUZZER_SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt},
                ],
            )
            raw   = resp["message"]["content"]
            clean = re.sub(r'```json|```', '', raw).strip()
            parsed = self._extract_json_payload(clean)
            if isinstance(parsed, dict):
                result = self._validate_ai_output(parsed)
                if cache:
                    self._cache[key] = result
                return result
            if isinstance(parsed, list):
                # Keep compatibility for callers that can handle list payloads.
                if cache:
                    self._cache[key] = {"findings": parsed}
                return {"findings": parsed}
        except Exception as e:
            console.print(f"[dim red]AI error: {e}[/dim red]")
        return None

    def identify_login_fields(self, html_body: str, url: str) -> dict:
        prompt = f"""Analyze this login page HTML and identify form field names.
URL: {url}
HTML (first 3000 chars): {html_body[:3000]}
Return JSON: {{"username_field": "username", "password_field": "password",
  "csrf_field": "csrf_token", "action_url": "/login"}}"""
        result = self._call(prompt) or {}
        return {
            "username_field": result.get("username_field", "username"),
            "password_field": result.get("password_field", "password"),
            "csrf_field":     result.get("csrf_field", "csrf_token"),
            "action_url":     result.get("action_url", url),
        }

    def plan_endpoints(self, endpoints: list[Endpoint]) -> list[Endpoint]:
        if not endpoints:
            return endpoints
        summary = [
            {"url": ep.url, "method": ep.method,
             "params": list(ep.params.keys())[:8], "source": ep.discovered_by}
            for ep in endpoints[:60]
        ]
        prompt = f"""You have {len(endpoints)} discovered endpoints to test for OWASP vulnerabilities.
Sample: {json.dumps(summary, indent=2)}
Prioritize endpoints. High priority: login, admin, API, id params, file params.
Return JSON: {{"priority_urls": ["http://...", ...]}}"""
        result    = self._call(prompt) or {}
        priority  = result.get("priority_urls", [])
        if not priority:
            return endpoints
        url_map   = {ep.url: ep for ep in endpoints}
        ordered   = [url_map[u] for u in priority if u in url_map]
        remaining = [ep for ep in endpoints if ep.url not in set(priority)]
        return ordered + remaining

    def classify_finding(self, context: dict) -> Optional[dict]:
        prompt = f"""Analyze this web application test result for vulnerabilities:
TARGET URL: {context.get('url')}
METHOD: {context.get('method')}
PARAMETER: {context.get('param')}
PAYLOAD: {context.get('payload')}
TOOL: {context.get('tool')}
BASELINE: Status={context.get('baseline_status')}, Size={context.get('baseline_size')}bytes, Time={context.get('baseline_timing')}s
FUZZED: Status={context.get('fuzz_status')}, Size={context.get('fuzz_size')}bytes, Time={context.get('fuzz_timing')}s
Size diff: {context.get('size_diff')} ({context.get('size_pct')}%), Time anomaly: {context.get('time_anomaly')}
New errors: {context.get('new_errors')}
Response snippet: {context.get('body_snippet', '')[:600]}
Tool output: {context.get('tool_output', '')[:800]}
STRICT RULES:
1) Do NOT report SQL injection based only on 400/500 status changes, generic exceptions, or larger error pages.
2) Report SQL injection only if there is DB-specific evidence: SQL syntax error text, sqlmap confirmation, boolean/time-based behavior, UNION/database markers.
3) Do NOT report LFI only because file names are mentioned. Report LFI only if actual file content is disclosed (e.g. passwd entries, win.ini sections, hosts file content).
4) Input-validation/type-conversion errors like "invalid literal for int()", "could not convert string to float", or plain ValueError/Traceback are NOT injection evidence.
5) If evidence is weak or ambiguous, mark as false positive.

Return ONLY JSON like:
{{"found": false, "confidence": 0, "owasp_id": "A05", "risk": "Low", "title": "", "evidence": "", "remediation": "", "exploit_cmd": "", "reason": ""}}"""
        return self._call(prompt, cache=False)

    def verify_finding(self, finding: "Finding", client: HTTPClient) -> dict:
        prompt = f"""Vulnerability to verify (lab only):
  URL: {finding.url}, Param: {finding.param}
  OWASP: {finding.owasp_id} - {finding.title}, Risk: {finding.risk}
  Evidence: {finding.evidence}
Write minimal non-destructive verification command.
Return JSON: {{"cmd": "curl ...", "expected": "what to look for", "safe": true}}"""
        result = self._call(prompt) or {}
        cmd = result.get("cmd", "")
        if not cmd:
            return {"confirmed": False, "reason": "No verification command"}
        r = _run_cmd(cmd, timeout=20)
        confirm_prompt = f"""Verification cmd: {cmd}
Expected: {result.get('expected','')}
Output: {r.get('output','')[:500]}
Confirmed? JSON: {{"confirmed": true/false, "evidence": "..."}}"""
        confirm = self._call(confirm_prompt, cache=False) or {}
        return {
            "confirmed": confirm.get("confirmed", False),
            "evidence":  confirm.get("evidence", ""),
            "cmd":       cmd,
            "output":    r.get("output", "")[:300],
        }

    def analyze_page(self, url: str, status: int, body: str,
                     headers: dict, is_200: dict) -> dict:
        title = re.search(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
        title = title.group(1).strip()[:80] if title else ""
        sens  = RiskScorer.score_body(body)
        prompt = f"""You are a web security analyst. Analyze this HTTP response.
URL: {url}, HTTP Status: {status}, Page Title: {title}, Content-Length: {len(body)}
Sensitive keys found: {json.dumps(sens)}
Body (first 2000 chars): {body[:2000]}
Answer ONLY in JSON:
{{
  "is_real_page": true, "is_auth_wall": false, "is_bac_candidate": false,
  "is_custom_404": false, "page_type": "login|admin|api|dashboard|config|error|static|unknown",
  "description": "What this page does",
  "sensitive_data": [], "available_actions": [], "next_tests": [],
  "suggested_child_paths": [], "risk": "Critical|High|Medium|Low|Info",
  "custom_404_reason": ""
}}"""
        return self._call(prompt, cache=False) or {
            "is_real_page": is_200.get("real", False),
            "page_type": "unknown", "description": "",
            "sensitive_data": [s["key"] for s in sens],
            "available_actions": [], "next_tests": [], "risk": "Info",
        }

    def analyze_bac(self, bac_data: dict) -> Optional[dict]:
        responses = bac_data.get("responses", {}) or {}
        anon = responses.get("anonymous", {}) or {}

        # Deterministic guardrails to avoid obvious FP before AI call.
        anon_status = anon.get("status", 0)
        anon_body   = (anon.get("body_snippet", "") or "").lower()
        anon_title  = (anon.get("title", "") or "").lower()
        anon_loc    = (anon.get("redirect_location", "") or "").lower()
        if anon_status in (401, 403):
            return {"found": False, "verified": False, "reason": "Anonymous is blocked (401/403)."}
        if any(x in anon_loc for x in ["/login", "/signin", "/auth"]):
            return {"found": False, "verified": False, "reason": "Anonymous is redirected to login."}
        login_hits = sum(1 for s in ["login", "sign in", "username", "password", "redirecting"] if s in anon_body)
        if login_hits >= 2 or any(x in anon_title for x in ["login", "sign in", "auth"]):
            return {"found": False, "verified": False, "reason": "Anonymous response is a login/auth page."}

        prompt = f"""Same endpoint requested with multiple user roles.
URL: {bac_data['url']}, Method: {bac_data['method']}
Role responses: {json.dumps(bac_data['responses'], indent=2)}
Comparison signals: {json.dumps(bac_data['comparisons'], indent=2)}
Is this BAC/IDOR?

STRICT RULES:
1) If anonymous gets login page or redirect-to-login, this is NOT BAC.
2) If authenticated user sees their own data on their own endpoint, this is NOT IDOR.
3) Report BAC/IDOR only when unauthorized role can access protected data with clear evidence.
4) Do not mark vulnerability based only on status=200; verify body content and access context.

Return ONLY JSON:
{{"found": false, "verified": false, "owasp_id": "A01", "risk": "High", "confidence": 0,
  "title": "...", "technical": "...", "exploitable": false,
  "exploit_cmd": "...", "remediation": "...", "reason": "..."}}"""
        result = self._call(prompt, cache=False) or {}
        if not isinstance(result, dict):
            return {"found": False, "verified": False, "reason": "AI parse failure"}
        if not result.get("found"):
            result["verified"] = False
            return result
        # If AI says found but cannot verify, keep it as not found to avoid noisy FP.
        if not result.get("verified", False):
            result["found"] = False
            result["confidence"] = min(int(result.get("confidence", 0) or 0), 40)
            result["reason"] = result.get("reason") or "Not verified as unauthorized access"
        return result

    def correlate(self, signals: list) -> list:
        if len(signals) < 2:
            return []
        prompt = f"""Multiple weak security signals:
{json.dumps(signals[:20], indent=2)}
Which form confirmed vulnerabilities?
Return JSON array: [{{"owasp_id":"A01","title":"...","risk":"High","confidence":70,"evidence":"..."}}]"""
        result = self._call(prompt, cache=False)
        if isinstance(result, list):
            return result
        if isinstance(result, dict) and "findings" in result:
            findings = result["findings"]
            return findings if isinstance(findings, list) else []
        return []

    def analyze_403_response(self, parent_url: str, child_url: str,
                             child_status: int, child_body: str,
                             child_headers: dict, context: str = "") -> dict:
        """
        AI fully analyzes any 403→200 response.
        Determines whether it's a static file (CSS/JS/image/font), login redirect,
        error page, or a real BAC — AI decides entirely on its own.

        AI sees the first 150 lines of the response body — sufficient to determine:
        - CSS file? → selectors/properties in body (.class { color: red })
        - JS file? → function/var/import in body
        - Image/font? → Content-Type header
        - Login page? → form, input password
        - Real data? → admin panel, user data, config

        AI makes the decision — no hardcoded filters.
        """
        title_m    = re.search(r'<title[^>]*>(.*?)</title>', child_body, re.I | re.S)
        page_title = title_m.group(1).strip()[:80] if title_m else ""
        ct_hdr     = child_headers.get("content-type", child_headers.get("Content-Type", ""))
        loc_hdr    = child_headers.get("location",     child_headers.get("Location", ""))
        server_hdr = child_headers.get("server",       child_headers.get("Server", ""))

        # Take only the first 150 lines from body (no need for 7000-line CSS)
        body_lines = child_body.split("\n")
        body_preview = "\n".join(body_lines[:150])
        if len(body_lines) > 150:
            body_preview += f"\n... [{len(body_lines) - 150} more lines truncated]"

        # Extract file extension from URL (context for AI)
        parsed_path = urllib.parse.urlparse(child_url).path
        file_ext = ""
        if "." in parsed_path.split("/")[-1]:
            file_ext = parsed_path.split("/")[-1].rsplit(".", 1)[-1].lower()

        prompt = f"""You are an expert penetration tester. A parent URL returned HTTP 403 (forbidden),
but a child URL under it returned HTTP {child_status} (accessible). Your job is to deeply
analyze the child response and determine what this content actually is.

CONTEXT:
  Parent URL (restricted):  {parent_url}
  Child URL (accessible):   {child_url}
  File extension in URL:    "{file_ext}" (may be empty)
  Context:                  {context}

CHILD RESPONSE METADATA:
  HTTP Status:     {child_status}
  Content-Type:    {ct_hdr}
  Server:          {server_hdr}
  Location header: {loc_hdr}
  Page title:      "{page_title}"
  Total body size: {len(child_body)} bytes ({len(body_lines)} lines)

CHILD RESPONSE BODY (first 150 lines — analyze the code/content structure):
---
{body_preview}
---

ANALYZE the body content carefully. Look at the actual code structure:
- CSS files have selectors, properties, @media, @import, .class {{ }}, #id {{ }}
- JavaScript files have function, var, let, const, import, export, =>, class
- Images/fonts are binary (garbled text or very short)
- HTML pages have <html>, <head>, <body>, <div> tags
- JSON API responses have {{"key": "value"}} structure
- Config files have KEY=VALUE or YAML/XML structure

DECISION CATEGORIES:
1. "static_asset" — CSS, JS, images, fonts, icons, source maps, SVG
   These are PUBLIC static files. Access to them is NOT a security vulnerability.
   Even under /admin/style.css — CSS is meant to be cached and served publicly.

2. "login_redirect" — Login form, auth page, "please sign in" content
   The server shows a login page instead of real content. NOT a BAC.

3. "error_page" — 404 custom page, error message, maintenance page, blank/empty
   Generic error or placeholder. NOT a BAC.

4. "public_content" — Public marketing page, documentation, help text
   Publicly intended content that happens to be under a restricted path. NOT a BAC.

5. "real_bac" — ACTUAL protected data: admin panel UI with real controls,
   user records/PII, configuration values, API keys, database contents,
   internal dashboards with real data, file manager, server status with internals.
   THIS IS a real Broken Access Control vulnerability.

IMPORTANT:
- A static file (CSS/JS/font/image) under /admin/ is NOT a BAC. Web apps commonly
  serve static assets from the same path prefix. The browser needs these files to
  render the login page itself.
- You must PROVE why something is a vulnerability. "It returned 200" is not enough.
- Explain what the content actually IS and what sensitive data it exposes.

Respond ONLY in JSON:
{{
  "verdict": "static_asset | login_redirect | error_page | public_content | real_bac",
  "is_real_bac": false,
  "confidence": 0,
  "content_type_detected": "css | javascript | html | json | image | font | text | binary | unknown",
  "what_i_see": "Detailed description of what this content actually is",
  "reason": "Specific technical reasoning for your decision — cite actual content from body",
  "evidence": "Exact snippet from body that confirms your verdict",
  "sensitive_data_found": "List any sensitive data if found, empty string if none"
}}"""

        result = self._call(prompt, cache=False)
        if result:
            return result

        # If AI unavailable — heuristic fallback
        return self._heuristic_403_analysis(child_url, child_status, child_body,
                                            child_headers, page_title, ct_hdr)

    def _heuristic_403_analysis(self, child_url: str, child_status: int,
                                 child_body: str, child_headers: dict,
                                 page_title: str, ct_hdr: str) -> dict:
        """Heuristic fallback when AI is unavailable."""
        body_lower = child_body.lower()
        ct_lower   = ct_hdr.lower() if ct_hdr else ""

        # Detect static asset based on Content-Type
        static_ct = ["text/css", "application/javascript", "text/javascript",
                     "image/", "font/", "application/font", "application/x-font",
                     "application/woff", "application/octet-stream"]
        if any(s in ct_lower for s in static_ct):
            return {
                "verdict": "static_asset", "is_real_bac": False,
                "confidence": 95, "content_type_detected": ct_lower.split(";")[0],
                "what_i_see": f"Static file (Content-Type: {ct_hdr})",
                "reason": f"Content-Type '{ct_hdr}' indicates a static asset, not protected data",
                "evidence": f"Content-Type: {ct_hdr}",
                "sensitive_data_found": "",
            }

        # Detect CSS/JS based on body content (first 50 lines)
        first_lines = "\n".join(child_body.split("\n")[:50]).lower()
        css_signals = sum(1 for p in [
            r'[{};]', r'\{[^}]*:', r'@media', r'@import', r'@charset',
            r'\.\w+\s*\{', r'#\w+\s*\{', r'color\s*:', r'font-', r'margin',
            r'padding', r'display\s*:', r'background', r'border',
        ] if re.search(p, first_lines))
        if css_signals >= 4:
            return {
                "verdict": "static_asset", "is_real_bac": False,
                "confidence": 90, "content_type_detected": "css",
                "what_i_see": f"CSS stylesheet ({css_signals} CSS patterns found in first 50 lines)",
                "reason": "Body contains CSS selectors, properties, and rules — this is a stylesheet",
                "evidence": first_lines[:200],
                "sensitive_data_found": "",
            }

        js_signals = sum(1 for p in [
            r'\bfunction\b', r'\bvar\b', r'\blet\b', r'\bconst\b',
            r'\bimport\b', r'\bexport\b', r'=>', r'\bclass\b',
            r'\breturn\b', r'document\.', r'window\.',
        ] if re.search(p, first_lines))
        if js_signals >= 3:
            return {
                "verdict": "static_asset", "is_real_bac": False,
                "confidence": 90, "content_type_detected": "javascript",
                "what_i_see": f"JavaScript file ({js_signals} JS patterns found in first 50 lines)",
                "reason": "Body contains JavaScript code — functions, variables, imports",
                "evidence": first_lines[:200],
                "sensitive_data_found": "",
            }

        # Detect login page
        login_words = ["login", "sign in", "username", "password", "log in",
                       "please log in", "authentication required", "signin"]
        login_count = sum(1 for s in login_words if s in body_lower)
        title_lower = page_title.lower()
        if login_count >= 2 or any(s in title_lower for s in ["login", "sign in", "auth", "signin"]):
            return {
                "verdict": "login_redirect", "is_real_bac": False,
                "confidence": 90, "content_type_detected": "html",
                "what_i_see": f"Login/auth page (title: '{page_title}')",
                "reason": f"Body has {login_count} login signals; title='{page_title}'",
                "evidence": f"login signals: {[s for s in login_words if s in body_lower]}",
                "sensitive_data_found": "",
            }

        # Empty page
        if len(child_body) < 200:
            return {
                "verdict": "empty_page", "is_real_bac": False,
                "confidence": 80, "content_type_detected": "unknown",
                "what_i_see": "Nearly empty response",
                "reason": f"Body only {len(child_body)} bytes — no real content",
                "evidence": child_body[:100],
                "sensitive_data_found": "",
            }

        return {
            "verdict": "unknown", "is_real_bac": False,
            "confidence": 0, "content_type_detected": "unknown",
            "what_i_see": child_body[:200],
            "reason": "AI unavailable — manual review needed",
            "evidence": "",
            "sensitive_data_found": "",
        }

    def verify_child_access(self, parent_url: str, child_url: str,
                            child_status: int, child_body: str,
                            child_headers: dict, parent_signal: str) -> dict:
        """
        Determines whether a child URL is a real BAC or a login redirect.
        Delegates to analyze_403_response and converts the result to legacy format.
        """
        result = self.analyze_403_response(
            parent_url=parent_url, child_url=child_url,
            child_status=child_status, child_body=child_body,
            child_headers=child_headers, context=f"parent_signal={parent_signal}",
        )
        # Maintain backward compatibility with old API
        return {
            "verdict":     result.get("verdict", "unknown"),
            "is_real_bac": result.get("is_real_bac", False),
            "confidence":  result.get("confidence", 0),
            "what_i_see":  result.get("what_i_see", ""),
            "reason":      result.get("reason", ""),
            "evidence":    result.get("evidence", ""),
        }


    def analyze_fuzz_baseline(self, base_url: str, probes: list) -> dict:
        """
        Analyzes 5 random probe results to determine optimal filter arguments
        for ffuf/gobuster/wfuzz.

        Questions:
        - Do all probes return the same status? (soft-404 pattern)
        - Are sizes consistent or constantly changing?
        - Is word count stable?
        - Is the title the same (branded 404)?
        - Which combination best rejects false positives?
        """
        prompt = f"""You are a penetration tester setting up smart fuzzing filters.

TARGET: {base_url}

I sent 5 random non-existent URL probes to fingerprint the 404/error behavior:
{json.dumps(probes, indent=2)}

ANALYZE these probes and determine the OPTIMAL ffuf/gobuster/wfuzz filters
to reject false positives while keeping real findings.

DECISION RULES:
1. If ALL probes have the SAME status code → add to filter_codes
2. If sizes are consistent (within 5% of each other) → add to filter_sizes
3. If word count is consistent (same value in all probes) → add to filter_words
4. If line count is consistent → add to filter_lines
5. If sizes vary significantly (>15%) → use filter_words or filter_lines instead
6. Never filter out 200 if some probes differ (might be real pages)
7. If the site returns 200 for everything with login page body:
   → filter by size AND words (login page is consistent size)
8. tolerance_bytes: how many bytes variance to accept (suggest 20-50 for stable,
   100-200 for dynamic sites)

Respond ONLY in JSON:
{{
  "filter_codes":   [],
  "filter_sizes":   [],
  "filter_words":   [],
  "filter_lines":   [],
  "tolerance_bytes": 20,
  "recursive": true,
  "explanation": "What pattern I detected and why I chose these filters",
  "site_type": "spa_with_login | traditional_404 | api | custom_404 | unknown",
  "warning": "Any important note about false positive risk"
}}"""
        result = self._call(prompt, cache=False)
        if result:
            return result

        # Fallback — uses BaselineEngine._heuristic_filters
        return {}


    def analyze_dir_hit(self, url: str, status: int, size: int,
                        words: int, lines: int, body: str,
                        profile: "SmartFuzzProfile") -> dict:
        """
        AI analyzes a URL found by ffuf/gobuster:
        - Real page or false positive?
        - What type (backup, config, admin, api, ...)?
        - How dangerous?
        - Needs recursive fuzzing (is it a directory)?
        """
        title_m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
        title   = title_m.group(1).strip()[:60] if title_m else ""

        prompt = f"""A fuzzer found this URL. Analyze if it's a real finding.

SMART PROFILE (what 404s look like on this site):
  filter_codes={profile.filter_codes}
  filter_sizes={profile.filter_sizes}
  filter_words={profile.filter_words}
  filter_lines={profile.filter_lines}
  Profile explanation: {profile.ai_explanation[:200]}

HIT DETAILS:
  URL:    {url}
  Status: {status}
  Size:   {size} bytes
  Words:  {words}
  Lines:  {lines}
  Title:  "{title}"
  Body (first 800 chars):
{body[:800]}

DECISION:
1. Does this look like a filtered-out 404 that slipped through? → is_sensitive=false
2. Is this a real page with content? What type?
3. Does it contain sensitive data (admin panel, config, backup, DB dump, source code)?
4. Is it a DIRECTORY that should be fuzzed recursively?
5. What OWASP category fits?

Respond ONLY in JSON:
{{
  "type": "admin|config|backup|api|static|error|login|unknown",
  "is_sensitive": false,
  "is_directory": false,
  "risk": "Critical|High|Medium|Low|Info",
  "confidence": 0,
  "owasp_id": "A05",
  "owasp_name": "Security Misconfiguration",
  "title": "Short finding title",
  "reason": "Detailed explanation of what you see and why",
  "remediation": "How to fix this",
  "false_positive_reason": "If FP, why"
}}"""
        result = self._call(prompt, cache=False)
        if result:
            return result

        # Heuristic fallback
        sensitive_keywords = [
            "admin","config","backup","secret",".env","db","database",
            "debug","shell","passwd","shadow","key","token","api",
            "swagger","actuator","phpmyadmin","console","phpinfo",
        ]
        url_lower  = url.lower()
        is_sens    = any(k in url_lower for k in sensitive_keywords)
        is_dir     = not any(url_lower.endswith(e) for e in [
            ".js",".css",".png",".jpg",".ico",".woff",".map",".txt"
        ]) and not re.search(r'\.\w{1,5}$', url_lower)
        return {
            "type":          "unknown",
            "is_sensitive":  is_sens,
            "is_directory":  is_dir,
            "risk":          "Medium" if is_sens else "Info",
            "confidence":    60 if is_sens else 30,
            "owasp_id":      "A05",
            "owasp_name":    "Security Misconfiguration",
            "title":         f"Exposed path: {url}",
            "reason":        f"URL contains sensitive keyword" if is_sens else "No sensitive indicators",
            "remediation":   "Review access controls for this path.",
            "false_positive_reason": "",
        }


    def fp_filter(self, finding: "Finding") -> dict:
        # Stronger analysis for BAC findings
        is_bac = finding.owasp_id == "A01" or "403" in finding.title or "bypass" in finding.title.lower()
        extra_rules = ""
        if is_bac:
            extra_rules = """

SPECIAL RULES FOR BAC/403 BYPASS FINDINGS:
- If the response body is CSS (selectors, properties, @media) → is_fp=true, reason="Static CSS file"
- If the response body is JavaScript (function, var, import) → is_fp=true, reason="Static JS file"
- If the Content-Type indicates a static asset (image, font, css, js) → is_fp=true
- If the URL ends with .css, .js, .png, .jpg, .gif, .svg, .ico, .woff, .woff2, .ttf, .map,
  .webp, .eot → is_fp=true, reason="Static asset file extension"
- A static file under /admin/ is NOT a BAC — browsers need these to render the login page.
- For real BAC: the body must contain ACTUAL protected data (admin UI, user records, configs, API keys).
- If the evidence only says "403→200" without proving sensitive data access → is_fp=true."""

        prompt = f"""Analyze this security finding for false positives. Be STRICT.

Finding:
  Title:         {finding.title}
  OWASP:         {finding.owasp_id} — {finding.owasp_name}
  Risk:          {finding.risk}
  Confidence:    {finding.confidence}%
  URL:           {finding.url}
  Payload:       {finding.payload[:200]}
  Evidence:      {finding.evidence}
  Baseline diff: {finding.baseline_diff}
  Tool:          {finding.tool}

Response body (first {2000 if is_bac else 500} chars):
---
{finding.response_raw[:2000] if is_bac else finding.response_raw[:500]}
---

Tool output (additional context):
---
{finding.tool_output[:500] if is_bac else ''}
---
{extra_rules}

GENERAL RULES:
- A finding with no concrete evidence of exploitability → is_fp=true
- Generic error pages, WAF blocks, empty responses → is_fp=true
- If evidence clearly shows real vulnerability → is_fp=false, increase confidence

Return JSON: {{"is_fp": false, "reason": "specific reason", "adjusted_confidence": 75}}"""
        return self._call(prompt, cache=False) or {"is_fp": False, "reason": "", "adjusted_confidence": finding.confidence}

class Recursive403Bypasser:
    """
    Problem: /admin → 403, /admin/config → 403, /admin/config/template → 200
    In V6.0 this is NOT FOUND because inner fuzz only keeps 200/201.

    This class:
    1. When 403 URL found → tries path/header/method bypass
    2. Inner fuzz: even 403 results → added to queue (recursive!)
    3. Separate fuzz for each layer
    4. Max 3 layers deep
    """
    PATH_VARIANTS = [
        lambda u: u + "/",
        lambda u: u + "%20",
        lambda u: u + "%09",
        lambda u: u + "/..",
        lambda u: u + "..;/",
        lambda u: u + "?",
        lambda u: u + "/*",
        lambda u: u.replace("/admin", "//admin") if "/admin" in u else u + "//",
        lambda u: re.sub(r'(/\w+)$', r'/.\1', u),
    ]
    HEADER_VARIANTS = [
        {"X-Forwarded-For":           "127.0.0.1"},
        {"X-Real-IP":                 "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Originating-IP":          "127.0.0.1"},
        {"X-Forwarded-Host":          "localhost"},
        {"X-Host":                    "127.0.0.1"},
        {"Client-IP":                 "127.0.0.1"},
        {"True-Client-IP":            "127.0.0.1"},
        {"X-Original-URL":            "PLACEHOLDER"},
        {"X-Rewrite-URL":             "PLACEHOLDER"},
    ]

    def __init__(self, client: HTTPClient, ai: AIEngine, wl_selector: "AIWordlistSelector"):
        self.client      = client
        self.ai          = ai
        self.wl_selector = wl_selector
        self._visited    : Set[str] = set()

    def bypass(self, start_url: str, max_depth: int = 3) -> List[Finding]:
        findings   : List[Finding] = []
        # BFS queue: (url, depth)
        bfs_queue  = [(start_url, 0)]

        while bfs_queue:
            url, depth = bfs_queue.pop(0)
            if url in self._visited or depth > max_depth:
                continue
            self._visited.add(url)

            parsed = urllib.parse.urlparse(url)
            path   = parsed.path
            leaf   = path.rstrip("/").rsplit("/", 1)[-1] if path.rstrip("/") else ""
            is_file_like_path = bool(leaf and "." in leaf and not path.endswith("/"))

            # ── 1. Baseline ───────────────────────────────────────────
            bl      = self.client.get(url)
            bl_hash = hashlib.md5(bl["body"].encode()).hexdigest() if bl["body"] else ""

            def is_potential_bypass(r: dict) -> bool:
                """Quick preliminary check — before sending to AI."""
                if r["status"] not in (200, 206): return False
                if not r["body"] or len(r["body"]) < 50: return False
                if hashlib.md5(r["body"].encode()).hexdigest() == bl_hash: return False
                login_kw = sum(1 for s in ["login","sign in","password","username"]
                               if s in r["body"].lower())
                return login_kw < 2

            def ai_verify_bypass(r: dict, test_url: str, bypass_type: str) -> Optional[dict]:
                """
                AI sees and analyzes every 403→200 response.
                Returns None for static files, login pages, error pages.
                Returns AI result if real BAC.
                """
                ai_result = self.ai.analyze_403_response(
                    parent_url=url,
                    child_url=test_url,
                    child_status=r["status"],
                    child_body=r["body"],
                    child_headers=r.get("headers", {}),
                    context=f"recursive_403_bypass_{bypass_type}_depth{depth}",
                )
                verdict     = ai_result.get("verdict", "unknown")
                is_real_bac = ai_result.get("is_real_bac", False)
                confidence  = ai_result.get("confidence", 0)
                reason      = ai_result.get("reason", "")
                ct_detected = ai_result.get("content_type_detected", "unknown")

                if is_real_bac and confidence >= MIN_CONFIDENCE:
                    console.print(
                        f"  [bold red]  🎯 AI-confirmed {bypass_type} bypass: {test_url}[/bold red]\n"
                        f"  [red]     {verdict}: {ai_result.get('what_i_see', '')}[/red]"
                    )
                    return ai_result
                else:
                    console.print(
                        f"  [dim yellow]  ✗ {bypass_type} skip: {test_url} — "
                        f"{verdict} ({ct_detected}) | {reason[:60]}[/dim yellow]"
                    )
                    return None

            # ── 2. Path variants ──────────────────────────────────────
            for variant_fn in self.PATH_VARIANTS:
                try:
                    test_url = variant_fn(url)
                except Exception:
                    continue
                r = self.client.get(test_url)
                if is_potential_bypass(r):
                    ai_result = ai_verify_bypass(r, test_url, "path")
                    if ai_result:
                        suffix = test_url[len(url):]
                        findings.append(self._make_finding(
                            f"403 Bypass (path variant '{suffix}'): {path}",
                            test_url, path, f"suffix='{suffix}'",
                            f"curl -v '{test_url}'", r["body"][:300], depth,
                            ai_result=ai_result))

            # ── 3. Header variants ────────────────────────────────────
            for hdrs in self.HEADER_VARIANTS:
                h = {k: (path if v == "PLACEHOLDER" else v) for k,v in hdrs.items()}
                r = self.client._request(url, "GET", headers=h)
                if is_potential_bypass(r):
                    hname = list(h.keys())[0]
                    ai_result = ai_verify_bypass(r, url, f"header_{hname}")
                    if ai_result:
                        findings.append(self._make_finding(
                            f"403 Bypass (header {hname}): {path}",
                            url, path, f"{hname}: {list(h.values())[0]}",
                            f"curl -H '{hname}: {list(h.values())[0]}' '{url}'",
                            r["body"][:300], depth, ai_result=ai_result))

            # ── 4. Method override ────────────────────────────────────
            for method in ("POST","PUT","PATCH","OPTIONS","HEAD"):
                r = self.client._request(url, method)
                if is_potential_bypass(r):
                    ai_result = ai_verify_bypass(r, url, f"method_{method}")
                    if ai_result:
                        findings.append(self._make_finding(
                            f"403 Bypass (method {method}): {path}",
                            url, path, f"HTTP Method: {method}",
                            f"curl -X {method} '{url}'",
                            r["body"][:300], depth, ai_result=ai_result))

            # ── 5. RECURSIVE inner fuzz ─────────────────────────────
            # 403 children are also added to queue
            if depth < max_depth and not is_file_like_path and shutil.which("ffuf"):
                ctx = {"url":url,"param":"dir_fuzz","tech":"dirs","param_type":"dirs","server":""}
                wordlist = self.wl_selector.select("dirs", ctx)
                if wordlist and Path(wordlist).exists():
                    out_file = str(Path(tempfile.gettempdir()) / f"403inner_{hashlib.md5(url.encode()).hexdigest()[:8]}.json")
                    console.print(f"  [dim]  ↳ inner ffuf: {url}/FUZZ[/dim]")
                    try:
                        subprocess.run(
                            f"ffuf -u '{url}/FUZZ' -w '{wordlist}' "
                            f"-t 60 -timeout 8 -maxtime 45 -mc 200,201,301,302,403 "
                            f"-o '{out_file}' -of json -s",
                            shell=True, capture_output=True, timeout=60)
                    except subprocess.TimeoutExpired:
                        console.print(f"  [dim yellow]  ↳ inner ffuf timeout: {url}/FUZZ[/dim yellow]")

                    try:
                        data = json.loads(Path(out_file).read_text())
                        for item in data.get("results",[]):
                            child_url    = item.get("url","")
                            child_status = item.get("status",0)
                            if not child_url: continue

                            if child_status in (200, 201):
                                # AI checks every 200 child
                                child_resp = self.client.get(child_url)
                                if child_resp["status"] in (200, 201) and child_resp["body"]:
                                    ai_result = ai_verify_bypass(child_resp, child_url, "inner_ffuf")
                                    if ai_result:
                                        findings.append(self._make_finding(
                                            f"Forbidden parent, accessible child: {child_url}",
                                            child_url, child_url, child_url,
                                            f"curl -v '{child_url}'",
                                            child_resp["body"][:300], depth,
                                            ai_result=ai_result))

                            elif child_status == 403 and child_url not in self._visited:
                                # RECURSIVE — 403 child also added to queue!
                                bfs_queue.append((child_url, depth + 1))
                                console.print(f"  [dim]  ↳ 403 child queued (depth {depth+1}): {child_url}[/dim]")

                    except Exception:
                        pass

        return findings

    def _make_finding(self, title, url, path, payload, exploit, resp, depth,
                      ai_result: dict = None) -> Finding:
        """
        Creates a Finding. If AI result exists — evidence and confidence
        are taken from AI. confirmed is True only if AI confirmed.
        """
        ai_reason   = ""
        ai_what     = ""
        ai_evidence = ""
        confidence  = 75  # default — low until AI confirms
        confirmed   = False

        if ai_result:
            ai_reason   = ai_result.get("reason", "")
            ai_what     = ai_result.get("what_i_see", "")
            ai_evidence = ai_result.get("evidence", "")
            confidence  = ai_result.get("confidence", 75)
            confirmed   = ai_result.get("is_real_bac", False) and confidence >= 70
            sensitive   = ai_result.get("sensitive_data_found", "")

        evidence_text = (
            f"HTTP 403 → 200 bypass at depth {depth}. Path: {path}. "
            f"AI verdict: {ai_result.get('verdict', 'unknown') if ai_result else 'not_verified'}. "
            f"AI sees: {ai_what[:150]}. "
            f"AI reason: {ai_reason[:150]}"
        )

        return Finding(
            owasp_id="A01", owasp_name="Broken Access Control",
            title=title, risk="High", confidence=confidence,
            url=url, method="GET", param="URL/Header",
            payload=payload[:200],
            evidence=evidence_text,
            baseline_diff="403→200",
            tool_output=resp[:2000] if resp else "",
            request_raw=f"GET {url}",
            response_raw=resp[:2000] if resp else "",
            exploit_cmd=exploit,
            remediation="Enforce authorization at application layer for ALL child paths recursively.",
            confirmed=confirmed, tool="recursive_403",
        )

class FPFilter:
    def __init__(self, ai: AIEngine, client: HTTPClient):
        self.ai     = ai
        self.client = client

    def filter(self, findings: list[Finding]) -> list[Finding]:
        # Step 0: Deduplication — merge duplicate findings
        findings = self._deduplicate(findings)

        passed = []
        for f in findings:
            is_bac_finding = (
                f.owasp_id == "A01" and
                ("403" in f.title or "bypass" in f.title.lower() or
                 "acl" in f.title.lower() or "forbidden" in f.title.lower())
            )

            # AI-confirmed 403 bypass findings — do NOT pass through FP filter
            # Because 403 bypass AI sees the full response body,
            # while FP filter only sees 500 chars and makes mistakes
            if is_bac_finding and f.confirmed and f.tool in ("acl_bypass", "recursive_403"):
                if "real_bac" in (f.evidence or "").lower():
                    console.print(
                        f"  [green]  BAC confirmed (AI pre-verified): {f.title}[/green]"
                    )
                    passed.append(f)
                    continue

            if f.confirmed and not is_bac_finding:
                # Non-BAC confirmed findings — pass through directly
                passed.append(f)
                continue

            if self._quick_fp(f):
                f.fp_filtered = True
                if not f.suppression_reason:
                    f.suppression_reason = "Quick filter: no reproducible diff or response looks like generic blocking."
                continue

            fp_result = self.ai.fp_filter(f)
            if fp_result.get("is_fp"):
                f.fp_filtered = True
                f.confirmed   = False  # AI FP desa confirmed ham bekor
                f.suppression_reason = fp_result.get("reason", "") or "AI FP filter marked this as false positive."
                console.print(
                    f"  [dim yellow]  FP removed: {f.title}[/dim yellow]"
                )
                console.print(
                    f"  [dim]    Reason: {f.suppression_reason}[/dim]"
                )
                if fp_result.get("adjusted_confidence"):
                    console.print(
                        f"  [dim]    Confidence: {f.confidence}% → {fp_result['adjusted_confidence']}%[/dim]"
                    )
                continue

            f.confidence = int(fp_result.get("adjusted_confidence", f.confidence))
            if f.confidence < MIN_CONFIDENCE:
                f.fp_filtered = True
                f.confirmed   = False
                f.suppression_reason = f"Confidence dropped below threshold after FP filter: {f.confidence}% < {MIN_CONFIDENCE}%."
                continue

            if f.risk in ("Critical", "High", "Medium") and not f.confirmed:
                if self._auto_confirm_by_evidence(f):
                    f.confirmed = True
                    passed.append(f)
                    continue
                verify = self.ai.verify_finding(f, self.client)
                f.confirmed = verify.get("confirmed", False)
                if verify.get("evidence"):
                    f.evidence += f" | VERIFIED: {verify['evidence'][:100]}"
            passed.append(f)
        return passed

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Merges findings with the same title+url+param combination.
        Keeps the one with highest confidence."""
        seen: dict[str, Finding] = {}
        for f in findings:
            key = f"{f.title}|{f.url}|{f.param}"
            if key in seen:
                if f.confidence > seen[key].confidence:
                    seen[key] = f
                elif f.confirmed and not seen[key].confirmed:
                    seen[key] = f
            else:
                seen[key] = f
        deduped = list(seen.values())
        removed = len(findings) - len(deduped)
        if removed:
            console.print(f"  [dim]  Dedup: {removed} duplicate findings removed, {len(deduped)} unique[/dim]")
        return deduped

    def _quick_fp(self, f: Finding) -> bool:
        has_supporting_signal = bool((f.evidence or "").strip() or (f.tool_output or "").strip())
        if (f.baseline_diff == "{}" or not f.baseline_diff) and not has_supporting_signal:
            return True
        ev = (f.evidence or "").lower()
        title = (f.title or "").lower()
        out = (f.tool_output or "").lower()
        # Contradiction guard: vulnerability claim but verification says login redirect.
        if "verified:" in ev and any(
            s in ev for s in [
                "redirect to /login",
                "redirected to /login",
                "properly redirects to login",
                "response is html redirect to /login",
                "received: '<!doctype html>",
            ]
        ):
            if not f.suppression_reason:
                f.suppression_reason = "Verification indicates login redirect/expected auth behavior."
            return True
        body = f.response_raw.lower()
        fp_keywords = ["access denied", "blocked by", "firewall", "captcha", "bot protection"]
        if any(k in body for k in fp_keywords) and f.confidence < 70:
            if not f.suppression_reason:
                f.suppression_reason = "Response body matches generic blocking page."
            return True
        if self._looks_like_generic_sqli_fp(f, title, ev, out, body):
            if not f.suppression_reason:
                f.suppression_reason = "SQLi suppressed: only generic error/status change without database-specific proof."
            return True
        if self._looks_like_input_validation_fp(f, title, ev, out, body):
            if not f.suppression_reason:
                f.suppression_reason = "Injection suppressed: payload only triggered input validation/type-conversion failure."
            return True
        if self._looks_like_generic_lfi_fp(f, title, ev, out, body):
            if not f.suppression_reason:
                f.suppression_reason = "LFI suppressed: file names referenced but no actual file content disclosure proven."
            return True
        return False

    def _looks_like_generic_sqli_fp(self, f: Finding, title: str, ev: str, out: str, body: str) -> bool:
        if "sql" not in title and "sql injection" not in ev and f.tool != "sqlmap":
            return False

        combined = "\n".join([title, ev, out, body])
        strong_markers = [
            "sql syntax", "mysql", "mariadb", "postgres", "postgresql", "sqlite",
            "oracle", "odbc", "sql server", "unterminated quoted string",
            "boolean-based blind", "time-based blind", "union select", "back-end dbms",
            "is vulnerable", "parameter '", "payload:",
        ]
        if any(marker in combined for marker in strong_markers):
            return False

        generic_only = any(marker in combined for marker in [
            "status=500", "status 500", "fuzzed: 500", "size diff", "internal server error", "traceback",
        ])
        return generic_only or f.tool in ("auth_sqli_probe", "sqlmap")

    def _looks_like_input_validation_fp(self, f: Finding, title: str, ev: str, out: str, body: str) -> bool:
        combined = "\n".join([title, ev, out, body])
        if "injection" not in title and f.owasp_id != "A03":
            return False
        validation_markers = [
            "invalid literal for int", "could not convert string to float", "valueerror",
            "invalid literal", "traceback", "typeerror",
        ]
        if not any(marker in combined for marker in validation_markers):
            return False
        strong_exec_markers = [
            "uid=", "gid=", "root:x:0:0:", "daemon:x:", "sql syntax", "mysql", "postgres", "sqlite",
        ]
        return not any(marker in combined for marker in strong_exec_markers)

    def _looks_like_generic_lfi_fp(self, f: Finding, title: str, ev: str, out: str, body: str) -> bool:
        if "lfi" not in title and "file inclusion" not in title and "passwd" not in ev:
            return False

        combined = "\n".join([title, ev, out, body])
        strong_content_markers = [
            "root:x:0:0:", "daemon:x:", "/bin/bash", "/usr/sbin/nologin",
            "[extensions]", "for 16-bit app support", "localhost", "127.0.0.1",
            "::1", "mail", "www-data", "nobody:x:",
        ]
        if any(marker in combined for marker in strong_content_markers):
            return False

        weak_name_markers = ["/etc/passwd", "/etc/shadow", "win.ini", ".htpasswd", "/etc/hosts"]
        return any(marker in combined for marker in weak_name_markers)

    def _auto_confirm_by_evidence(self, f: Finding) -> bool:
        ev = (f.evidence or "").lower()
        out = (f.tool_output or "").lower()

        # Explicit negative/redirect evidence should not be auto-confirmed.
        if any(s in ev for s in ["redirect to /login", "redirected to /login", "properly redirects to login"]):
            return False

        # High-confidence signals from tools.
        if f.tool in ("oob_interactsh", "recursive_403", "acl_bypass") and f.confidence >= 80:
            return True
        if f.tool == "nuclei" and f.risk in ("Critical", "High") and f.confidence >= 85:
            return True
        if f.tool in ("xxe_probe", "stored_xss", "second_order_sqli", "deser_probe") and f.confidence >= 75:
            return True

        # SQLmap direct evidence patterns.
        if f.tool == "sqlmap" and any(s in out for s in [
            "sql injection", "is vulnerable", "parameter", "payload",
            "back-end dbms", "boolean-based blind", "time-based blind",
        ]):
            return True

        return False

class Correlator:
    def __init__(self, ai: AIEngine):
        self.ai = ai

    def correlate(self, findings: list[Finding], signals: list[dict]) -> list[Finding]:
        if not signals:
            return findings
        new_findings = []

        # 1. Per-URL signal grouping
        by_url = collections.defaultdict(list)
        for s in signals:
            by_url[s.get("url","")].append(s)
        for url, url_signals in by_url.items():
            if len(url_signals) >= 2:
                correlated = self.ai.correlate(url_signals)
                for c in correlated:
                    if c.get("confidence", 0) >= MIN_CONFIDENCE:
                        new_findings.append(Finding(
                            owasp_id   = c.get("owasp_id", "A05"),
                            owasp_name = c.get("owasp_name", "Correlated Finding"),
                            title      = c.get("title", "Correlated weakness"),
                            risk       = c.get("risk", "Medium"),
                            confidence = c.get("confidence", 50),
                            url=url, method="", param="multiple",
                            payload="multiple signals",
                            evidence   = c.get("evidence", ""),
                            baseline_diff="", tool_output="",
                            request_raw="", response_raw="",
                            exploit_cmd="", remediation="",
                        ))

        # 2. Cross-URL correlation — same vulnerability across different endpoints
        self._cross_url_correlate(findings, new_findings, signals)

        # 3. Attack chain detection — findings orasida zanjir tuzish
        self._detect_attack_chains(findings, new_findings)

        return findings + new_findings

    def _cross_url_correlate(self, findings: list[Finding],
                              new_findings: list[Finding],
                              signals: list[dict]):
        """Compare signals across different URLs."""
        # If the same parameter is sensitive across different endpoints
        by_param = collections.defaultdict(list)
        for s in signals:
            param = s.get("param", "")
            if param:
                by_param[param].append(s)

        for param, param_signals in by_param.items():
            urls = list({s.get("url","") for s in param_signals})
            if len(urls) >= 2:
                # Same param — different URLs — pattern
                owasp_types = {s.get("owasp_id","") for s in param_signals
                               if s.get("owasp_id")}
                summary = f"Parameter '{param}' vulnerable across {len(urls)} endpoints"
                new_findings.append(Finding(
                    owasp_id="A04",
                    owasp_name="Insecure Design",
                    title=f"Cross-URL Vulnerability Pattern: param '{param}' ({', '.join(owasp_types)})",
                    risk="High", confidence=70,
                    url=urls[0], method="", param=param,
                    payload="multiple endpoints",
                    evidence=f"{summary}: {', '.join(u[-40:] for u in urls[:5])}",
                    baseline_diff="cross_url_pattern",
                    tool_output="", request_raw="", response_raw="",
                    exploit_cmd="", remediation="Apply consistent input validation across all endpoints.",
                ))

    def _detect_attack_chains(self, findings: list[Finding],
                               new_findings: list[Finding]):
        """Detect exploit chains between vulnerabilities."""
        # Group findings by OWASP
        by_owasp = collections.defaultdict(list)
        for f in findings:
            if not f.fp_filtered:
                by_owasp[f.owasp_id].append(f)

        # Known attack chain patterns
        chains = [
            (["A01", "A03"], "BAC + Injection → Potential full system compromise"),
            (["A01", "A07"], "BAC + Auth failure → Account takeover chain"),
            (["A10", "A03"], "SSRF + Injection → Internal network pivot"),
            (["A02", "A01"], "Crypto failure + BAC → Token forgery → Admin access"),
            (["A05", "A03"], "Misconfiguration + Injection → Debug/admin RCE"),
        ]

        for chain_ids, chain_desc in chains:
            chain_findings = []
            for cid in chain_ids:
                if cid in by_owasp:
                    chain_findings.extend(by_owasp[cid][:2])
            if len(chain_findings) >= len(chain_ids):
                chain_urls = [f.url for f in chain_findings[:3]]
                chain_titles = [f.title[:40] for f in chain_findings[:3]]
                new_findings.append(Finding(
                    owasp_id="A04",
                    owasp_name="Insecure Design",
                    title=f"Attack Chain: {chain_desc}",
                    risk="Critical", confidence=75,
                    url=chain_urls[0], method="", param="chain",
                    payload=" → ".join(chain_ids),
                    evidence=f"Chain: {' → '.join(chain_titles)}",
                    baseline_diff="attack_chain",
                    tool_output="", request_raw="", response_raw="",
                    exploit_cmd="# Multi-step exploitation chain detected",
                    remediation="Address each vulnerability in the chain. Defense-in-depth.",
                ))

__all__ = ['AIEngine', 'Recursive403Bypasser', 'FPFilter', 'Correlator']
