from .base import *
from .route_analyzer import RouteAnalyzer # <-- YANGI IMPORT
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import json
import time

_run_cmd = globals().get("_run_cmd")

@dataclass
class ScanContext:
    """Holds the entire state of the current pentest scan."""
    target: str
    endpoints: list # Barcha topilgan endpointlar
    findings: list  # Barcha topilgan zaifliklar
    route_families: dict = field(default_factory=dict) # <-- YANGI MAYDON
    # ... boshqa maydonlar ...

class AIEngine:
    """
    The strategic core of the AI Pentester. It analyzes the current state
    of the scan and decides the next best action.
    """
    def __init__(self):
        self.route_analyzer = RouteAnalyzer() # <-- ANALIZATORNI ISHGA TUSHIRISH
        self._cache: dict[str, Any] = {}

    def update_route_families(self, context: ScanContext):
        """Analyzes all endpoints and updates the route families in the context."""
        all_urls = [ep.get('url') for ep in context.endpoints]
        context.route_families = self.route_analyzer.cluster_urls(all_urls)
        console.print(f"  [cyan]Route families identified:[/cyan] {len(context.route_families)}")

    def decide_next_action(self, context: "ScanContext") -> Dict:
        """
        Analyzes all discovered data and determines the most logical next step.
        This is the central decision-making function.
        """
        # 1. Birinchi navbatda, yo'nalishlar oilasini yangilab olamiz
        self.update_route_families(context)

        # 2. Har bir oiladan namuna olib, uni tahlil qilish
        for family, urls in context.route_families.items():
            if len(urls) > 5: # Agar oilada 5 dan ortiq URL bo'lsa
                # Bu oilani "shovqinli" deb taxmin qilish va tekshirish
                # ... (bu yerda namunani tahlil qilish logikasi bo'ladi) ...
                
                # Agar tahlil natijasi "past qiymatli" bo'lsa:
                is_low_value = True # (bu qiymat analizdan keladi)
                if is_low_value:
                    return {
                        "action": "DEPRIORITIZE_FAMILY",
                        "route_family": family,
                        "reason": f"Dynamic analysis of {len(urls)} URLs shows repetitive content."
                    }

        # 3. Agar shovqinli oila topilmasa, eng yuqori prioritetli endpointni tanlash
        # ... (mavjud endpointlarni prioritetlash logikasi) ...
        
        # Standart holatda, eng yuqori skorli endpointni test qilish
        highest_priority_endpoint = sorted(context.endpoints, key=lambda e: e.get('score', 0), reverse=True)[0]
        return {
            "action": "FUZZ_ENDPOINT",
            "endpoint": highest_priority_endpoint
        }

    def _call(self, prompt: str, cache: bool = True) -> Any:
        cache_key = hashlib.md5(prompt.encode("utf-8", errors="ignore")).hexdigest()
        if cache and cache_key in self._cache:
            return self._cache[cache_key]

        client = create_ollama_client()
        if client is None or not HAS_OLLAMA:
            result: Any = {}
        else:
            try:
                resp = client.chat(
                    model=MODEL_NAME,
                    messages=[
                        {"role": "system", "content": "Return compact JSON when possible."},
                        {"role": "user", "content": prompt},
                    ],
                )
                content = (resp.get("message", {}) or {}).get("content", "").strip()
                try:
                    result = json.loads(content) if content else {}
                except Exception:
                    match = re.search(r"\{.*\}|\[.*\]", content, re.S)
                    if match:
                        try:
                            result = json.loads(match.group(0))
                        except Exception:
                            result = content
                    else:
                        result = content
            except Exception:
                result = {}

        if cache:
            self._cache[cache_key] = result
        return result

    def identify_login_fields(self, body: str, login_url: str) -> Dict[str, str]:
        return {
            "username_field": "username" if 'name="username"' in body.lower() else "email" if 'name="email"' in body.lower() else "username",
            "password_field": "password",
            "csrf_field": "csrf_token",
        }

    def analyze_403_response(self, parent_url: str, child_url: str, child_status: int,
                             child_body: str, child_headers: dict, context: str = "") -> Dict[str, Any]:
        body_lower = (child_body or "").lower()
        login_signals = sum(1 for s in ("login", "sign in", "password", "username") if s in body_lower)
        is_html = "<html" in body_lower or "text/html" in str(child_headers).lower()
        looks_real = child_status in (200, 201) and len(child_body or "") > 80 and login_signals < 2 and is_html
        return {
            "verdict": "real_accessible_content" if looks_real else "not_bac",
            "is_real_bac": looks_real,
            "confidence": 80 if looks_real else 20,
            "what_i_see": "HTML content different from a login wall" if looks_real else "Login/error/static-like response",
            "reason": "Heuristic 403 child validation" if looks_real else "Heuristic rejected as non-sensitive or login-like",
            "content_type_detected": "html" if is_html else "unknown",
        }

    def analyze_page(self, url: str, status: int, body: str, headers: dict, real_200: dict) -> Dict[str, Any]:
        path = urllib.parse.urlparse(url).path.lower()
        suggested = []
        if "/admin" in path or path.endswith("/admin"):
            suggested = ["/admin/users", "/admin/settings", "/admin/config"]
        elif any(token in path for token in ("/login", "/signin", "/auth")):
            suggested = ["/dashboard", "/profile", "/account"]
        elif any(token in path for token in ("/search", "/find", "/query")):
            suggested = ["/search", "/api/search"]
        page_type = "admin" if "/admin" in path else "auth" if any(token in path for token in ("/login", "/signin", "/auth")) else "generic"
        return {
            "page_type": page_type,
            "description": f"Heuristic analysis for {page_type} page",
            "suggested_child_paths": suggested,
        }

    def verify_child_access(self, parent_url: str, child_url: str, child_status: int,
                            child_body: str, child_headers: dict, parent_signal: str = "") -> Dict[str, Any]:
        result = self.analyze_403_response(parent_url, child_url, child_status, child_body, child_headers, parent_signal)
        return {
            "verdict": result.get("verdict", "unknown"),
            "reason": result.get("reason", ""),
            "is_real_bac": result.get("is_real_bac", False),
            "confidence": result.get("confidence", 0),
        }

    def analyze_bac(self, bac: dict) -> Dict[str, Any]:
        comparisons = bac.get("comparisons", [])
        if not comparisons:
            return {"found": False}
        first = comparisons[0]
        return {
            "found": True,
            "verified": True,
            "confidence": 80,
            "owasp_id": "A01",
            "owasp_name": "Broken Access Control",
            "title": f"BAC/IDOR via role comparison: {bac.get('url', '')}",
            "risk": "High",
            "technical": json.dumps(first)[:200],
            "exploit_cmd": "",
            "remediation": "Ensure each role is validated server-side for every protected endpoint.",
        }

    def plan_endpoints(self, endpoints: List[Any]) -> List[Any]:
        return sorted(endpoints, key=lambda ep: getattr(ep, "score", 0), reverse=True)

    def classify_finding(self, context: Dict[str, Any]) -> Dict[str, Any]:
        status_changed = context.get("status_changed", False)
        size_pct = context.get("size_pct", 0) or 0
        new_errors = context.get("new_errors", []) or []
        found = bool(status_changed or size_pct >= 20 or new_errors)
        return {
            "found": found,
            "confidence": 75 if found else 20,
            "owasp_id": "A01" if "idor" in str(context.get("tool", "")).lower() else "A03",
            "owasp_name": "Broken Access Control" if "idor" in str(context.get("tool", "")).lower() else "Injection",
            "title": f"Potential finding on {context.get('url', '')}",
            "risk": "Medium",
            "evidence": context.get("tool_output", "") or json.dumps({"size_pct": size_pct, "status_changed": status_changed})[:200],
            "exploit_cmd": "",
            "remediation": "Review server-side validation and access controls.",
        }

    def analyze_fuzz_baseline(self, base_url: str, probes: List[Dict[str, Any]]) -> Dict[str, Any]:
        statuses = [p.get("status") for p in probes]
        sizes = [p.get("size") for p in probes]
        words = [p.get("words") for p in probes]
        lines = [p.get("lines") for p in probes]
        return {
            "filter_codes": list(set(statuses)) if len(set(statuses)) == 1 else [],
            "filter_sizes": list(set(sizes)) if len(set(sizes)) <= 2 else [],
            "filter_words": list(set(words)) if len(set(words)) <= 2 else [],
            "filter_lines": list(set(lines)) if len(set(lines)) <= 2 else [],
            "tolerance_bytes": 20,
            "explanation": "Heuristic baseline analysis",
            "recursive": True,
        }

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

    def __init__(self, client: "HTTPClient", ai: AIEngine, wl_selector: "AIWordlistSelector"):
        self.client      = client
        self.ai          = ai
        self.wl_selector = wl_selector
        self._visited    : Set[str] = set()

    def bypass(self, start_url: str, max_depth: int = 3) -> List["Finding"]:
        findings   : List["Finding"] = []
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
                      ai_result: dict = None) -> "Finding":
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
    def __init__(self, ai: AIEngine, client: "HTTPClient"):
        self.ai     = ai
        self.client = client

    def filter(self, findings: list["Finding"]) -> list["Finding"]:
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

    def _deduplicate(self, findings: list["Finding"]) -> list["Finding"]:
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

    def _quick_fp(self, f: "Finding") -> bool:
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

    def _looks_like_generic_sqli_fp(self, f: "Finding", title: str, ev: str, out: str, body: str) -> bool:
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

    def _looks_like_input_validation_fp(self, f: "Finding", title: str, ev: str, out: str, body: str) -> bool:
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

    def _looks_like_generic_lfi_fp(self, f: "Finding", title: str, ev: str, out: str, body: str) -> bool:
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

    def _auto_confirm_by_evidence(self, f: "Finding") -> bool:
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

    def correlate(self, findings: list["Finding"], signals: list[dict]) -> list["Finding"]:
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

    def _cross_url_correlate(self, findings: list["Finding"],
                              new_findings: list["Finding"],
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

    def _detect_attack_chains(self, findings: list["Finding"],
                               new_findings: list["Finding"]):
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
