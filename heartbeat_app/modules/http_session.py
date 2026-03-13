from .base import *

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
        Detects technology stack from response.
        This info is used for AI wordlist selection.
        """
        tech = {"lang": "unknown", "server": "unknown", "framework": "unknown", "cms": "unknown"}
        headers = resp.get("headers", {})
        body    = resp.get("body", "")[:3000]

        # Server header
        server = headers.get("server", headers.get("Server", ""))
        tech["server"] = server[:40] if server else "unknown"

        # Programming language — from headers
        powered_by = headers.get("x-powered-by", headers.get("X-Powered-By", ""))
        if "PHP" in powered_by:
            tech["lang"] = "php"
        elif "ASP.NET" in powered_by:
            tech["lang"] = "aspnet"
        elif "Express" in powered_by or "Node" in powered_by:
            tech["lang"] = "nodejs"

        # Detect from body
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

        # Detect from Server header
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
        # Store site technology (for wordlist selection)
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

        # Fetch root page for technology detection
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

            # Tech detection — update from each response
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
                # custom_404_branded: SPA/Flask sites return login
                # page with 200 for 404 URLs — this is NOT BAC, it's a soft-404.
                # NOT added to auth_wall_pages — BAC probe cancelled.
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

    def _ai_check_403_child(self, parent_path: str, child_url: str, resp: dict) -> bool:
        """
        When 403→200 is found, shows AI the response.
        AI identifies static files (CSS/JS/image), login pages, error pages.
        Returns True only for real BAC and adds to acl_bypass_findings.
        """
        ai_result = self.ai.analyze_403_response(
            parent_url=parent_path,
            child_url=child_url,
            child_status=resp["status"],
            child_body=resp["body"],
            child_headers=resp.get("headers", {}),
            context="forbidden_child_probe",
        )

        verdict     = ai_result.get("verdict", "unknown")
        is_real_bac = ai_result.get("is_real_bac", False)
        confidence  = ai_result.get("confidence", 0)
        what_i_see  = ai_result.get("what_i_see", "")
        reason      = ai_result.get("reason", "")
        ct_detected = ai_result.get("content_type_detected", "unknown")

        if is_real_bac and confidence >= MIN_CONFIDENCE:
            console.print(
                f"  [bold red]🚨 AI-confirmed BAC: {child_url}[/bold red]\n"
                f"  [red]     Verdict: {verdict} | {what_i_see}[/red]\n"
                f"  [red]     Reason:  {reason}[/red]"
            )
            self.acl_bypass_findings.append({
                "parent_403":   parent_path,
                "child_200":    child_url,
                "body_size":    len(resp["body"]),
                "body_snippet": resp["body"][:400],
                "ai_reason":    reason,
                "confidence":   confidence,
                "ai_verdict":   verdict,
                "ai_what":      what_i_see,
            })
            return True
        else:
            console.print(
                f"  [dim yellow]  ✗ NOT BAC: {child_url} — "
                f"{verdict} ({ct_detected}) | {reason[:80]}[/dim yellow]"
            )
            return False

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
            parent_path = base + fpath
            for suffix in suffixes:
                url = parent_path + suffix
                if url in self.visited:
                    continue
                r = self.client.get(url)
                with self._lock:
                    self.visited.add(url)
                if r["status"] in (200, 201, 202):
                    # AI checks each 403→200 response
                    is_real = self._ai_check_403_child(parent_path, url, r)
                    if is_real:
                        ep = self._url_to_endpoint(url, "GET", 0, "forbidden_child")
                        ep.score = 90
                        with self._lock:
                            self.endpoints.append(ep)
                        # Nested scan only for real BAC
                        for nsuffix in nested_suffixes:
                            nurl = url.rstrip("/") + nsuffix
                            if nurl in self.visited:
                                continue
                            nr = self.client.get(nurl)
                            with self._lock:
                                self.visited.add(nurl)
                            if nr["status"] in (200, 201, 202):
                                nis_real = self._ai_check_403_child(parent_path, nurl, nr)
                                if nis_real:
                                    nep = self._url_to_endpoint(nurl, "GET", 0, "forbidden_child_deep")
                                    nep.score = 95
                                    with self._lock:
                                        self.endpoints.append(nep)
                    else:
                        # Even static files added as endpoints
                        # (but NOT BAC findings)
                        ep = self._url_to_endpoint(url, "GET", 0, "forbidden_child_static")
                        ep.score = 5  # low priority
                        with self._lock:
                            self.endpoints.append(ep)
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
            except Exception as exc:
                console.print(f"  [dim red]Crawl worker error: {str(exc)[:80]}[/dim red]")
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

class BaselineEngine:
    def __init__(self, client: HTTPClient):
        self.client        = client
        self._cache        : dict[str, BaselineFingerprint] = {}
        self._custom404_fp : Optional[BaselineFingerprint]  = None
        self._rate_limit_delay : float = 0.2  # adaptive delay
        self._consecutive_429  : int   = 0
        self._waf_detected     : bool  = False

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
        Generates a Smart Fuzz Profile by probing 5 different random URLs.

        Process:
        1. Sends 5 DIFFERENT random paths (each with unique suffix)
        2. Collects results: status, size, words, lines, title, hash
        3. AI analyzes — determines which parameters form the "404 signature"
        4. Tolerance is calculated (±% difference)
        5. Returns SmartFuzzProfile — ready arguments for ffuf/gobuster/wfuzz

        This function is called both BEFORE well_known probing AND whenever
        a new directory is found (for recursive fuzzing).
        """
        import random, string

        base = base_url.rstrip("/")
        probes = []

        # 5 different random paths — each with unique pattern
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

        # If AI doesn't respond — heuristic fallback
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
        """Heuristic filter based on probe results when AI is unavailable."""
        statuses = [p["status"] for p in probes]
        sizes    = [p["size"]   for p in probes]
        words    = [p["words"]  for p in probes]
        lines    = [p["lines"]  for p in probes]
        hashes   = [p["hash"]   for p in probes]

        filter_codes, filter_sizes, filter_words, filter_lines = [], [], [], []

        # All same status → filter
        if len(set(statuses)) == 1:
            filter_codes = list(set(statuses))

        # Sizes similar (±5% tolerance) → filter
        if sizes:
            avg_size   = sum(sizes) / len(sizes)
            max_dev    = max(abs(s - avg_size) for s in sizes)
            rel_dev    = max_dev / max(avg_size, 1)
            if rel_dev < 0.05:  # less than 5% difference
                # Add all unique sizes to filter
                filter_sizes = list(set(sizes))
            elif rel_dev < 0.15:  # up to 15% — filter by word count
                if len(set(words)) <= 2:
                    filter_words = list(set(words))

        # All hashes identical → definite custom 404
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
            time.sleep(self._rate_limit_delay)
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
            r = self.client.get(ep.url)
        else:
            r = self.client.post(ep.url, data=ep.params)

        # 429 rate-limit adaptive handling
        if r.get("status") == 429:
            self._consecutive_429 += 1
            retry_after = 1.0
            # Respect Retry-After header
            ra_header = r.get("headers", {}).get("retry-after", "")
            if ra_header:
                try:
                    retry_after = max(float(ra_header), 0.5)
                except (ValueError, TypeError):
                    pass
            # Exponential backoff: 1s, 2s, 4s, max 10s
            delay = min(retry_after * (2 ** (self._consecutive_429 - 1)), 10.0)
            self._rate_limit_delay = max(self._rate_limit_delay, delay)
            console.print(f"  [dim yellow]  429 Rate Limited — waiting {delay:.1f}s[/dim yellow]")
            time.sleep(delay)
            # Retry once after backoff
            if ep.method == "GET":
                r = self.client.get(ep.url)
            else:
                r = self.client.post(ep.url, data=ep.params)
        else:
            self._consecutive_429 = 0

        # WAF detection in response
        body_lower = r.get("body", "").lower()[:500]
        waf_signals = ["blocked by", "web application firewall", "cloudflare",
                       "access denied", "403 forbidden", "captcha",
                       "rate limit exceeded", "too many requests"]
        if r.get("status") in (403, 406, 429, 503) and \
           any(s in body_lower for s in waf_signals):
            if not self._waf_detected:
                self._waf_detected = True
                self._rate_limit_delay = max(self._rate_limit_delay, 1.0)
                console.print("  [bold yellow]⚠ WAF/Rate-limiter detected in baseline — slowing down[/bold yellow]")

        return r

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

__all__ = ['HTTPClient', 'RiskScorer', 'RoleContext', 'SessionManager', 'Crawler', 'ParamDiscoverer', 'BaselineEngine', 'EndpointGraph']
