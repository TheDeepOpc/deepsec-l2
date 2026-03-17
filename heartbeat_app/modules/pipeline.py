from .base import *
from typing import List, Dict, Optional, Any
from .wordlists import AIWordlistSelector as ModuleAIWordlistSelector
from .http_session import HTTPClient, SessionManager, Crawler, ParamDiscoverer, BaselineEngine
from .fuzzing import KaliToolRunner, OWASPFuzzEngine, NucleiRunner
from .ai import FPFilter, Correlator
from .ai_exploiter import IntelligentPayloadGenerator, MultiStageAttackChainer, WildcardWAFEvader
from .ai_risk_model import VulnerabilityPredictor, EndpointPrioritizer, BehavioralAnalyzer
from .vuln_explainer import VulnerabilityExplainer

class PentestPipeline:
    def __init__(self, args):
        self.args    = args
        self.session = SessionContext()
        self.client  = HTTPClient(self.session, timeout=DEFAULT_TIMEOUT)
        self.ai      = AIEngine()
        self.graph   = EndpointGraph()
        # Use the selector from heartbeat_app.modules.wordlists explicitly.
        # This avoids ambiguous symbol resolution from star imports.
        self.wl_selector = ModuleAIWordlistSelector(self.ai)
        # V7 MEGA — new components
        self.oob     = OOBClient()
        self.ctf     = getattr(args, "ctf", False)
        self._last_target = (getattr(args, "target", "") or "").rstrip("/")
        self._partial_findings = []
        
        # NEW: Enterprise-grade AI exploitation modules
        self.payload_gen = IntelligentPayloadGenerator(self.ai)
        self.attack_chainer = MultiStageAttackChainer(self.ai, self.client)
        self.waf_evader = WildcardWAFEvader(self.client)
        self.vuln_predictor = VulnerabilityPredictor(self.ai)
        self.endpoint_prioritizer = EndpointPrioritizer(self.ai)
        self.behavior_analyzer = BehavioralAnalyzer(self.ai)
        self.vuln_explainer = VulnerabilityExplainer(self.ai)
        self._partial_findings = []

    def run(self):
        raw_input = self.args.target.rstrip("/")

        console.print(BANNER)
        print_tools_status()
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
                console.print("  [dim yellow]  interactsh-client not found — OOB disabled[/dim yellow]")

        # Step 0: RECON — domain/IP analysis, port scan, HTTP target identification
        recon_engine = ReconEngine(self.ai)
        recon_result = recon_engine.run(raw_input)

        # Primary HTTP target tanlash
        if recon_result.http_targets:
            primary = recon_result.http_targets[0]
            target  = primary["url"].rstrip("/")
            self._last_target = target
            console.print(f"  [bold green]Primary target: {target}[/bold green]"
                          + (f"  [dim]({primary.get('ai_reason','')})[/dim]"
                             if primary.get("ai_reason") else ""))
        else:
            # Recon found nothing — use input directly
            target = raw_input
            if not target.startswith("http"):
                target = "http://" + target
            self._last_target = target
            console.print(f"  [dim yellow]  Recon found no HTTP targets — using {target}[/dim yellow]")

        # ── DOMAIN INFO ────────────────────────────────────────
        console.print(f"\n[cyan]━━ DOMAIN ANALYSIS ━━[/cyan]")
        domain_name = target.replace("http://", "").replace("https://", "").split("/")[0]
        from .domain_analyzer import get_whois_data
        domain_info = get_whois_data(domain_name)
        
        if "error" in domain_info:
            console.print(f"  [yellow]⚠ Domen ma'lumotlarini olishda xatolik: {domain_info['error']}[/yellow]")
        else:
            console.print(f"  [green]✓ Domen ma'lumotlari olingan[/green]")
            for key, value in domain_info.items():
                if isinstance(value, list):
                    console.print(f"  [dim]  {key.replace('_', ' ').title()}:[/dim]")
                    for item in value[:3]:
                        console.print(f"  [dim]    - {item}[/dim]")
                else:
                    console.print(f"  [dim]  {key.replace('_', ' ').title()}: {value}[/dim]")

        # ── SUBDOMAIN ENUMERATION ──────────────────────────────────────
        console.print(f"\n[cyan]━━ SUBDOMAIN ENUMERATION ━━[/cyan]")
        if recon_result.subdomains:
            console.print(f"  [green]✓ {len(recon_result.subdomains)} subdomainlar topilgan[/green]")
            for sub in recon_result.subdomains[:10]:
                console.print(f"  [dim]  - {sub}[/dim]")
            if len(recon_result.subdomains) > 10:
                console.print(f"  [dim]  ... va yana {len(recon_result.subdomains) - 10}[/dim]")
            
            # Subdomainlarni skanerlashga qo'shish
            for subdomain in recon_result.subdomains[:5]:  # First 5 subdomains
                sub_url = f"http://{subdomain}"
                if sub_url not in [t.get("url") for t in recon_result.http_targets]:
                    recon_result.http_targets.append({
                        "url": sub_url,
                        "port": 80,
                        "ssl": False,
                        "source": "subdomain_enum"
                    })
        else:
            console.print(f"  [dim yellow]  ⚠ Subdomainlar topilmadi[/dim yellow]")

        # WAF warning
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
            active_role = ""
            if self.args.user and self.args.password:
                if session_mgr.add_role("user", login_url, self.args.user, self.args.password):
                    self.graph.roles.append("user")
                    active_role = "user"
            if self.args.admin_user and self.args.admin_pass:
                if session_mgr.add_role("admin", login_url, self.args.admin_user, self.args.admin_pass):
                    self.graph.roles.append("admin")
                    if not active_role:
                        active_role = "admin"

            # Ensure crawler/fuzzer use authenticated session when available.
            if active_role:
                switched = False
                activate_fn = getattr(session_mgr, "activate_role", None)
                if callable(activate_fn):
                    switched = bool(activate_fn(active_role))
                else:
                    # Backward-compat fallback for older SessionManager builds.
                    role_ctx = getattr(session_mgr, "roles", {}).get(active_role)
                    role_sess = getattr(role_ctx, "session", None)
                    if role_sess is not None:
                        self.session.cookies = dict(getattr(role_sess, "cookies", {}) or {})
                        self.session.headers = dict(getattr(role_sess, "headers", {}) or {})
                        self.session.jwt_token = getattr(role_sess, "jwt_token", "") or ""
                        self.session.csrf_token = getattr(role_sess, "csrf_token", "") or ""
                        self.session.role = active_role
                        self.session.logged_in = True
                        switched = True

                if switched:
                    console.print(f"[green]✓ Active scan session switched to role '{active_role}'[/green]")
                else:
                    console.print("[yellow]⚠ Could not activate authenticated role session; continuing.[/yellow]")

        # Step 1b: OAuth/SAML/CSRF detection on login page
        oauth_saml_findings = []
        if self.args.auth_url:
            console.print(f"\n[cyan]━━ OAUTH/SAML/CSRF CHECK ━━[/cyan]")
            login_full = urllib.parse.urljoin(target + "/", self.args.auth_url.lstrip("/"))
            lr = self.client.get(login_full)
            login_body = lr.get("body", "")

            # Detect OAuth endpoints
            oauth_patterns = [
                (r'(?:href|action)\s*=\s*["\']([^"\']*(?:oauth|authorize|openid)[^"\']*)["\']', "OAuth endpoint"),
                (r'(?:href|action)\s*=\s*["\']([^"\']*(?:saml|sso|adfs)[^"\']*)["\']', "SAML/SSO endpoint"),
            ]
            for pat, name in oauth_patterns:
                for m in re.finditer(pat, login_body, re.I):
                    endpoint = m.group(1)
                    if endpoint.startswith("/"):
                        endpoint = target + endpoint
                    console.print(f"  [dim]  Found {name}: {endpoint}[/dim]")

                    # Check for state/nonce parameters
                    if "oauth" in name.lower() or "authorize" in endpoint.lower():
                        or_ = self.client.get(endpoint)
                        if or_["status"] in (200, 302):
                            redirect_url = or_.get("headers", {}).get("location", endpoint)
                            parsed_qs = urllib.parse.parse_qs(
                                urllib.parse.urlparse(redirect_url).query)
                            has_state = "state" in parsed_qs
                            has_nonce = "nonce" in parsed_qs
                            if not has_state:
                                oauth_saml_findings.append(Finding(
                                    owasp_id="A07",
                                    owasp_name="Identification and Authentication Failures",
                                    title=f"OAuth Missing State Parameter: {endpoint[:60]}",
                                    risk="High", confidence=85,
                                    url=endpoint, method="GET", param="state",
                                    payload="missing",
                                    evidence="OAuth authorization request lacks 'state' parameter — CSRF on OAuth flow possible",
                                    baseline_diff="state_missing",
                                    tool_output=redirect_url[:200],
                                    request_raw=f"GET {endpoint}",
                                    response_raw=redirect_url[:200],
                                    exploit_cmd="# Initiate OAuth flow without state to perform CSRF login",
                                    remediation="Always include and validate a cryptographic 'state' parameter in OAuth flows.",
                                    confirmed=True, tool="oauth_check",
                                ))
                                console.print(f"  [bold red]🎯 OAuth: missing state param![/bold red]")

            # CSRF token check on login form
            login_has_csrf = bool(re.search(
                r'<input[^>]+name=["\'](?:csrf|_token|csrfmiddlewaretoken|authenticity_token)["\']',
                login_body, re.I))
            if not login_has_csrf and "<form" in login_body.lower():
                oauth_saml_findings.append(Finding(
                    owasp_id="A01",
                    owasp_name="Broken Access Control",
                    title=f"Login Form Missing CSRF Token: {login_full}",
                    risk="Medium", confidence=75,
                    url=login_full, method="GET", param="csrf_token",
                    payload="missing",
                    evidence="Login form does not include CSRF token — login CSRF possible",
                    baseline_diff="csrf_missing",
                    tool_output=login_body[:300],
                    request_raw=f"GET {login_full}",
                    response_raw=login_body[:300],
                    exploit_cmd=f"# Submit login form from external site without CSRF token",
                    remediation="Add CSRF token to all forms including login.",
                    tool="csrf_check",
                ))
                console.print(f"  [yellow]⚠ Login form: no CSRF token[/yellow]")
            console.print(f"[green]✓ OAuth/SAML/CSRF: {len(oauth_saml_findings)} findings[/green]")

        # Step 2: Baseline + Smart Fuzz Profile
        console.print(f"\n[cyan]━━ FINGERPRINTING ━━[/cyan]")
        baseline     = BaselineEngine(self.client)
        baseline.build_custom_404(target)   # legacy compat
        smart_profile = baseline.build_smart_profile(target, self.ai, depth=3)

        # Step 3: Crawl (with technology detection, using SmartProfile for soft-404 filtering)
        console.print(f"\n[cyan]━━ CRAWLER ━━[/cyan]")
        crawler   = Crawler(self.client, self.ai, target)
        endpoints = crawler.crawl(max_depth=3 if self.args.deep else 2, smart_profile=smart_profile)
        site_tech = crawler.site_tech
        console.print(f"[bold]Site technology:[/bold] {site_tech}")
        for ep in endpoints:
            self.graph.add_endpoint(ep)

        # Step 4: Param discovery (with AI wordlist selector)
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
        page_candidates = sorted(enriched, key=lambda e: e.score, reverse=True)
        analyzed_count = 0
        skipped_non_200 = 0
        skipped_non_html = 0
        skipped_route_stop = 0
        forced_search_urls = set()
        route_state = {}

        def _route_key(url: str) -> str:
            path = (urllib.parse.urlparse(url).path or "/").strip()
            if not path:
                return "/"
            segs = [s for s in path.strip("/").split("/") if s]
            normalized = [":id" if re.fullmatch(r"\d+", s) else s.lower() for s in segs]
            return "/" + "/".join(normalized)

        def _extract_search_params(html: str) -> list[str]:
            names = []
            for m in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', html, re.I):
                n = (m.group(1) or "").strip()
                if not n:
                    continue
                nl = n.lower()
                if any(k in nl for k in ("q", "query", "search", "keyword", "filter")):
                    names.append(n)
            return list(dict.fromkeys(names))[:8]

        for ep in page_candidates:
            route_key = _route_key(ep.url)
            state = route_state.setdefault(route_key, {"low_value": 0, "stopped": False, "reason": ""})
            if state["stopped"]:
                skipped_route_stop += 1
                console.print(
                    f"  [dim]AI stop: {ep.url[:70]}  reason={state['reason']}[/dim]"
                )
                continue

            # Skip non-HTML file types (backups, configs, logs, etc.)
            url_path = urllib.parse.urlparse(ep.url).path.lower()
            skip_extensions = ['.bak', '.sql', '.zip', '.tar', '.gz', 
                             '.log', '.conf', '.jar', '.war', '.exe', '.apk',
                             '.backup', '.old', '.tmp']
            should_skip_file = any(url_path.endswith(ext) or f'{ext}.' in url_path for ext in skip_extensions)
            
            if should_skip_file:
                skipped_non_html += 1
                continue

            resp = self.client.get(ep.url)
            if resp.get("status") != 200:
                skipped_non_200 += 1
                continue
            content_type = (resp.get("headers", {}).get("content-type")
                            or resp.get("headers", {}).get("Content-Type", "")).lower()
            body = resp.get("body", "")
            
            # Skip non-HTML content types (images, archives, documents, APIs, etc.)
            skip_content_types = ['application/json', 'application/xml', 'text/xml',
                                'application/pdf', 'image/', 'video/', 'audio/',
                                'application/zip', 'application/x-gzip', 'application/x-tar',
                                'application/octet-stream', 'text/plain', 'text/csv']
            is_non_html_content = any(ct in content_type for ct in skip_content_types)
            
            # Check if body looks like HTML
            is_html_body = "<html" in body[:500].lower() or "<body" in body[:500].lower()
            
            if is_non_html_content or (not is_html_body and "html" not in content_type):
                skipped_non_html += 1
                continue

            analysis = self.ai.analyze_page(
                ep.url,
                resp["status"],
                body[:4000],
                resp.get("headers", {}),
                baseline.is_real_200(resp),
            )
            analyzed_count += 1

            # If page analysis points to risky page types, increase test priority.
            if analysis.get("risk") in ("Critical", "High"):
                ep.score += 25

            # Search-like inputs should always be tested, regardless of planner order.
            search_inputs = _extract_search_params(body)
            if any(x in ep.url.lower() for x in ("search", "query", "find")) and not search_inputs:
                search_inputs = ["query"]
            for inp in search_inputs:
                key = f"query:{inp}"
                if key not in ep.params:
                    ep.params[key] = "test"
            if search_inputs:
                forced_search_urls.add(f"{ep.method}:{ep.url}")
                ep.score += 35

            page_type = analysis.get("page_type", "unknown")
            is_numeric_leaf = bool(re.search(r"/\d+/?$", urllib.parse.urlparse(ep.url).path or ""))
            low_value_page = (
                analysis.get("risk", "Info") in ("Info", "Low")
                and page_type in ("static", "dashboard", "unknown")
                and len(search_inputs) <= 1
                and is_numeric_leaf
            )
            if low_value_page:
                state["low_value"] += 1
                if state["low_value"] >= 3 and not state["stopped"]:
                    state["stopped"] = True
                    state["reason"] = "repetitive numeric-content pages; oddiy yangilik/deep content deb to'xtatildi"
                    console.print(
                        f"  [dim yellow]AI route-stop: {route_key} — {state['reason']}[/dim yellow]"
                    )

            console.print(
                f"  [dim]AI page: {ep.url[:70]}  type={page_type} "
                f"risk={analysis.get('risk','Info')} search_inputs={len(search_inputs)}[/dim]"
            )

            extra_children = analysis.get("suggested_child_paths", []) or []
            for child in extra_children[:10]:
                if not str(child).startswith("/"):
                    continue
                # Root-relative child paths must always resolve from target root,
                # not from the current page path (prevents /login/transfer style artifacts).
                child_url = urllib.parse.urljoin(target.rstrip("/") + '/', child.lstrip('/'))
                if not child_url.startswith(target):
                    continue
                if child_url in crawler.visited:
                    continue
                crawler.visited.add(child_url)
                enriched.append(crawler._url_to_endpoint(child_url, "GET", ep.depth + 1, "ai_page_analysis"))

        console.print(
            f"[green]✓ Page analysis: analyzed {analyzed_count} HTML pages, "
            f"skipped_non_200={skipped_non_200}, skipped_non_html={skipped_non_html}, "
            f"skipped_route_stop={skipped_route_stop}[/green]"
        )

        for aw in crawler.auth_wall_pages:
            # custom_404_branded — SPA site's soft-404 page,
            # not for BAC checking, skip it
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
                child_url = urllib.parse.urljoin(self.args.target.rstrip("/") + '/', child.lstrip('/'))
                if child_url in crawler.visited:
                    continue

                # 1. Send request without following redirect
                #    (allow_redirects=False equivalent — manual HEAD)
                cr = self.client.get(child_url)
                crawler.visited.add(child_url)

                raw_status  = cr["status"]
                body        = cr["body"]
                final_url   = cr.get("url", child_url)
                body_lower  = body.lower()[:800]

                # 2. Check redirect to login
                redirected_to_login = (
                    final_url != child_url and
                    any(x in final_url.lower() for x in ["/login", "/signin", "/auth", "/account"])
                )
                # Body login page indicators
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

                # 3. Show response to AI — real content or login redirect?
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

        for ep in page_candidates:
            if ep.score < 0:
                ep.score = 0

        # Step 5b: ACL bypass findings — only AI-confirmed bypasses
        acl_findings = []
        for bypass in crawler.acl_bypass_findings:
            ai_reason  = bypass.get("ai_reason", "")
            confidence = bypass.get("confidence", 75)
            ai_verdict = bypass.get("ai_verdict", "unknown")
            ai_what    = bypass.get("ai_what", "")

            # If AI confirmed — confidence and ai_reason will exist
            # If AI not confirmed (old format) — confidence 85 default, but
            # confirmed=False is set — FPFilter will check it
            has_ai_confirmation = bool(ai_reason and confidence >= MIN_CONFIDENCE)

            evidence   = (
                f"Parent {bypass['parent_403']} restricted, "
                f"child {bypass['child_200']} accessible ({bypass['body_size']} bytes). "
                f"AI verdict: {ai_verdict}. "
                f"AI sees: {ai_what[:150]}. "
                f"AI reason: {ai_reason}"
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
                confirmed=has_ai_confirmation,
                tool="acl_bypass",
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
                    if (
                        ai_bac
                        and ai_bac.get("found")
                        and ai_bac.get("verified", False)
                        and ai_bac.get("confidence", 0) >= MIN_CONFIDENCE
                    ):
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

        # Force-test search endpoints before generic planner order.
        forced_eps = [ep for ep in enriched if f"{ep.method}:{ep.url}" in forced_search_urls]
        if forced_eps:
            seen = set()
            ordered = []
            for ep in forced_eps + planned:
                key = (ep.method, ep.url)
                if key in seen:
                    continue
                seen.add(key)
                ordered.append(ep)
            planned = ordered
            console.print(f"[green]✓ Forced AI search/input tests: {len(forced_eps)} endpoint(s)[/green]")

        # Drop low-value synthetic/nested auth endpoints before fuzzing.
        def _should_prune_low_value(ep: "Endpoint") -> bool:
            try:
                path = urllib.parse.urlparse(ep.url).path.lower().strip("/")
            except Exception:
                return False
            if not path:
                return False
            segs = [s for s in path.split("/") if s]
            if ep.score > 0:
                return False
            auth_tokens = {"login", "logout", "signin", "signout", "logoff", "register", "forgot-password"}
            if len(segs) >= 2 and segs[0] in auth_tokens:
                return True
            if len(segs) >= 2 and any(s in auth_tokens for s in segs[1:]):
                return True
            if len(segs) >= 3:
                return True
            return False

        def _planner_route_key(ep: "Endpoint") -> str:
            parsed = urllib.parse.urlparse(ep.url)
            segs = [s for s in (parsed.path or "/").strip("/").split("/") if s]
            norm_segs = []
            for seg in segs:
                if re.fullmatch(r"\d+", seg):
                    norm_segs.append(":id")
                else:
                    norm_segs.append(seg.lower())
            query_names = sorted(urllib.parse.parse_qs(parsed.query).keys())
            query_part = "?" + "&".join(query_names) if query_names else ""
            return f"{ep.method.upper()}:/{'/'.join(norm_segs)}{query_part}"

        def _planner_route_cap(ep: "Endpoint", route_key: str) -> int:
            path = (urllib.parse.urlparse(ep.url).path or "").lower()
            if any(token in path for token in ("/search", "/query", "/find")):
                return 2
            if "/lists/view/" in path and re.search(r"/\d+/?$", path):
                return 1
            if any(token in path for token in ("/news", "/guide", "/category", "/central")) and ep.score <= 20:
                return 1
            if ":id" in route_key:
                return 2
            return 3

        before_prune = len(planned)
        planned = [ep for ep in planned if not _should_prune_low_value(ep)]
        if len(planned) != before_prune:
            console.print(f"  [dim]Pruned {before_prune - len(planned)} low-value synthetic endpoint(s) before fuzzing[/dim]")

        capped_planned = []
        route_counts = {}
        route_pruned = 0
        for ep in planned:
            route_key = _planner_route_key(ep)
            cap = _planner_route_cap(ep, route_key)
            if route_counts.get(route_key, 0) >= cap:
                route_pruned += 1
                continue
            route_counts[route_key] = route_counts.get(route_key, 0) + 1
            capped_planned.append(ep)
        planned = capped_planned
        if route_pruned:
            console.print(f"  [dim]Pruned {route_pruned} repetitive route duplicate(s) before fuzzing[/dim]")

        console.print(f"[green]✓ AI prioritized {len(planned)} endpoints[/green]")

        # Step 8: OWASP Fuzzing (with site_tech)
        console.print(f"\n[cyan]━━ OWASP FUZZING ━━[/cyan]")
        kali   = KaliToolRunner(self.session, self.wl_selector)
        fuzzer = OWASPFuzzEngine(
            self.client, baseline, kali, self.ai,
            self.wl_selector, site_tech=site_tech
        )

        unique_routes = len({_planner_route_key(ep) for ep in planned})
        non_deep_limit = max(30, min(60, unique_routes))
        limit        = len(planned) if self.args.deep else min(len(planned), non_deep_limit)
        all_findings = list(bac_findings) + oauth_saml_findings

        # NEW: Advanced AI Vulnerability Prediction & Prioritization
        console.print(f"\n[cyan]━━ AI RISK PREDICTION & PRIORITIZATION ━━[/cyan]")
        for ep in planned[:limit]:
            # Predict vulnerabilities for each endpoint
            try:
                resp = self.client.get(ep.url)
                risk_profile = self.predict_vulnerabilities_advanced(
                    ep, resp.get("body", ""), "detected_tech"
                )
                ep.predicted_risk = risk_profile.risk_score
            except Exception:
                ep.predicted_risk = 0
        
        # Re-prioritize by predicted risk
        planned_by_risk = sorted(planned[:limit], key=lambda e: getattr(e, 'predicted_risk', 0), reverse=True)
        console.print(f"[green]✓ Endpoints re-prioritized by AI vulnerability prediction[/green]")
        planned = planned_by_risk

        # ── Smart Directory/File Fuzzing ──────────────────────────────────────
        if shutil.which("ffuf") or shutil.which("gobuster"):
            console.print(f"\n[cyan]━━ SMART DIR FUZZING ━━[/cyan]")
            dir_findings = self._smart_dir_fuzz(
                target=target, kali=kali, baseline=baseline,
                profile=smart_profile, ai=self.ai,
            )
            all_findings.extend(dir_findings)
        lock         = threading.Lock()
        ai_thread_limit = 2 if HAS_OLLAMA else MAX_WORKERS
        sema         = threading.Semaphore(max(1, min(MAX_WORKERS, ai_thread_limit)))
        threads      = []

        def fuzz_ep(ep):
            auth_snap = None
            if getattr(self.session, "logged_in", False):
                auth_snap = {
                    "cookies": dict(getattr(self.session, "cookies", {}) or {}),
                    "headers": dict(getattr(self.session, "headers", {}) or {}),
                    "jwt_token": getattr(self.session, "jwt_token", "") or "",
                    "csrf_token": getattr(self.session, "csrf_token", "") or "",
                    "role": getattr(self.session, "role", "") or "",
                    "logged_in": bool(getattr(self.session, "logged_in", False)),
                }
            try:
                with sema:
                    results = fuzzer.test_endpoint(ep)
                    with lock:
                        all_findings.extend(results)
            except Exception as exc:
                console.print(f"  [dim red]Thread error for {ep.url[:50]}: {exc}[/dim red]")
            finally:
                # Generic auth-safety: if an endpoint invalidates active session,
                # restore previous authenticated state without path-name hardcoding.
                if auth_snap and auth_snap.get("logged_in"):
                    cookies_now = dict(getattr(self.session, "cookies", {}) or {})
                    if auth_snap.get("cookies") and not cookies_now:
                        self.session.cookies = dict(auth_snap.get("cookies", {}) or {})
                        self.session.headers = dict(auth_snap.get("headers", {}) or {})
                        self.session.jwt_token = auth_snap.get("jwt_token", "") or ""
                        self.session.csrf_token = auth_snap.get("csrf_token", "") or ""
                        self.session.role = auth_snap.get("role", "") or ""
                        self.session.logged_in = bool(auth_snap.get("logged_in", False))
                        console.print(f"  [dim yellow]⚠ auth session restored after endpoint: {ep.url}[/dim yellow]")

        for ep in planned[:limit]:
            console.print(f"[dim]  ▶ {ep.method} {ep.url[:70]} (score:{ep.score:.0f})[/dim]")
            t = threading.Thread(target=fuzz_ep, args=(ep,), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=180)

        # ── NUCLEI CVE scan ────────────────────────────────────────────────
        if not getattr(self.args, 'no_nuclei', False):
            console.print(f"\n[cyan]━━ NUCLEI CVE SCAN ━━[/cyan]")
            nuclei_runner = NucleiRunner()
            nuclei_hits   = nuclei_runner.run(target, site_tech, self.session)
            all_findings.extend(nuclei_hits)
            console.print(f"[green]✓ Nuclei: {len(nuclei_hits)} findings[/green]")
        else:
            console.print(f"\n[dim]  Nuclei scan skipped (--no-nuclei)[/dim]")

        # ── Recursive 403 bypass (BFS 3 layers) ───────────────────────────
        if getattr(self.args, 'no_403', False):
            console.print(f"\n[dim]  403 bypass skipped (--no-403)[/dim]")
        else:
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
        if not getattr(self.args, 'no_upload', False):
            upload_eps = [ep for ep in enriched if any(
                x in ep.url.lower() for x in
                ["upload","file","image","avatar","import","attach","media"])]
            if upload_eps:
                console.print(f"\n[cyan]━━ FILE UPLOAD ATTACK ━━[/cyan]")
                uploader = FileUploadAttacker(self.client, self.ai)
                for ep in upload_eps[:5]:
                    upload_hits = uploader.attack(ep.url, site_tech)
                    all_findings.extend(upload_hits)
        else:
            console.print(f"\n[dim]  File upload attack skipped (--no-upload)[/dim]")

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

        # ── MitmProxy Interceptor — Burp Suite style analysis ──────────
        if getattr(self.args, "intercept", False) and HAS_MITMPROXY:
            console.print(f"\n[cyan]━━ MITMPROXY INTERCEPTOR (Burp Suite Mode) ━━[/cyan]")
            interceptor = MitmProxyInterceptor(
                self.client, self.ai, self.session, enriched)
            mitm_findings = interceptor.run_passive_analysis()
            all_findings.extend(mitm_findings)
            console.print(f"[green]✓ MitmProxy: {len(mitm_findings)} findings "
                          f"(CSRF/SSRF/BAC/AI-Repeater)[/green]")
        elif getattr(self.args, "intercept", False) and not HAS_MITMPROXY:
            console.print("  [dim yellow]⚠ mitmproxy not installed — skipping interceptor[/dim yellow]")

        # ── OOB payload injection (blind SSRF/CMDi/XXE) ───────────────────
        if oob_domain:
            console.print(f"\n[cyan]━━ OOB BLIND DETECTION ━━[/cyan]")
            oob_payloads = self.oob.payloads(token="pentest")
            console.print(f"  [dim]OOB payloads: {list(oob_payloads.keys())}[/dim]")
            # Send OOB SSRF payloads in URL/param parameters
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
        self._partial_findings = list(all_findings)

        # Step 9b: Confidence threshold enforcement (global gate)
        pre_conf_count = len(all_findings)
        all_findings = [f for f in all_findings if f.confidence >= MIN_CONFIDENCE]
        dropped = pre_conf_count - len(all_findings)
        if dropped:
            console.print(f"  [dim]  Confidence gate: dropped {dropped} findings below {MIN_CONFIDENCE}%[/dim]")

        # Step 10: FP Filter
        console.print(f"\n[cyan]━━ FP FILTER ━━[/cyan]")
        fp_filter = FPFilter(self.ai, self.client)
        clean     = fp_filter.filter(all_findings)

        # NEW Step 10b: Advanced AI Exploitation Analysis
        if clean:
            self._advanced_ai_exploitation(target, clean)
            # Re-rank findings by ROI (exploitability × impact)
            clean = self._rank_findings_by_roi(clean)

        self._partial_findings = list(clean)
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
        self._print_summary(clean, all_findings)

        # ── AI UMUMIY XULOSA ─────────────────────────────────────────────
        console.print(f"\n[cyan]━━ AI SECURITY ASSESSMENT ━━[/cyan]")
        self._ai_final_assessment(clean, all_findings, target, site_tech)

        return clean

    def _advanced_ai_exploitation(self, target: str, all_findings: List):
        """
        NEW: Advanced AI-powered exploitation analysis.
        Plans multi-stage attack chains and intelligent payload strategies.
        """
        console.print(f"\n[cyan]━━ ADVANCED AI EXPLOITATION PLANNING ━━[/cyan]")
        
        # Step 1: Plan multi-stage attack chains
        chains = self.attack_chainer.plan_chain(all_findings)
        if chains:
            console.print(f"[green]✓ {len(chains)} multi-stage attack chain(s) planned[/green]")
            for chain in chains[:3]:
                console.print(f"  [dim]→ {chain.name}: {chain.description[:60]}...[/dim]")
        
        # Step 2: Detect WAF and plan evasion strategies
        waf_detected = self.waf_evader.detect_waf(target)
        if waf_detected != "none":
            console.print(f"  [yellow]⚠ WAF detected: {waf_detected}[/yellow]")
            evasion = self.waf_evader.get_evasion_strategy(waf_detected)
            console.print(f"  [dim]Evasion techniques: {', '.join(evasion['techniques'][:3])}[/dim]")
        
        # Step 3: Identify zero-day patterns
        zero_days = self.vuln_predictor.identify_zero_day_patterns(self.graph.endpoints, all_findings)
        if zero_days:
            console.print(f"[yellow]⚠ {len(zero_days)} potential zero-day pattern(s) detected[/yellow]")
            for zday in zero_days[:2]:
                console.print(f"  [dim]Type: {zday['type']} — {zday['reason'][:50]}...[/dim]")

    def _intelligent_endpoint_prioritization(self, endpoints: List) -> List:
        """
        NEW: Intelligent endpoint prioritization using risk modeling.
        Returns endpoints sorted by vulnerability likelihood.
        """
        console.print(f"\n[cyan]━━ AI INTELLIGENT PRIORITIZATION ━━[/cyan]")
        
        prioritized = self.endpoint_prioritizer.prioritize(endpoints, {})
        
        # Show top 10 highest-risk endpoints
        console.print(f"[green]✓ Endpoints re-prioritized by AI risk model[/green]")
        for i, ep in enumerate(prioritized[:10]):
            ep_str = (ep.url if hasattr(ep, 'url') else str(ep))[:60]
            console.print(f"  [{i+1}] {ep_str}")
        
        return prioritized

    def _predict_vulnerabilities_advanced(self, endpoint, response_body: str, tech_stack: str):
        """
        NEW: Use ML-inspired vulnerability prediction.
        Returns risk profile with likelihood for each vulnerability type.
        """
        profile = self.vuln_predictor.predict_vulnerabilities(
            endpoint.url if hasattr(endpoint, 'url') else str(endpoint),
            response_body,
            {},
            tech_stack
        )
        
        if profile.risk_score > 60:
            console.print(f"  [yellow]⚠ High-risk endpoint identified: {endpoint.url[:50]} ({profile.risk_score:.0f}/100)[/yellow]")
            for vuln_type, likelihood in profile.vulnerability_likelihood.items():
                if likelihood > 0.65:
                    console.print(f"    - {vuln_type}: {likelihood*100:.0f}% likelihood")
        
        return profile

    def _intelligent_payload_generation_for_endpoint(self, endpoint, vuln_type: str) -> List[str]:
        """
        NEW: Generate intelligent payloads based on context.
        Uses tech stack, parameter names, and WAF detection.
        """
        from .ai_exploiter import PayloadContext
        
        tech_stack = "unknown"  # Would be detected from response analysis
        param_name = endpoint.params.keys() if hasattr(endpoint, 'params') else []
        
        ctx = PayloadContext(
            vuln_type=vuln_type,
            param_name=list(param_name)[0] if param_name else "query",
            param_type="query",
            tech_stack=tech_stack,
            response_type="html",
            waf_detected=self.waf_evader.detected_waf,
            encoding="none",
            context_value="",
            injection_point="reflective",
        )
        
        payloads = self.payload_gen.generate(ctx)
        return payloads

    def _rank_findings_by_roi(self, findings: List) -> List:
        """
        NEW: Re-rank findings by exploitation ROI (return on investment).
        Prioritizes high-impact, easily exploitable vulnerabilities.
        """
        return self.endpoint_prioritizer.rank_by_roi(findings)

    def _generate_detailed_explanations(self, findings: List) -> Dict:
        """
        NEW: Generate detailed vulnerability explanations for findings.
        Returns mapping of finding_id → detailed explanation.
        """
        explanations = {}
        for finding in findings:
            try:
                explanation = self.vuln_explainer.explain_vulnerability(finding)
                explanations[id(finding)] = explanation
            except Exception:
                pass  # Skip findings that can't be explained
        return explanations

    def save_partial_results(self, reason: str = "interrupted"):
        """Best-effort partial report save used by runtime on interrupts/exceptions."""
        try:
            target = self._last_target or (getattr(self.args, "target", "") or "unknown_target")
            reporter = Reporter(target, self.graph)
            path = reporter.save(self._partial_findings)
            console.print(f"[yellow]Partial results saved ({reason}) -> {path}[/yellow]")
            return path
        except Exception as exc:
            console.print(f"[bold red]Could not save partial results ({reason}): {exc}[/bold red]")
            return None


    def _ctf_chain(self, finding: "Finding", target: str, tech: dict):
        """
        CTF mode: topilgan finding'dan exploitation chain yaratadi.
        AI searches for flag.txt and shows privilege escalation paths.
        """
        console.print(f"  [bold yellow]⚡ CTF Chain for: {finding.title[:60]}[/bold yellow]")

        # Flag qidirish paths
        flag_paths = [
            "/flag.txt", "/flag", "/root/flag.txt", "/home/ctf/flag.txt",
            "/var/flag.txt", "/tmp/flag.txt", "/flag.php", "/.flag",
        ]

        # If RCE found — attempt to read flag
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
        Recursive smart directory fuzzing:

        1. SmartFuzzProfile for target (already built)
        2. Uses ffuf or gobuster — filter arguments from profile
        3. AI checks each found item (real page or not?)
        4. When a new directory is found — RECURSIVE — same process inside it
        5. A NEW SmartProfile is built for each layer (different path, different 404)
        6. Returns findings
        """
        findings        : list = []
        visited_dirs    : set  = set()
        queue_dirs      : list = [target.rstrip("/")]
        current_depth   : int  = 0
        max_depth       : int  = profile.depth

        # Wordlist for dir fuzzing
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

        def _looks_error_page(body: str) -> bool:
            if not body:
                return False
            body_lower = body.lower()[:2000]
            title_m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
            title = (title_m.group(1).strip().lower() if title_m else "")
            error_signals = [
                "page not found", "not found", "404", "internal server error",
                "500", "sahifa topilmadi", "саҳифа топилмади", "xatolik", "error"
            ]
            return any(sig in title or sig in body_lower for sig in error_signals)

        def _matches_404_profile(body: str, cur_profile: "SmartFuzzProfile") -> bool:
            if not body:
                return False
            body_size = len(body)
            body_words = len(re.findall(r'\S+', body))
            body_lines = len(body.splitlines())
            tolerance = max(80, int(getattr(cur_profile, "tolerance_bytes", 20) or 20) * 4)
            if any(abs(body_size - size) <= tolerance for size in (cur_profile.filter_sizes or [])):
                return True
            if any(abs(body_words - words) <= 8 for words in (cur_profile.filter_words or [])):
                return True
            if any(abs(body_lines - lines) <= 5 for lines in (cur_profile.filter_lines or [])):
                return True
            return False

        while queue_dirs and current_depth <= max_depth:
            current_batch = list(queue_dirs)
            queue_dirs    = []

            for base_dir in current_batch:
                if base_dir in visited_dirs:
                    continue
                visited_dirs.add(base_dir)

                console.print(f"  [bold]→ Fuzzing:[/bold] {base_dir}  "
                              f"[dim](depth {current_depth}/{max_depth})[/dim]")

                # New SmartProfile for this directory
                if current_depth == 0:
                    cur_profile = profile  # Already computed
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

                # AI checks each candidate
                for hit in hits:
                    hit_url  = hit.get("url") or (base_dir + "/" + hit.get("input","")).replace("//","/")
                    hit_size = hit.get("size", 0)
                    hit_status = hit.get("status", 0)

                    # Fetch the hit via GET
                    resp = self.client.get(hit_url)
                    body = resp.get("body", "")
                    final_status = resp.get("status", hit_status)
                    final_url = resp.get("url", hit_url)

                    # Redirect-to-404 / error pages are noise and should not become findings.
                    if final_status == 0:
                        console.print(
                            f"  [dim yellow]  ↳ skip fetch error: {hit_url} — {resp.get('error', '')[:90]}[/dim yellow]"
                        )
                        continue
                    if final_status == 404 or (
                        hit_status in (301, 302, 307, 308) and
                        (final_status in (404, 500) or _looks_error_page(body) or _matches_404_profile(body, cur_profile))
                    ):
                        reason = "redirect-to-error/404 noise"
                        if final_status == 404:
                            reason = "final response is 404"
                        console.print(
                            f"  [dim]  ↳ skip noise: {hit_url}  hit_status={hit_status} final_status={final_status} "
                            f"reason={reason}[/dim]"
                        )
                        continue

                    # AI analysis
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

                    # Recursive — if directory found, proceed to next layer
                    if v_is_dir and current_depth < max_depth:
                        new_dir = hit_url.rstrip("/")
                        if new_dir not in visited_dirs:
                            queue_dirs.append(new_dir)
                            console.print(f"  [dim]    ↳ queued for recursive fuzz: {new_dir}[/dim]")

            current_depth += 1

        return findings

    def _print_summary(self, findings: list["Finding"], all_findings: list["Finding"] = None):
        by_risk = collections.defaultdict(list)
        for f in findings:
            by_risk[f.risk].append(f)

        # Suppressed findings
        suppressed = []
        if all_findings:
            suppressed = [f for f in all_findings if f.fp_filtered]

        if HAS_RICH:
            # ── Confirmed findings table ──
            t = Table(title="📊 Confirmed Findings", box=box.ROUNDED)
            t.add_column("Risk",  width=10)
            t.add_column("OWASP", width=6)
            t.add_column("Title", style="dim", max_width=60)
            t.add_column("Conf",  width=6)
            t.add_column("✓",    width=4)
            colors = {"Critical":"bold red","High":"red","Medium":"yellow","Low":"cyan","Info":"dim"}
            for risk in ["Critical","High","Medium","Low","Info"]:
                for f in by_risk.get(risk, []):
                    c = colors.get(risk, "white")
                    t.add_row(f"[{c}]{risk}[/{c}]", f.owasp_id, f.title[:60],
                              f"{f.confidence}%", "✅" if f.confirmed else "")
            console.print(t)

            # ── Suppressed findings table ──
            if suppressed:
                console.print(f"\n[dim]━━ FP Removed ({len(suppressed)}) ━━[/dim]")
                st = Table(title="🚫 False Positives Removed", box=box.SIMPLE, style="dim")
                st.add_column("Title", max_width=50)
                st.add_column("Reason", max_width=80)
                for f in suppressed:
                    st.add_row(
                        f.title[:50],
                        f.suppression_reason or "Quick filter",
                    )
                console.print(st)

            # ── Statistics ──
            console.print(f"\n[bold]📈 Statistics:[/bold]")
            console.print(f"  Total findings: {len(findings) + len(suppressed)}")
            console.print(f"  ✅ Confirmed:     {len(findings)}")
            console.print(f"  🚫 FP removed:    {len(suppressed)}")
            console.print(f"  Critical: {len(by_risk.get('Critical',[]))}  "
                          f"High: {len(by_risk.get('High',[]))}  "
                          f"Medium: {len(by_risk.get('Medium',[]))}  "
                          f"Low: {len(by_risk.get('Low',[]))}  "
                          f"Info: {len(by_risk.get('Info',[]))}")
        else:
            for f in findings:
                print(f"  [{f.risk}] {f.owasp_id} — {f.title} ({f.confidence}%)")
            if suppressed:
                print(f"\n  FP removed: {len(suppressed)} findings")
                for f in suppressed:
                    print(f"    - {f.title}: {f.suppression_reason}")

    def _ai_final_assessment(self, clean: list["Finding"],
                              all_findings: list["Finding"],
                              target: str, site_tech: dict):
        """End-of-scan comprehensive security assessment by AI."""
        suppressed = [f for f in all_findings if f.fp_filtered]

        findings_summary = []
        for f in clean[:20]:
            findings_summary.append({
                "title": f.title, "risk": f.risk, "owasp": f.owasp_id,
                "confidence": f.confidence, "confirmed": f.confirmed,
                "url": f.url, "evidence": (f.evidence or "")[:150],
            })

        suppressed_summary = []
        for f in suppressed[:15]:
            suppressed_summary.append({
                "title": f.title, "reason": f.suppression_reason or "",
            })

        prompt = f"""You are a senior penetration tester. Write a comprehensive security assessment.

Target: {target}
Technology: {json.dumps(site_tech)}

Confirmed findings ({len(clean)}):
{json.dumps(findings_summary, indent=2)}

FP Removed ({len(suppressed)}):
{json.dumps(suppressed_summary, indent=2)}

Write in this EXACT format:

1. OVERALL RATING: Target security level (Critical/High/Medium/Low) and general assessment
2. KEY RISKS: Most important vulnerabilities found and their consequences
3. FP ANALYSIS: Why certain findings were marked as false positive — brief explanation for each
4. ATTACK VECTORS: How a real attacker could exploit these
5. RECOMMENDATIONS: What to fix in order of priority
6. CONCLUSION: 2-3 sentence final summary

Return as plain text (NOT JSON). Write detailed, professional analysis."""

        try:
            # Get plain text assessment from AI — _call parses JSON,
            # so we call Ollama API directly
            assessment_text = ""
            if HAS_OLLAMA:
                _client = create_ollama_client()
                if _client is not None:
                    resp = _client.chat(
                        model=MODEL_NAME,
                        messages=[
                            {"role": "system", "content": "You are a senior penetration testing expert. Write detailed security assessments."},
                            {"role": "user", "content": prompt},
                        ],
                    )
                    assessment_text = resp["message"]["content"].strip()
            else:
                # Ollama unavailable, AI _call tries to return dict
                result = self.ai._call(prompt, cache=False)
                if isinstance(result, dict):
                    assessment_text = json.dumps(result, indent=2, ensure_ascii=False)
                elif result:
                    assessment_text = str(result)

            if assessment_text and len(assessment_text) > 50:
                console.print(Panel(
                    assessment_text,
                    title="🔍 AI Security Assessment",
                    border_style="cyan",
                    padding=(1, 2),
                ))
            else:
                console.print("  [dim]AI assessment returned no response[/dim]")
                # Fallback — generate our own summary
                self._fallback_assessment(clean, suppressed)
        except Exception as e:
            console.print(f"  [dim]AI assessment error: {e}[/dim]")
            self._fallback_assessment(clean, suppressed)

    def _fallback_assessment(self, clean: list["Finding"], suppressed: list["Finding"]):
        """Heuristic assessment when AI is unavailable."""
        by_risk = collections.defaultdict(list)
        for f in clean:
            by_risk[f.risk].append(f)

        crits = len(by_risk.get("Critical", []))
        highs = len(by_risk.get("High", []))

        if crits > 0:
            level = "CRITICAL"
            color = "bold red"
            desc  = "Critical vulnerabilities found — system can be fully compromised"
        elif highs > 0:
            level = "HIGH"
            color = "red"
            desc  = "High-risk vulnerabilities present — immediate remediation needed"
        elif len(clean) > 0:
            level = "MEDIUM"
            color = "yellow"
            desc  = "Medium-severity vulnerabilities found"
        else:
            level = "LOW"
            color = "green"
            desc  = "No critical vulnerabilities found"

        console.print(f"\n  [{color}]SECURITY LEVEL: {level}[/{color}]")
        console.print(f"  {desc}")
        console.print(f"\n  Findings: {len(clean)} confirmed, {len(suppressed)} FP removed")

        if crits:
            console.print(f"\n  [bold red]CRITICAL vulnerabilities:[/bold red]")
            for f in by_risk["Critical"][:5]:
                console.print(f"    • {f.title} ({f.confidence}%)")
                console.print(f"      [dim]{(f.evidence or '')[:120]}[/dim]")

        if highs:
            console.print(f"\n  [red]HIGH vulnerabilities:[/red]")
            for f in by_risk["High"][:5]:
                console.print(f"    • {f.title} ({f.confidence}%)")

        if suppressed:
            console.print(f"\n  [dim]FP analysis ({len(suppressed)} removed):[/dim]")
            for f in suppressed[:10]:
                console.print(f"    [dim]• {f.title[:50]}[/dim]")
                console.print(f"      [dim]{f.suppression_reason}[/dim]")

__all__ = ['PentestPipeline']
