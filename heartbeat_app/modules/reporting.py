from .base import *

class Reporter:
    def __init__(self, target: str, graph: EndpointGraph):
        self.target = target
        self.graph  = graph
        self.scan_log: list[dict] = []  # Scan process logs

    def log(self, step: str, action: str, details: dict = None):
        """Logs each action during the scan process."""
        self.scan_log.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "step": step,
            "action": action,
            "details": details or {},
        })

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
                    f"| **Verification Reason** | {self._verification_reason(f)} |",
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
                    lines.append(f"- Evidence: {f.evidence}")
        return "\n".join(lines)

    def _build_finding_report(self, f: Finding) -> dict:
        """Creates a complete, thorough report for a single finding."""
        report = {
            "id": hashlib.md5(f"{f.title}{f.url}{f.param}".encode()).hexdigest()[:12],
            "vulnerability": {
                "title": f.title,
                "owasp_id": f.owasp_id,
                "owasp_name": f.owasp_name,
                "risk_level": f.risk,
                "confidence": f.confidence,
                "confirmed": f.confirmed,
                "verification_reason": self._verification_reason(f),
                "description": self._vuln_description(f),
            },
            "target": {
                "url": f.url,
                "method": f.method,
                "parameter": f.param,
            },
            "evidence": {
                "summary": f.evidence,
                "baseline_diff": f.baseline_diff,
                "response_body_snippet": f.response_raw[:3000] if f.response_raw else "",
                "tool_output": f.tool_output[:2000] if f.tool_output else "",
            },
            "exploitation": {
                "poc_command": f.exploit_cmd,
                "request": f.request_raw,
                "payload_used": f.payload,
                "what_attacker_can_do": self._impact_description(f),
                "attack_scenario": self._attack_scenario(f),
            },
            "remediation": f.remediation,
            "tool_used": f.tool,
            "timestamp": f.timestamp,
        }
        if f.chain:
            report["exploitation"]["chain_steps"] = f.chain
        if f.oob:
            report["exploitation"]["oob_confirmed"] = True
        return report

    def _verification_reason(self, f: Finding) -> str:
        """Human-readable reason for why a finding is confirmed or not."""
        explicit_reason = str(getattr(f, "verification_reason", "") or "").strip()
        if explicit_reason:
            return explicit_reason

        if f.fp_filtered:
            return f.suppression_reason or "Filtered as false positive by verification logic."

        if f.confirmed:
            if getattr(f, "oob", False):
                return "Out-of-band callback observed during verification."

            evidence = str(f.evidence or "")
            if "VERIFIED:" in evidence:
                return evidence.split("VERIFIED:", 1)[1].strip() or "Verified by evidence in response comparison."

            tool_output = str(f.tool_output or "")
            if "VERIFIED:" in tool_output:
                return tool_output.split("VERIFIED:", 1)[1].strip() or "Verified by scanner/tool output."

            if f.exploit_cmd:
                return "Exploit PoC generated and verification signal met."

            return "Confirmed by automated verification heuristics and confidence threshold."

        if f.suppression_reason:
            return f.suppression_reason

        if f.confidence < 70:
            return f"Not confirmed due to low confidence ({f.confidence}%)."

        return "Not confirmed: evidence did not meet verification criteria."

    def _vuln_description(self, f: Finding) -> str:
        """Full explanation of what the vulnerability consists of."""
        descs = {
            "A01": "Broken Access Control — the server does not properly validate user permissions. "
                   "Unauthorized access to protected resources is possible.",
            "A02": "Cryptographic Failures — encryption is improperly or weakly implemented.",
            "A03": "Injection — malicious data can be sent to the server and executed.",
            "A04": "Insecure Design — security weakness in the application architecture.",
            "A05": "Security Misconfiguration — the server is improperly configured.",
            "A07": "Identification/Auth Failures — authentication is weak or can be bypassed.",
            "A10": "SSRF — the server can be forced to send requests to external or internal resources.",
        }
        return descs.get(f.owasp_id, f"OWASP {f.owasp_id} — {f.owasp_name}")

    def _impact_description(self, f: Finding) -> str:
        """What an attacker CAN DO through this vulnerability."""
        if "BAC" in f.title or "Access Control" in f.title or "bypass" in f.title.lower():
            return ("An attacker can gain unauthorized access to protected pages, view admin panels, "
                    "read confidential configurations, and obtain user data.")
        if "SSRF" in f.title:
            return ("An attacker can force the server to send requests to other services on the internal network, "
                    "obtain AWS metadata, and read internal data.")
        if "SQL" in f.title.upper():
            return ("An attacker can read, modify, and delete all data in the database. "
                    "In some cases, they can also execute commands on the operating system.")
        if "XSS" in f.title.upper():
            return ("An attacker can execute JavaScript code in other users' browsers, "
                    "steal cookies/sessions, and perform phishing attacks.")
        if "rate limit" in f.title.lower():
            return "An attacker can brute-force passwords (no rate limiting in place)."
        if "header" in f.title.lower() and "missing" in f.title.lower():
            return "Browser protections are not enabled — vulnerable to clickjacking, XSS, MIME sniffing attacks."
        if "JWT" in f.title:
            return "An attacker can forge JWT tokens and gain access as another user."
        if "Method" in f.title:
            return "Unexpected HTTP methods are accepted — data modification/deletion is possible."
        return "This vulnerability can be exploited by an attacker to compromise the target system."

    def _attack_scenario(self, f: Finding) -> str:
        """Explains a concrete attack scenario."""
        if "X-Forwarded-For" in f.title:
            return ("1. Attacker adds 'X-Forwarded-For: 127.0.0.1' header to the request\n"
                    "2. Server treats the attacker as localhost\n"
                    "3. IP-based restrictions are bypassed\n"
                    "4. Access to protected endpoints becomes possible")
        if "403" in f.title or "ACL" in f.title:
            return ("1. /admin page returns 403 Forbidden\n"
                    "2. But /admin/child-path page returns 200 OK\n"
                    "3. Permission check only exists on parent path — not on child\n"
                    "4. Attacker accesses child path directly and views admin data")
        if "SSRF" in f.title:
            return ("1. Attacker sends an internal URL in the parameter (e.g. http://169.254.169.254/)\n"
                    "2. Server sends a request to that URL\n"
                    "3. Internal network data is returned to the attacker")
        if "rate limit" in f.title.lower():
            return ("1. Attacker sends thousands of passwords to the login page\n"
                    "2. Server applies no rate limiting\n"
                    "3. When the correct password is found — account is compromised")
        return f"PoC buyrug'ini ishga tushiring va natijani kuzating: {f.exploit_cmd}"

    def save(self, findings: list[Finding]) -> Path:
        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r'[^\w.]', '_', self.target)

        # 1st JSON: Scan Log — what actions were performed
        log_path = REPORT_DIR / f"scan_log_{safe}_{ts}.json"
        scan_log_data = {
            "target": self.target,
            "scan_date": datetime.datetime.now().isoformat(),
            "endpoints_tested": self.graph.stats()["endpoints"],
            "parameters_found": self.graph.stats()["params"],
            "scan_steps": self.scan_log,
            "endpoint_map": self.graph.nodes,
        }
        log_path.write_text(json.dumps(scan_log_data, indent=2, default=str, ensure_ascii=False), encoding="utf-8")

        # 2nd JSON: Findings Report — what was found (complete and thorough)
        confirmed_findings = [f for f in findings if not f.fp_filtered]
        suppressed_findings = [f for f in findings if f.fp_filtered]

        findings_data = {
            "target": self.target,
            "scan_date": datetime.datetime.now().isoformat(),
            "summary": {
                "total_confirmed": len(confirmed_findings),
                "total_suppressed": len(suppressed_findings),
                "by_risk": {},
                "by_owasp": {},
            },
            "confirmed_vulnerabilities": [],
            "suppressed_false_positives": [],
        }

        # Risk and OWASP statistics
        for f in confirmed_findings:
            findings_data["summary"]["by_risk"][f.risk] = findings_data["summary"]["by_risk"].get(f.risk, 0) + 1
            findings_data["summary"]["by_owasp"][f.owasp_id] = findings_data["summary"]["by_owasp"].get(f.owasp_id, 0) + 1

        # Confirmed findings — full report
        for f in confirmed_findings:
            findings_data["confirmed_vulnerabilities"].append(self._build_finding_report(f))

        # Suppressed — brief reason
        for f in suppressed_findings:
            findings_data["suppressed_false_positives"].append({
                "title": f.title,
                "url": f.url,
                "risk": f.risk,
                "confidence": f.confidence,
                "reason_suppressed": f.suppression_reason or "AI FP filter",
                "verification_reason": self._verification_reason(f),
            })

        findings_path = REPORT_DIR / f"findings_{safe}_{ts}.json"
        findings_path.write_text(json.dumps(findings_data, indent=2, default=str, ensure_ascii=False), encoding="utf-8")

        # MD report also saved (for legacy format)
        md_path = REPORT_DIR / f"pentest_{safe}_{ts}.md"
        md_path.write_text(self.generate(findings), encoding="utf-8")

        console.print(f"\n[bold green]✅ Reports saved:[/bold green]")
        console.print(f"   📋 Scan Log:     {log_path}")
        console.print(f"   🔍 Findings:     {findings_path}")
        console.print(f"   📄 Full Report:  {md_path}")
        return md_path

__all__ = ['Reporter']
