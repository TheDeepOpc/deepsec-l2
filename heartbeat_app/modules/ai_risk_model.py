"""
Advanced Vulnerability Prediction & Risk Modeling Engine
Features:
  - Predictive vulnerability modeling based on code patterns
  - ML-inspired risk scoring combining behavioral indicators
  - Zero-day pattern recognition
  - Endpoint risk classification and prioritization
  - Vulnerability interdependency analysis
"""

from .base import *
import json
import re
import hashlib
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
import statistics


@dataclass
class RiskProfile:
    """Risk assessment for an endpoint"""
    endpoint_url: str
    risk_score: float  # 0-100
    vulnerability_likelihood: Dict[str, float]  # vuln_type -> probability
    behavioral_signals: List[str]
    attack_surface_area: int
    confidence: float


class VulnerabilityPredictor:
    """
    Predicts vulnerabilities using pattern analysis and behavioral signals.
    Identifies zero-day like patterns and emerging vulnerabilities.
    """

    def __init__(self, ai_engine):
        self.ai = ai_engine
        self.pattern_db = self._init_pattern_db()
        self.cache = {}

    def _init_pattern_db(self) -> Dict:
        """Initialize vulnerability pattern database"""
        return {
            "sqli": {
                "critical_keywords": ["WHERE", "ORDER BY", "GROUP BY", "SELECT", "INSERT", "UPDATE"],
                "param_patterns": [r"id\d*", r"user_id", r"product_id", r"filter", r"sort"],
                "response_indicators": [r"SQL\s+error", r"mysql_fetch", r"syntax error", "SQLite3"],
                "tech_indicators": ["mysql", "postgresql", "mssql", "oracle"],
                "base_risk": 0.7,
            },
            "xss": {
                "critical_keywords": ["ECHO", "PRINT", "_GET", "_POST", "_REQUEST", "RESPONSE.WRITE"],
                "param_patterns": [r"q\d*", r"query", r"search", r"text", r"comment"],
                "response_indicators": [r"<html", r"<script", r"<body"],
                "tech_indicators": ["php", "asp", "node", "python"],
                "base_risk": 0.6,
            },
            "cmdi": {
                "critical_keywords": ["SHELL", "EXEC", "SYSTEM", "POPEN", "SUBPROCESS", "BACKTICK"],
                "param_patterns": [r"cmd", r"command", r"exec", r"shell", r"ping"],
                "response_indicators": [r"uid=\d+", r"root:"],
                "tech_indicators": ["php", "python", "nodejs", "perl"],
                "base_risk": 0.8,
            },
            "lfi": {
                "critical_keywords": ["INCLUDE", "REQUIRE", "FOPEN", "READFILE", "LOAD_FILE"],
                "param_patterns": [r"file\d*", r"page", r"path", r"load"],
                "response_indicators": [r"root:", r"admin:"],
                "tech_indicators": ["php", "asp"],
                "base_risk": 0.65,
            },
            "ssrf": {
                "critical_keywords": ["CURL", "SOCKET", "FSOCKOPEN", "FOPEN", "STREAM"],
                "param_patterns": [r"url", r"link", r"fetch", r"download", r"preview"],
                "response_indicators": [],
                "tech_indicators": ["python", "java", "nodejs"],
                "base_risk": 0.62,
            },
            "acl_bypass": {
                "critical_keywords": ["ADMIN", "ROLE", "PERMISSION", "AUTH", "ACCESS"],
                "param_patterns": [r"id\d*", r"user", r"admin", r"role"],
                "response_indicators": [r"200", r"403", r"401"],
                "tech_indicators": [],
                "base_risk": 0.75,
            },
            "ssti": {
                "critical_keywords": ["{{", "{%", "${", "<%", "#{{"],
                "param_patterns": [r"template", r"view", r"name"],
                "response_indicators": ["{{7*7}}", "${7*7}"],
                "tech_indicators": ["python", "java", "node", "ruby"],
                "base_risk": 0.68,
            },
        }

    def predict_vulnerabilities(self, endpoint_url: str, response_body: str, headers: Dict, tech_stack: str) -> RiskProfile:
        """
        Analyze endpoint and predict potential vulnerabilities using pattern matching.
        Returns risk profile with vulnerability likelihood for each vuln type.
        """
        cache_key = hashlib.md5(endpoint_url.encode()).hexdigest()
        if cache_key in self.cache:
            return self.cache[cache_key]

        vuln_likelihood = {}
        behavioral_signals = []
        attack_surface = 0

        # Extract endpoint characteristics
        parsed_url = urllib.parse.urlparse(endpoint_url)
        path = parsed_url.path.lower()
        query = parsed_url.query.lower()
        params = urllib.parse.parse_qs(parsed_url.query)

        # Analyze each vulnerability type
        for vuln_type, pattern_info in self.pattern_db.items():
            risk_score = pattern_info["base_risk"]

            # Check critical keywords in response
            keyword_hits = sum(
                1 for kw in pattern_info["critical_keywords"]
                if re.search(kw, response_body, re.IGNORECASE)
            )
            keyword_boost = min(0.2, keyword_hits * 0.05)
            risk_score += keyword_boost

            # Check parameter patterns
            param_hits = 0
            for param in params.keys():
                if any(re.match(p, param, re.IGNORECASE) for p in pattern_info["param_patterns"]):
                    param_hits += 1
            param_boost = min(0.15, param_hits * 0.05)
            risk_score += param_boost

            # Check response indicators
            if pattern_info["response_indicators"]:
                indicator_hits = sum(
                    1 for indicator in pattern_info["response_indicators"]
                    if re.search(indicator, response_body, re.IGNORECASE)
                )
                indicator_boost = indicator_hits * 0.1
                risk_score += indicator_boost

            # Check technology stack
            if any(tech.lower() in tech_stack.lower() for tech in pattern_info["tech_indicators"]):
                risk_score += 0.1

            # Analyze HTTP method
            if endpoint_url.startswith("POST "):
                if vuln_type in ("sqli", "xss", "cmdi", "ssrf", "ssti"):
                    risk_score += 0.1

            # Add behavioral signals
            if risk_score > 0.7:
                behavioral_signals.append(f"High indicators for {vuln_type}")
            elif risk_score > 0.5:
                behavioral_signals.append(f"Medium indicators for {vuln_type}")

            # Normalize risk score to 0-1
            vuln_likelihood[vuln_type] = min(1.0, max(0.0, risk_score))
            attack_surface += (1 if risk_score > 0.5 else 0)

        # Calculate overall risk score
        avg_risk = statistics.mean(vuln_likelihood.values()) if vuln_likelihood else 0
        high_risk_vulns = sum(1 for v in vuln_likelihood.values() if v > 0.65)
        overall_risk = (avg_risk * 0.6 + (high_risk_vulns / len(vuln_likelihood)) * 0.4) * 100

        profile = RiskProfile(
            endpoint_url=endpoint_url,
            risk_score=overall_risk,
            vulnerability_likelihood=vuln_likelihood,
            behavioral_signals=behavioral_signals,
            attack_surface_area=attack_surface,
            confidence=min(0.99, 0.5 + (len(behavioral_signals) * 0.15)),
        )

        self.cache[cache_key] = profile
        return profile

    def identify_zero_day_patterns(self, endpoints: List, findings: List) -> List[Dict]:
        """
        Identify patterns that might indicate zero-day vulnerabilities.
        Detects unusual endpoint behaviors not matching known vulnerability signatures.
        """
        zero_day_candidates = []

        # Pattern 1: Endpoints with high response variance
        response_sizes = {}
        for ep in endpoints:
            if hasattr(ep, 'url'):
                size = len(ep.url)
                response_sizes[ep.url] = size

        # Pattern 2: Endpoints that accept unusual parameters
        uncommon_params = {}
        for ep in endpoints:
            if hasattr(ep, 'params'):
                for param in ep.params.keys():
                    if param not in uncommon_params:
                        uncommon_params[param] = []
                    uncommon_params[param].append(ep.url)

        # Identify rare parameters that might indicate custom functionality
        for param, urls in uncommon_params.items():
            if len(urls) == 1 and any(c in param.lower() for c in ("_debug", "_trace", "_log", "_internal")):
                zero_day_candidates.append({
                    "type": "custom_param_exposure",
                    "endpoint": urls[0],
                    "param": param,
                    "risk": "Medium",
                    "reason": f"Custom parameter '{param}' may expose debug/internal functionality",
                })

        # Pattern 3: Endpoints with status code anomalies
        status_dist = {}
        for ep in endpoints:
            if hasattr(ep, 'status'):
                status = ep.status
                if status not in status_dist:
                    status_dist[status] = 0
                status_dist[status] += 1

        unusual_statuses = [status for status, count in status_dist.items() if count == 1 and status not in (200, 301, 302, 404)]
        if unusual_statuses:
            zero_day_candidates.append({
                "type": "unusual_status_codes",
                "statuses": unusual_statuses,
                "risk": "Low",
                "reason": f"Unusual HTTP status codes detected: {unusual_statuses}",
            })

        return zero_day_candidates

    def score_endpoint(self, endpoint, response_body: str, tech_stack: str) -> float:
        """
        Score endpoint on 0-100 scale for likelihood of vulnerability.
        Higher score = more likely to be vulnerable.
        """
        profile = self.predict_vulnerabilities(
            endpoint.url if hasattr(endpoint, 'url') else str(endpoint),
            response_body,
            {},
            tech_stack
        )
        return profile.risk_score


class EndpointPrioritizer:
    """
    Prioritizes endpoints for testing based on multiple risk signals.
    Uses ML-inspired scoring combining behavioral indicators.
    """

    def __init__(self, ai_engine):
        self.ai = ai_engine
        self.predictor = VulnerabilityPredictor(ai_engine)

    def prioritize(self, endpoints: List, response_data: Dict) -> List:
        """
        Score and rank endpoints by testability and risk.
        Returns endpoints sorted by priority for fuzzing.
        """
        scored = []

        for ep in endpoints:
            score = 0

            # Factor 1: Parameter count (more params = more attack surface)
            param_count = len(ep.params) if hasattr(ep, 'params') and ep.params else 0
            score += min(30, param_count * 5)

            # Factor 2: HTTP method (POST > PUT > PATCH > DELETE > GET)
            method = ep.method.upper() if hasattr(ep, 'method') else "GET"
            method_weights = {"POST": 20, "PUT": 15, "PATCH": 15, "DELETE": 10, "GET": 5}
            score += method_weights.get(method, 0)

            # Factor 3: Endpoint depth/complexity
            path = ep.url if hasattr(ep, 'url') else ""
            depth = path.count('/')
            score += min(15, depth * 2)

            # Factor 4: High-risk keywords in path
            risky_keywords = ["admin", "api", "internal", "debug", "test", "dev", "backup", "tmp", "upload", "file"]
            risk_keywords_found = sum(1 for kw in risky_keywords if kw in path.lower())
            score += risk_keywords_found * 10

            # Factor 5: Tech stack
            tech_stack_indicators = {
                "php": 15,
                "python": 12,
                "java": 12,
                "nodejs": 10,
                "asp": 12,
                "wordpress": 18,
                "joomla": 15,
            }
            for tech, weight in tech_stack_indicators.items():
                if tech.lower() in path.lower():
                    score += weight

            # Factor 6: Has authentication/sensitive operations
            sensitive_keywords = ["login", "auth", "password", "pay", "transaction", "billing", "credit"]
            sensitive_count = sum(1 for kw in sensitive_keywords if kw in path.lower())
            score += sensitive_count * 12

            # Factor 7: Endpoint has special handling (custom scoring)
            if hasattr(ep, 'score'):
                score += ep.score * 0.5

            # Cap at 100
            score = min(100, max(0, score))

            scored.append((ep, score))

        # Sort by score descending
        scored.sort(key=lambda x: x[1], reverse=True)
        return [ep for ep, score in scored]

    def rank_by_roi(self, findings: List) -> List:
        """
        Re-rank findings by ROI (return on investment).
        Critical high-confidence findings first, then chainable vulns.
        """
        # Score each finding by exploitability and impact
        scored = []
        for finding in findings:
            roi_score = 0

            # Risk * Confidence = impact
            risk_weight = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(finding.risk, 1)
            confidence = getattr(finding, 'confidence', 50) / 100
            roi_score += risk_weight * confidence * 30

            # Chainable vulnerability bonus
            chainable_keywords = ["sqli", "xss", "ssrf", "cmdi", "rce", "auth"]
            if any(kw in finding.title.lower() for kw in chainable_keywords):
                roi_score += 20

            # Confirmed findings bonus
            if getattr(finding, 'confirmed', False):
                roi_score += 15

            scored.append((finding, roi_score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [f for f, _ in scored]


class BehavioralAnalyzer:
    """
    Analyzes application behavior to detect unusual patterns.
    Helps identify custom vulnerabilities and logic errors.
    """

    def __init__(self, ai_engine):
        self.ai = ai_engine
        self.baseline_behaviors = {}

    def establish_baseline(self, target_url: str, sample_requests: List[Dict]) -> Dict:
        """
        Establish baseline behavior for target application.
        Used to detect anomalies later.
        """
        baseline = {
            "avg_response_time": 0,
            "avg_response_size": 0,
            "common_status_codes": [],
            "common_headers": {},
            "error_patterns": [],
        }

        response_times = []
        response_sizes = []
        status_codes = []

        for req in sample_requests:
            response_times.append(req.get("time", 0))
            response_sizes.append(len(req.get("body", "")))
            status_codes.append(req.get("status"))

        baseline["avg_response_time"] = statistics.mean(response_times) if response_times else 0
        baseline["avg_response_size"] = statistics.mean(response_sizes) if response_sizes else 0
        baseline["common_status_codes"] = list(set(status_codes))

        self.baseline_behaviors[target_url] = baseline
        return baseline

    def detect_anomalies(self, target_url: str, current_responses: List[Dict]) -> List[Dict]:
        """
        Detect behavioral anomalies based on baseline.
        Returns list of detected anomalies.
        """
        if target_url not in self.baseline_behaviors:
            return []

        baseline = self.baseline_behaviors[target_url]
        anomalies = []

        for resp in current_responses:
            # Detect response time anomaly
            resp_time = resp.get("time", 0)
            if resp_time > baseline["avg_response_time"] * 3:
                anomalies.append({
                    "type": "slow_response",
                    "threshold_exceeded": resp_time / baseline["avg_response_time"],
                    "potential_issue": "Possible time-delay based blind vulnerability or DoS impact",
                })

            # Detect unexpected status code
            status = resp.get("status")
            if status not in baseline["common_status_codes"] and status != 404:
                anomalies.append({
                    "type": "unexpected_status",
                    "status": status,
                    "potential_issue": "Unusual HTTP response, may indicate error handling bypass",
                })

        return anomalies


__all__ = [
    "VulnerabilityPredictor",
    "EndpointPrioritizer",
    "BehavioralAnalyzer",
    "RiskProfile",
]
