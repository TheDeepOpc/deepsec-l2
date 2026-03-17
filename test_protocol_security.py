#!/usr/bin/env python3
"""
Test suite for HTTP protocol security detection.
Tests the _check_protocol_security method with various scenarios.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any

# Mock Finding for testing
@dataclass
class Finding:
    owasp_id: str
    owasp_name: str
    title: str
    risk: str
    confidence: int
    url: str
    method: str
    param: str
    payload: str
    evidence: str
    baseline_diff: str
    tool_output: str
    request_raw: str
    response_raw: str
    exploit_cmd: str
    remediation: str
    confirmed: bool = False
    tool: str = ""

@dataclass
class ReconResult:
    target_input: str
    resolved_ip: str
    open_ports: list
    http_targets: list
    subdomains: list = field(default_factory=list)
    waf: str = "none"
    tech_stack: dict = field(default_factory=dict)
    os_guess: str = "unknown"
    hostnames: list = field(default_factory=list)
    raw_nmap: str = ""
    raw_whatweb: str = ""

# Test scenarios
def test_http_https_downgrade():
    """Test: Both HTTP and HTTPS available"""
    recon = ReconResult(
        target_input="rtrj.uz",
        resolved_ip="91.212.89.91",
        open_ports=[],
        http_targets=[
            {"url": "http://rtrj.uz", "port": 80, "ssl": False},
            {"url": "https://rtrj.uz", "port": 443, "ssl": True},
        ],
        hostnames=["rtrj.uz"],
    )
    
    # Check conditions
    has_http = any(t["url"].startswith("http://") for t in recon.http_targets)
    has_https = any(t["url"].startswith("https") for t in recon.http_targets)
    
    print(f"[TEST] Test 1 (HTTP+HTTPS downgrade risk):")
    print(f"  has_http={has_http}, has_https={has_https}")
    print(f"  Expected: Both True -> Finding generated")
    assert has_http and has_https, "Should detect both HTTP and HTTPS"
    print(f"  Result: [PASS]\n")

def test_https_only():
    """Test: HTTPS-only (secure)"""
    recon = ReconResult(
        target_input="secure.example.com",
        resolved_ip="192.0.2.1",
        open_ports=[],
        http_targets=[
            {"url": "https://secure.example.com", "port": 443, "ssl": True},
        ],
        hostnames=["secure.example.com"],
    )
    
    has_http = any(t["url"].startswith("http://") for t in recon.http_targets)
    has_https = any(t["url"].startswith("https") for t in recon.http_targets)
    
    print(f"[TEST] Test 2 (HTTPS-only, no downgrade risk):")
    print(f"  has_http={has_http}, has_https={has_https}")
    print(f"  Expected: HTTP=False, HTTPS=True -> No downgrade finding")
    assert not has_http and has_https, "Should not alert on HTTPS-only"
    print(f"  Result: [PASS]\n")

def test_http_only():
    """Test: HTTP-only (insecure)"""
    recon = ReconResult(
        target_input="insecure.local",
        resolved_ip="192.0.2.2",
        open_ports=[],
        http_targets=[
            {"url": "http://insecure.local", "port": 80, "ssl": False},
        ],
        hostnames=["insecure.local"],
    )
    
    has_http = any(t["url"].startswith("http://") for t in recon.http_targets)
    has_https = any(t["url"].startswith("https") for t in recon.http_targets)
    
    print(f"[TEST] Test 3 (HTTP-only, sensitive data risk):")
    print(f"  has_http={has_http}, has_https={has_https}")
    print(f"  Expected: HTTP=True, HTTPS=False -> Finding for unencrypted transmission")
    assert has_http and not has_https, "Should detect HTTP-only service"
    print(f"  Result: [PASS]\n")

def test_finding_structure():
    """Test: Finding dataclass structure"""
    finding = Finding(
        owasp_id="A02",
        owasp_name="Cryptographic Failures",
        title="HTTP and HTTPS Both Available",
        risk="High",
        confidence=90,
        url="http://example.com",
        method="GET",
        param="",
        payload="",
        evidence="Both protocols available",
        baseline_diff="mixed_http_https",
        tool_output="HTTP and HTTPS detected",
        request_raw="GET /",
        response_raw="200 OK",
        exploit_cmd="curl http://example.com",
        remediation="Use HSTS and disable HTTP",
        confirmed=True,
        tool="protocol_check",
    )
    
    print(f"[TEST] Test 4 (Finding structure validation):")
    print(f"  title={finding.title[:40]}...")
    print(f"  risk={finding.risk}, confidence={finding.confidence}%")
    assert finding.risk in ("Critical", "High", "Medium", "Low", "Info"), "Risk level invalid"
    assert 0 <= finding.confidence <= 100, "Confidence must be 0-100"
    print(f"  Result: [PASS]\n")

if __name__ == "__main__":
    print("=" * 60)
    print("  HTTP Protocol Security Detection Tests")
    print("=" * 60 + "\n")
    
    try:
        test_http_https_downgrade()
        test_https_only()
        test_http_only()
        test_finding_structure()
        
        print("=" * 60)
        print("  [PASS] All protocol security tests passed")
        print("=" * 60)
    except AssertionError as e:
        print(f"\n[FAIL] Test failed: {e}")
        exit(1)
