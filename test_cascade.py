#!/usr/bin/env python3
from heartbeat_app.engine_combined import CascadeDetector

# Test Case 1: Cascading redirects (80% are 301s)
cascading_results = [
    {"status": 301, "url": "http://example.com/a", "size": 100},
    {"status": 301, "url": "http://example.com/b", "size": 100},
    {"status": 301, "url": "http://example.com/c", "size": 100},
    {"status": 301, "url": "http://example.com/d", "size": 100},
    {"status": 200, "url": "http://example.com/admin", "size": 500},
]

result1 = CascadeDetector.detect_cascading_redirects(cascading_results)
print("Test 1 (Cascading):")
print(f"  is_cascading: {result1['is_cascading']}")
print(f"  cascade_percent: {result1['cascade_percent']:.1%}")
print(f"  should_halt: {result1['should_halt']}")
print(f"  reason: {result1['reason']}\n")

# Test Case 2: Normal results (20% are 301s)
normal_results = [
    {"status": 200, "url": "http://example.com/admin", "size": 500},
    {"status": 200, "url": "http://example.com/api", "size": 600},
    {"status": 200, "url": "http://example.com/login", "size": 700},
    {"status": 200, "url": "http://example.com/profile", "size": 800},
    {"status": 301, "url": "http://example.com/old", "size": 100},
]

result2 = CascadeDetector.detect_cascading_redirects(normal_results)
print("Test 2 (Normal):")
print(f"  is_cascading: {result2['is_cascading']}")
print(f"  cascade_percent: {result2['cascade_percent']:.1%}")
print(f"  should_halt: {result2['should_halt']}")
print(f"  reason: {result2['reason']}\n")

# Test Case 3: Edge case (exactly at threshold)
edge_results = [
    {"status": 301, "url": "http://example.com/a", "size": 100},
    {"status": 301, "url": "http://example.com/b", "size": 100},
    {"status": 301, "url": "http://example.com/c", "size": 100},
    {"status": 200, "url": "http://example.com/d", "size": 500},
    {"status": 200, "url": "http://example.com/e", "size": 600},
]

result3 = CascadeDetector.detect_cascading_redirects(edge_results)
print("Test 3 (Edge case - 60% threshold):")
print(f"  is_cascading: {result3['is_cascading']}")
print(f"  cascade_percent: {result3['cascade_percent']:.1%}")
print(f"  should_halt: {result3['should_halt']}")
print(f"  reason: {result3['reason']}\n")

print("✅ CascadeDetector tests completed successfully!")
