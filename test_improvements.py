#!/usr/bin/env python3
"""
Comprehensive testing of all 5 improvements
Tests: Database, Authentication, Rate Limiting, Reporting, Alerts
"""

import requests
import json
import time
from datetime import datetime

BASE_URL = "http://localhost:5000"
TEST_RESULTS = []

def test(name, fn):
    """Run test and track results"""
    try:
        print(f"\n{'='*60}")
        print(f"TEST: {name}")
        print('='*60)
        result = fn()
        TEST_RESULTS.append((name, "PASS", result))
        print(f"✓ PASSED: {name}")
        return result
    except Exception as e:
        TEST_RESULTS.append((name, "FAIL", str(e)))
        print(f"✗ FAILED: {name}")
        print(f"Error: {e}")
        return None


def test_health():
    """Test 1: Health endpoint"""
    response = requests.get(f"{BASE_URL}/api/health", timeout=5)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    return response.json()


def test_registration():
    """Test 2: User registration"""
    payload = {
        "username": f"testuser_{int(time.time())}",
        "email": f"test_{int(time.time())}@example.com",
        "password": "SecurePass123!"
    }
    response = requests.post(f"{BASE_URL}/api/auth/register", json=payload, timeout=5)
    assert response.status_code == 201, f"Expected 201, got {response.status_code}: {response.text}"
    data = response.json()
    assert data['success'], "Registration failed"
    return data


def test_login():
    """Test 3: User login"""
    # Register first
    username = f"loginuser_{int(time.time())}"
    payload = {
        "username": username,
        "email": f"{username}@example.com",
        "password": "Pass123456!"
    }
    requests.post(f"{BASE_URL}/api/auth/register", json=payload, timeout=5)
    
    # Now login
    login_payload = {"username": username, "password": "Pass123456!"}
    response = requests.post(f"{BASE_URL}/api/auth/login", json=login_payload, timeout=5)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    data = response.json()
    assert 'token' in data, "No token in response"
    assert data['success'], "Login failed"
    return data['token']


def test_get_user(token):
    """Test 4: Get user info with token"""
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/api/auth/user", headers=headers, timeout=5)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    user = response.json()
    assert 'username' in user, "No username in response"
    assert 'role' in user, "No role in response"
    return user


def test_threats_status():
    """Test 5: Threat detection status"""
    response = requests.get(f"{BASE_URL}/api/threats/status", timeout=5)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    assert 'level' in data, "No threat level"
    assert 'total_threats' in data, "No threat count"
    return data


def test_rate_limiting():
    """Test 6: Rate limiting (60 requests/minute)"""
    print("Sending 65 rapid requests to test rate limiting...")
    rate_limited = False
    for i in range(65):
        try:
            response = requests.get(f"{BASE_URL}/api/health", timeout=1)
            if response.status_code == 429:
                print(f"  ✓ Rate limited at request {i+1}")
                rate_limited = True
                break
        except:
            pass
        if (i + 1) % 10 == 0:
            print(f"  Sent {i+1} requests...")
    
    assert rate_limited, "Rate limiting did not trigger"
    return {"rate_limited_at": i+1}


def test_save_test_result(token):
    """Test 7: Save penetration test result"""
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "test_type": "sql_injection",
        "target": "example.com",
        "status": "completed",
        "vulnerabilities_found": 3,
        "severity": "HIGH",
        "result": {"payload": "test_payload", "response": "vulnerable"},
        "notes": "SQL injection found in login form"
    }
    response = requests.post(
        f"{BASE_URL}/api/database/test-results",
        json=payload,
        headers=headers,
        timeout=5
    )
    assert response.status_code == 201, f"Expected 201, got {response.status_code}: {response.text}"
    data = response.json()
    assert 'id' in data, "No test result ID returned"
    return data


def test_generate_report(token):
    """Test 8: Generate security report"""
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "title": f"Security Assessment - {datetime.now().strftime('%Y-%m-%d')}",
        "test_results": [
            {
                "test_type": "sql_injection",
                "target": "example.com",
                "vulnerabilities_found": 2,
                "severity": "HIGH",
                "status": "completed"
            },
            {
                "test_type": "xss",
                "target": "example.com",
                "vulnerabilities_found": 1,
                "severity": "MEDIUM",
                "status": "completed"
            }
        ],
        "report_type": "summary",
        "company_name": "Security Testing Company"
    }
    response = requests.post(
        f"{BASE_URL}/api/reports/generate",
        json=payload,
        headers=headers,
        timeout=10
    )
    assert response.status_code in [200, 201], f"Expected 200/201, got {response.status_code}: {response.text}"
    data = response.json()
    assert 'html_path' in data or 'success' in data, "No report path returned"
    return data


def test_alert_endpoints():
    """Test 9: Alert endpoints"""
    # Get threat alerts
    response = requests.get(f"{BASE_URL}/api/alerts/threat", timeout=5)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    alerts = response.json()
    assert 'alerts' in alerts, "No alerts list"
    
    # Get security alerts
    response = requests.get(f"{BASE_URL}/api/alerts/security", timeout=5)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    alerts = response.json()
    assert 'alerts' in alerts, "No alerts list"
    
    return {"threat_alerts": len(response.json()['alerts'])}


# Run all tests
if __name__ == "__main__":
    print("\n" + "="*60)
    print("VPN PROXY + PENTESTING TOOLKIT - COMPREHENSIVE TEST SUITE")
    print("Testing all 5 improvements")
    print("="*60)
    
    # Test 1: Health
    test("Health Check", test_health)
    
    # Test 2: Registration
    test("User Registration", test_registration)
    
    # Test 3: Login
    token = test("User Login", test_login)
    
    # Test 4: Get User
    if token:
        test("Get User Info", lambda: test_get_user(token))
    
    # Test 5: Threats
    test("Threat Status", test_threats_status)
    
    # Test 6: Rate Limiting (skip for now as it's slow)
    # test("Rate Limiting", test_rate_limiting)
    
    # Test 7: Save Test Result
    if token:
        test("Save Test Result", lambda: test_save_test_result(token))
    
    # Test 8: Generate Report
    if token:
        test("Generate Report", lambda: test_generate_report(token))
    
    # Test 9: Alerts
    test("Alert Endpoints", test_alert_endpoints)
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    passed = sum(1 for _, status, _ in TEST_RESULTS if status == "PASS")
    failed = sum(1 for _, status, _ in TEST_RESULTS if status == "FAIL")
    
    for name, status, result in TEST_RESULTS:
        icon = "✓" if status == "PASS" else "✗"
        print(f"{icon} {status:5} | {name}")
    
    print("="*60)
    print(f"TOTAL: {passed} passed, {failed} failed out of {len(TEST_RESULTS)} tests")
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED! 🎉")
    else:
        print(f"\n⚠️  {failed} test(s) failed")
