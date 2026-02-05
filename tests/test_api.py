#!/usr/bin/env python3
"""Guardian Portal Full Test Suite"""
import json
import urllib.request
import urllib.error
import http.cookiejar
import sys

BASE = "http://david:8080"
PASS = "guardian123"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    END = '\033[0m'

def ok(msg): print(f"{Colors.GREEN}[PASS]{Colors.END} {msg}")
def fail(msg): print(f"{Colors.RED}[FAIL]{Colors.END} {msg}")
def warn(msg): print(f"{Colors.YELLOW}[WARN]{Colors.END} {msg}")

class TestClient:
    def __init__(self):
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
    
    def get(self, path):
        try:
            req = urllib.request.Request(f"{BASE}{path}")
            resp = self.opener.open(req, timeout=10)
            return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())
        except Exception as e:
            return 0, {"error": str(e)}
    
    def post(self, path, data=None):
        try:
            body = json.dumps(data).encode() if data else b'{}'
            req = urllib.request.Request(
                f"{BASE}{path}",
                data=body,
                headers={"Content-Type": "application/json"},
                method='POST'
            )
            resp = self.opener.open(req, timeout=10)
            return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())
        except Exception as e:
            return 0, {"error": str(e)}

def run_tests():
    client = TestClient()
    results = {"passed": 0, "failed": 0, "warnings": 0}
    
    print("="*50)
    print("Guardian Portal Test Suite")
    print("="*50 + "\n")
    
    # Test 1: Auth status without login
    print("--- Authentication Tests ---")
    code, data = client.get("/api/auth/status")
    if code == 200 and data.get("authenticated") == False:
        ok("Unauthenticated status check")
        results["passed"] += 1
    else:
        fail(f"Auth status: {data}")
        results["failed"] += 1
    
    # Test 2: Protected endpoint without auth
    code, data = client.get("/api/vpn/config")
    if code == 401:
        ok("Protected endpoint blocks unauthenticated access")
        results["passed"] += 1
    else:
        fail(f"Protected endpoint accessible without auth: {code}")
        results["failed"] += 1
    
    # Test 3: Wrong password
    code, data = client.post("/api/auth/login", {"password": "wrongpassword"})
    if code == 401:
        ok("Wrong password rejected")
        results["passed"] += 1
    else:
        fail(f"Wrong password not rejected: {code}")
        results["failed"] += 1
    
    # Test 4: Login
    code, data = client.post("/api/auth/login", {"password": PASS})
    if code == 200 and data.get("success"):
        ok("Login successful")
        results["passed"] += 1
    else:
        fail(f"Login failed: {data}")
        results["failed"] += 1
        return results  # Can't continue without login
    
    # Test 5: Auth status after login
    code, data = client.get("/api/auth/status")
    if code == 200 and data.get("authenticated") == True:
        ok("Authenticated status check")
        results["passed"] += 1
    else:
        fail(f"Auth status after login: {data}")
        results["failed"] += 1
    
    print("\n--- System Tests ---")
    
    # Test 6: System status
    code, data = client.get("/api/status")
    if code == 200:
        checks = ["uptime", "cpu_temp_c", "memory", "disk", "load_avg"]
        missing = [c for c in checks if c not in data]
        if not missing:
            ok(f"System status: {data['uptime']}, {data['cpu_temp_c']}°C")
            results["passed"] += 1
        else:
            warn(f"System status missing fields: {missing}")
            results["warnings"] += 1
    else:
        fail(f"System status: {code}")
        results["failed"] += 1
    
    print("\n--- VPN Tests ---")
    
    # Test 7: VPN status
    code, data = client.get("/api/vpn/status")
    if code == 200:
        if "active" in data:
            status = "Connected" if data["active"] else "Disconnected"
            ok(f"VPN status: {status}")
            if data.get("public_ip"):
                ok(f"  Public IP: {data['public_ip']}")
            results["passed"] += 1
        else:
            fail(f"VPN status missing 'active' field")
            results["failed"] += 1
    else:
        fail(f"VPN status: {code}")
        results["failed"] += 1
    
    # Test 8: VPN config
    code, data = client.get("/api/vpn/config")
    if code == 200:
        ok(f"VPN config: endpoint={data.get('endpoint', 'N/A')}")
        results["passed"] += 1
    else:
        fail(f"VPN config: {code} - {data}")
        results["failed"] += 1
    
    print("\n--- WiFi Tests ---")
    
    # Test 9: AP status
    code, data = client.get("/api/wifi/ap")
    if code == 200:
        ok(f"AP status: SSID={data.get('ssid')}, clients={data.get('client_count')}")
        results["passed"] += 1
    else:
        fail(f"AP status: {code}")
        results["failed"] += 1
    
    # Test 10: Uplink status
    code, data = client.get("/api/wifi/uplink")
    if code == 200:
        connected = "Connected" if data.get("connected") else "Disconnected"
        ok(f"Uplink: {connected} to {data.get('ssid', 'N/A')}")
        results["passed"] += 1
    else:
        fail(f"Uplink status: {code}")
        results["failed"] += 1
    
    print("\n--- Logs Test ---")
    
    # Test 11: Logs
    code, data = client.get("/api/logs?service=guardian-portal&lines=5")
    if code == 200 and "lines" in data:
        ok(f"Logs endpoint: {len(data['lines'])} lines returned")
        results["passed"] += 1
    else:
        fail(f"Logs: {code}")
        results["failed"] += 1
    
    # Test 12: Invalid service
    code, data = client.get("/api/logs?service=invalid-service")
    if code == 400:
        ok("Invalid service rejected")
        results["passed"] += 1
    else:
        fail(f"Invalid service not rejected: {code}")
        results["failed"] += 1
    
    print("\n--- Logout Test ---")
    
    # Test 13: Logout
    code, data = client.post("/api/auth/logout")
    if code == 200:
        ok("Logout successful")
        results["passed"] += 1
    else:
        fail(f"Logout: {code} - {data}")
        results["failed"] += 1
    
    # Test 14: Verify logged out
    code, data = client.get("/api/auth/status")
    if code == 200 and data.get("authenticated") == False:
        ok("Verified logged out")
        results["passed"] += 1
    else:
        fail(f"Still authenticated after logout")
        results["failed"] += 1
    
    # Test 15: Protected endpoint after logout
    code, data = client.get("/api/vpn/config")
    if code == 401:
        ok("Protected endpoint blocked after logout")
        results["passed"] += 1
    else:
        fail(f"Protected endpoint accessible after logout: {code}")
        results["failed"] += 1
    
    print("\n" + "="*50)
    total = results['passed'] + results['failed']
    print(f"Results: {results['passed']}/{total} passed, {results['failed']} failed, {results['warnings']} warnings")
    print("="*50)
    
    return results

if __name__ == "__main__":
    results = run_tests()
    sys.exit(1 if results["failed"] > 0 else 0)


def run_rate_limit_test():
    """Test rate limiting separately (destructive test)."""
    print("\n" + "="*50)
    print("Rate Limit Test (requires service restart after)")
    print("="*50 + "\n")

    client = TestClient()
    results = {"passed": 0, "failed": 0}

    # Make 5 failed attempts
    print("Making 5 failed login attempts...")
    for i in range(5):
        code, _ = client.post("/api/auth/login", {"password": "wrong"})
        if code != 401:
            fail(f"Attempt {i+1} returned {code}, expected 401")
            results["failed"] += 1
            return results

    ok("5 failed attempts returned 401")
    results["passed"] += 1

    # 6th attempt should be rate limited
    code, data = client.post("/api/auth/login", {"password": "wrong"})
    if code == 429:
        ok("6th attempt rate limited (429)")
        results["passed"] += 1
    else:
        fail(f"6th attempt returned {code}, expected 429")
        results["failed"] += 1

    # Even correct password should be rate limited
    code, data = client.post("/api/auth/login", {"password": "guardian123"})
    if code == 429:
        ok("Correct password also rate limited")
        results["passed"] += 1
    else:
        fail(f"Correct password not rate limited: {code}")
        results["failed"] += 1

    print(f"\nRate limit test: {results['passed']} passed, {results['failed']} failed")
    print("Note: Restart service to clear rate limits")
    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--rate-limit":
        results = run_rate_limit_test()
    else:
        results = run_tests()
    sys.exit(1 if results["failed"] > 0 else 0)
