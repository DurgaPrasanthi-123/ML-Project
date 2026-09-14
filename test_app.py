"""
Automated Verification Test Suite for Phishing Website Detection System.

Tests:
1. Web routes (/, /detector, /about, /how-it-works)
2. API endpoint /api/metrics
3. API endpoint /predict with Legitimate URLs
4. API endpoint /predict with Phishing URLs
5. Input validation and edge-case handling (empty URLs, bad JSON, invalid schemes)
"""

import sys
import json
from app import app

def run_tests():
    client = app.test_client()
    passed = 0
    total = 0

    def assert_test(name, condition, details=""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f"  [PASS] {name}")
        else:
            print(f"  [FAIL] {name} - {details}")

    print("\n" + "="*60)
    print(" Running Phishing Detection System Automated Tests")
    print("="*60 + "\n")

    # 1. Test Web Routes
    print("Testing Web Page Routes...")
    for route in ["/", "/detector", "/about", "/how-it-works"]:
        res = client.get(route)
        assert_test(f"GET {route} returns HTTP 200", res.status_code == 200, f"Got status {res.status_code}")

    # 2. Test Metrics API
    print("\nTesting Metrics API...")
    res = client.get("/api/metrics")
    assert_test("GET /api/metrics returns HTTP 200", res.status_code == 200)
    data = json.loads(res.data.decode("utf-8"))
    assert_test("Metrics response has status 'success'", data.get("status") == "success")
    assert_test("Metrics contains 'best_model'", "best_model" in data.get("metrics", {}))
    assert_test("Metrics contains 'dataset'", "dataset" in data.get("metrics", {}))

    # 3. Test Prediction API - Legitimate
    print("\nTesting Predictions - Legitimate URLs...")
    legit_test_urls = [
        "https://www.google.com/search?q=cybersecurity",
        "https://en.wikipedia.org/wiki/Machine_learning",
        "https://docs.python.org/3/library/urllib.parse.html"
    ]
    for url in legit_test_urls:
        res = client.post("/predict", json={"url": url})
        assert_test(f"POST /predict with '{url[:35]}...' returns HTTP 200", res.status_code == 200)
        p_data = json.loads(res.data.decode("utf-8"))
        assert_test(f"Prediction is 'Legitimate' for {url[:30]}", p_data.get("prediction") == "Legitimate", f"Got: {p_data.get('prediction')}")
        assert_test("Confidence >= 75%", p_data.get("confidence", 0) >= 75.0, f"Got: {p_data.get('confidence')}")

    # 4. Test Prediction API - Phishing
    print("\nTesting Predictions - Phishing URLs...")
    phish_test_urls = [
        "http://192.168.1.105:8080/paypal-security/login.php",
        "http://login.paypal.com.verify-billing-secure.xyz/signin.php",
        "http://verify-chase-account-security-alert.net/banking/auth.php"
    ]
    for url in phish_test_urls:
        res = client.post("/predict", json={"url": url})
        assert_test(f"POST /predict with '{url[:35]}...' returns HTTP 200", res.status_code == 200)
        p_data = json.loads(res.data.decode("utf-8"))
        assert_test(f"Prediction is 'Phishing' for {url[:30]}", p_data.get("prediction") == "Phishing", f"Got: {p_data.get('prediction')}")
        assert_test("Confidence >= 75%", p_data.get("confidence", 0) >= 75.0, f"Got: {p_data.get('confidence')}")

    # 5. Test Error Handling
    print("\nTesting Error Handling & Input Validation...")
    # Empty URL
    res = client.post("/predict", json={"url": ""})
    assert_test("Empty URL returns HTTP 400", res.status_code == 400)
    
    # Missing 'url' key
    res = client.post("/predict", json={"other_key": "test"})
    assert_test("Missing 'url' key returns HTTP 400", res.status_code == 400)

    # Malformed non-JSON
    res = client.post("/predict", data="not json", content_type="text/plain")
    assert_test("Non-JSON payload returns HTTP 400", res.status_code == 400)

    # Forbidden scheme
    res = client.post("/predict", json={"url": "javascript:alert(1)"})
    assert_test("Dangerous scheme javascript: returns HTTP 400", res.status_code == 400)

    print("\n" + "="*60)
    print(f" Summary: {passed}/{total} tests passed ({round(passed/total*100, 1)}%)")
    print("="*60 + "\n")

    if passed == total:
        print("[SUCCESS] All system integration tests passed flawlessly!")
        return 0
    else:
        print("[ERROR] Some tests failed.")
        return 1

if __name__ == "__main__":
    sys.exit(run_tests())
