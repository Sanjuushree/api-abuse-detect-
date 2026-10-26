"""Shows how a real API would use the platform: report each request, obey the verdict.

Run the platform first (python run.py), then:  python sample_client.py
Integrate by calling report() from your own middleware (Flask/FastAPI/Express etc.).
"""
import json
import time
import urllib.request

PLATFORM = "http://127.0.0.1:8000/api/ingest"


def report(api_key, ip, method, path, status, user_agent, latency_ms=0):
    data = json.dumps({"client": api_key, "ip": ip, "method": method, "path": path,
                       "status": status, "user_agent": user_agent, "latency_ms": latency_ms}).encode()
    req = urllib.request.Request(PLATFORM, data, {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=2))


if __name__ == "__main__":
    for i in range(1, 31):
        v = report("key_demo_client", "10.0.0.5", "GET", f"/api/users/{i}", 200, "curl/8.0")
        print(i, v)
        if v["action"] == "block":
            print("-> your API should now return HTTP 429/403 for this client")
            break
        time.sleep(0.05)
