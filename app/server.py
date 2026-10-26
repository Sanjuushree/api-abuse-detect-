"""HTTP server (stdlib only): ingest API, analytics API and the dashboard."""
import json
import mimetypes
import os
import random
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .detector import Detector
from .storage import Storage
from . import simulator

STATIC = os.path.join(os.path.dirname(__file__), "static")
BUCKET = 5  # seconds per timeline bucket


class Platform:
    def __init__(self, db_path="abuse.db", config=None):
        self.detector = Detector(config)
        self.store = Storage(db_path)
        self.lock = threading.Lock()
        self.timeline = defaultdict(lambda: [0, 0])   # bucket -> [total, flagged]
        self.info = {}                                # client -> latest snapshot
        self.running = {}                             # scenario -> thread
        self.rng = random.Random()
        self.start_time = time.time()

    def ingest(self, ev):
        ev.setdefault("ts", time.time())
        try:
            ev["ts"] = float(ev["ts"])
        except (ValueError, TypeError):
            ev["ts"] = time.time()
        ev["client"] = ev.get("client") or ev.get("api_key") or "ip:" + str(ev.get("ip") or "unknown")
        if not ev.get("path"):
            ev["path"] = "/"
        with self.lock:
            res = self.detector.process(ev)
            self.store.add_event(ev, res)
            b = int(ev["ts"] // BUCKET)
            self.timeline[b][0] += 1
            if res["action"] != "allow":
                self.timeline[b][1] += 1
            st = self.detector.clients.get(ev["client"])
            req_count = len(st.events) if st else 1
            peak_val = st.peak_score if st else res["score"]
            self.info[ev["client"]] = {"client": ev["client"], "score": res["score"], "action": res["action"],
                                       "requests_60s": req_count, "ip": ev.get("ip", ""),
                                       "rules": res["rules"], "peak": peak_val, "last_seen": ev["ts"]}
            for k in [k for k in self.timeline if k < b - 120]:
                del self.timeline[k]
        return {"action": res["action"], "score": res["score"], "rules": res["rules"]}

    def stats(self):
        now = time.time()
        with self.lock:
            cur = int(now // BUCKET)
            tl = [{"t": (cur - i) * BUCKET, "total": self.timeline[cur - i][0] if (cur - i) in self.timeline else 0,
                   "flagged": self.timeline[cur - i][1] if (cur - i) in self.timeline else 0}
                  for i in range(59, -1, -1)]
            rpm = sum(x["total"] for x in tl[-12:])
            active = sum(1 for i in self.info.values() if now - i["last_seen"] < 60)
            blocked = [{"client": c, **b, "remaining": max(0, int(b["until"] - now))}
                       for c, b in list(self.detector.blocked.items()) if b["until"] > now]
        return {"totals": self.store.totals(), "rpm": rpm, "active_clients": active,
                "blocked": blocked, "timeline": tl, "rules": self.store.rule_counts(),
                "top_endpoints": self.store.top_endpoints(now - 300), "running": list(self.running)}

    def clients(self):
        now = time.time()
        with self.lock:
            rows = []
            for i in self.info.values():
                r = dict(i)
                r["blocked"] = self.detector.is_blocked(r["client"], now)
                r["idle"] = int(now - r["last_seen"])
                rows.append(r)
        rows.sort(key=lambda r: (-r["score"], r["idle"]))
        return rows[:25]

    def run_scenario(self, name):
        fn = simulator.SCENARIOS.get(name)
        if not fn or name in self.running:
            return False

        def go():
            try:
                fn(self.ingest, self.rng)
            finally:
                self.running.pop(name, None)
        t = threading.Thread(target=go, daemon=True)
        self.running[name] = t
        t.start()
        return True

    def start_background_traffic(self, rate=3.0):
        def loop():
            while True:
                try:
                    simulator.normal(self.ingest, self.rng)
                    time.sleep(self.rng.expovariate(rate))
                except Exception:
                    time.sleep(1)
        threading.Thread(target=loop, daemon=True).start()

    def reset(self):
        with self.lock:
            self.detector.reset()
            self.store.reset()
            self.timeline.clear()
            self.info.clear()


def make_handler(app):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            try:
                return json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return None

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
            self.end_headers()

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if u.path == "/api/health":
                return self._json({"status": "ok", "uptime_sec": round(time.time() - app.start_time, 1)})
            if u.path == "/api/stats":
                return self._json(app.stats())
            if u.path == "/api/clients":
                return self._json(app.clients())
            if u.path == "/api/alerts":
                return self._json(app.store.alerts(int(q.get("limit", ["40"])[0])))
            if u.path == "/api/scenarios":
                return self._json(list(simulator.SCENARIOS))
            path = "/index.html" if u.path in ("/", "") else u.path
            rel_path = path.lstrip("/")
            f = os.path.normpath(os.path.join(STATIC, rel_path))
            static_norm = os.path.normcase(os.path.abspath(STATIC))
            f_norm = os.path.normcase(os.path.abspath(f))
            if f_norm.startswith(static_norm) and os.path.isfile(f):
                try:
                    with open(f, "rb") as fh:
                        data = fh.read()
                    mime, _ = mimetypes.guess_type(f)
                    if not mime:
                        if f.endswith(".html"):
                            mime = "text/html; charset=utf-8"
                        elif f.endswith(".css"):
                            mime = "text/css; charset=utf-8"
                        elif f.endswith(".js"):
                            mime = "application/javascript; charset=utf-8"
                        elif f.endswith(".json"):
                            mime = "application/json"
                        elif f.endswith(".svg"):
                            mime = "image/svg+xml"
                        else:
                            mime = "application/octet-stream"
                    self.send_response(200)
                    self.send_header("Content-Type", mime)
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    return self.wfile.write(data)
                except Exception as e:
                    return self._json({"error": str(e)}, 500)
            self._json({"error": "not found"}, 404)

        def do_POST(self):
            body = self._body()
            if body is None:
                return self._json({"error": "invalid JSON"}, 400)
            p = urlparse(self.path).path
            if p == "/api/ingest":
                if "path" not in body or not (body.get("client") or body.get("api_key") or body.get("ip")):
                    return self._json({"error": "need path and one of client/api_key/ip"}, 400)
                return self._json(app.ingest(body))
            if p == "/api/simulate":
                return self._json({"started": app.run_scenario(body.get("scenario", ""))})
            if p == "/api/block":
                with app.lock:
                    app.detector.block(body.get("client", ""), reason="manual block")
                return self._json({"ok": True})
            if p == "/api/unblock":
                with app.lock:
                    app.detector.unblock(body.get("client", ""))
                return self._json({"ok": True})
            if p == "/api/reset":
                app.reset()
                return self._json({"ok": True})
            self._json({"error": "not found"}, 404)
    return H


def serve(host="127.0.0.1", port=8000, demo=True, db_path="abuse.db"):
    app = Platform(db_path)
    if demo:
        app.start_background_traffic()
    srv = ThreadingHTTPServer((host, port), make_handler(app))
    print(f"Dashboard:  http://{host}:{port}\nIngest API: POST http://{host}:{port}/api/ingest")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
