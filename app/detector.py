"""Detection engine: sliding-window rules + peer-based statistical anomaly scoring.

Each event is: {ts, client, ip, method, path, status, latency_ms, user_agent}
`client` is the API key (or "ip:<addr>" if no key). Every event returns a risk score,
any new alerts, and an action: allow | throttle | block.
"""
import re
import statistics
import time
from collections import deque

DEFAULT_CONFIG = {
    "window_sec": 60,
    "burst_window_sec": 10,
    "burst_threshold": 60,          # requests in 10s
    "peer_min_requests": 40,        # min 60s requests before peer comparison
    "peer_z_threshold": 3.5,        # modified z-score (median/MAD)
    "auth_fail_threshold": 10,      # 401/403 on auth endpoints in 60s
    "enum_distinct_paths": 20,      # distinct normalised endpoints in 60s
    "enum_404_ratio": 0.4,
    "idscan_distinct_ids": 15,
    "bot_min_requests": 20,
    "bot_cv_threshold": 0.12,       # coefficient of variation of inter-arrival gaps
    "key_share_ips": 4,
    "error_ratio": 0.6,
    "error_min_requests": 20,
    "throttle_score": 40,
    "block_score": 80,
    "block_seconds": 300,
    "alert_cooldown_sec": 30,
}

WEIGHTS = {
    "RATE_BURST": 35, "RATE_ANOMALY": 25, "CREDENTIAL_STUFFING": 55,
    "ENDPOINT_ENUMERATION": 40, "ID_SCANNING": 40, "BOT_TIMING": 25,
    "KEY_SHARING": 40, "SUSPICIOUS_UA": 10, "HIGH_ERROR_RATE": 20,
}


def severity(score):
    return "high" if score >= 60 else "medium" if score >= 30 else "low"


BAD_UA = ("sqlmap", "nikto", "nmap", "masscan", "python-requests", "curl/",
          "go-http-client", "scrapy", "wget", "httpclient", "libwww")
AUTH_HINTS = ("login", "auth", "token", "signin", "password", "oauth")
_ID = re.compile(r"/(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27})(?=/|$)")
_TRAILING_ID = re.compile(r"/(\d+)/?$")


def normalize(path):
    """/api/users/42?x=1 -> /api/users/{id}"""
    return _ID.sub("/{id}", path.split("?")[0])


class ClientState:
    __slots__ = ("events", "last_alert", "peak_score")

    def __init__(self):
        self.events = deque()   # (ts, ip, norm_path, raw_path, status, ua)
        self.last_alert = {}
        self.peak_score = 0


class Detector:
    def __init__(self, config=None):
        self.cfg = dict(DEFAULT_CONFIG, **(config or {}))
        self.clients = {}
        self.blocked = {}       # client -> {"until", "reason", "since"}

    # ---------- blocking ----------
    def block(self, client, reason="manual", seconds=None, now=None):
        now = now if now is not None else time.time()
        self.blocked[client] = {"until": now + (seconds or self.cfg["block_seconds"]),
                                "reason": reason, "since": now}

    def unblock(self, client):
        self.blocked.pop(client, None)

    def is_blocked(self, client, now=None):
        now = now if now is not None else time.time()
        b = self.blocked.get(client)
        if not b:
            return False
        if b["until"] < now:
            del self.blocked[client]
            return False
        return True

    def reset(self):
        self.clients.clear()
        self.blocked.clear()

    # ---------- main entry ----------
    def process(self, ev):
        now = ev.get("ts")
        now = float(now) if now is not None else time.time()
        c = str(ev.get("client") or ev.get("api_key") or "ip:" + str(ev.get("ip") or "unknown"))
        st = self.clients.setdefault(c, ClientState())
        path = str(ev.get("path") or "/")
        raw_status = ev.get("status")
        try:
            status = int(raw_status) if raw_status is not None else 200
        except (ValueError, TypeError):
            status = 200
        ua = str(ev.get("user_agent") or ev.get("ua") or "")
        ip = str(ev.get("ip") or "")

        st.events.append((now, ip, normalize(path), path, status, ua))
        cut = now - self.cfg["window_sec"]
        while st.events and st.events[0][0] < cut:
            st.events.popleft()

        findings = self._evaluate(c, st, now)
        score = min(100, sum(w for _, w, _ in findings))
        st.peak_score = max(st.peak_score, score)

        alerts = []
        for rule, weight, detail in findings:
            if now - st.last_alert.get(rule, 0) >= self.cfg["alert_cooldown_sec"]:
                st.last_alert[rule] = now
                alerts.append({"ts": now, "client": c, "rule": rule, "weight": weight,
                               "severity": severity(weight), "score": score, "detail": detail})

        if self.is_blocked(c, now):
            action = "block"
        elif score >= self.cfg["block_score"]:
            self.block(c, reason=", ".join(r for r, _, _ in findings), now=now)
            action = "block"
        elif score >= self.cfg["throttle_score"]:
            action = "throttle"
        else:
            action = "allow"
        return {"score": score, "action": action, "alerts": alerts,
                "rules": [r for r, _, _ in findings]}

    # ---------- rules ----------
    def _evaluate(self, c, st, now):
        cfg, ev, out = self.cfg, st.events, []
        n = len(ev)

        burst = sum(1 for e in ev if e[0] >= now - cfg["burst_window_sec"])
        if burst >= cfg["burst_threshold"]:
            out.append(("RATE_BURST", WEIGHTS["RATE_BURST"], f"{burst} requests in {cfg['burst_window_sec']}s"))

        if n >= cfg["peer_min_requests"] and len(self.clients) >= 5:
            counts = [len(s.events) for s in self.clients.values() if s.events]
            if len(counts) >= 5:
                med = statistics.median(counts)
                mad = statistics.median(abs(x - med) for x in counts) or 1.0
                z = 0.6745 * (n - med) / mad
                if z >= cfg["peer_z_threshold"]:
                    out.append(("RATE_ANOMALY", WEIGHTS["RATE_ANOMALY"],
                                f"{n} req/min vs peer median {med:.0f} (z={z:.1f})"))

        fails = sum(1 for e in ev if e[4] in (401, 403) and any(h in e[2].lower() for h in AUTH_HINTS))
        if fails >= cfg["auth_fail_threshold"]:
            out.append(("CREDENTIAL_STUFFING", WEIGHTS["CREDENTIAL_STUFFING"],
                        f"{fails} failed auth attempts in {cfg['window_sec']}s"))

        distinct = {e[2] for e in ev}
        nf = sum(1 for e in ev if e[4] == 404)
        if len(distinct) >= cfg["enum_distinct_paths"] and n and nf / n >= cfg["enum_404_ratio"]:
            out.append(("ENDPOINT_ENUMERATION", WEIGHTS["ENDPOINT_ENUMERATION"],
                        f"{len(distinct)} distinct endpoints probed, {nf / n:.0%} returned 404"))

        ids = {}
        for e in ev:
            m = _TRAILING_ID.search(e[3].split("?")[0])
            if m:
                ids.setdefault(e[2], set()).add(int(m.group(1)))
        for pat, s in ids.items():
            if len(s) >= cfg["idscan_distinct_ids"]:
                out.append(("ID_SCANNING", WEIGHTS["ID_SCANNING"], f"{len(s)} distinct object IDs read under {pat}"))
                break

        if n >= cfg["bot_min_requests"]:
            ts = sorted(e[0] for e in ev)
            gaps = [b - a for a, b in zip(ts, ts[1:])]
            mean = sum(gaps) / len(gaps) if gaps else 0
            if mean > 0:
                cv = statistics.pstdev(gaps) / mean
                if cv < cfg["bot_cv_threshold"]:
                    out.append(("BOT_TIMING", WEIGHTS["BOT_TIMING"],
                                f"machine-like spacing: {mean * 1000:.0f}ms gaps, CV={cv:.2f}"))

        ips = {e[1] for e in ev if e[1]}
        if not c.startswith("ip:") and len(ips) >= cfg["key_share_ips"]:
            out.append(("KEY_SHARING", WEIGHTS["KEY_SHARING"],
                        f"one API key used from {len(ips)} IPs in {cfg['window_sec']}s"))

        ua = ev[-1][5].lower()
        if not ua or any(b in ua for b in BAD_UA):
            out.append(("SUSPICIOUS_UA", WEIGHTS["SUSPICIOUS_UA"], f"user-agent: {ev[-1][5] or '(empty)'}"))

        errs = sum(1 for e in ev if e[4] >= 400)
        if n >= cfg["error_min_requests"] and errs / n >= cfg["error_ratio"]:
            out.append(("HIGH_ERROR_RATE", WEIGHTS["HIGH_ERROR_RATE"],
                        f"{errs / n:.0%} of {n} requests returned errors"))
        return out
