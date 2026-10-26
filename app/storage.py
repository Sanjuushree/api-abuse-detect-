import sqlite3
import threading


class Storage:
    def __init__(self, path="abuse.db"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS events(ts REAL, client TEXT, ip TEXT, method TEXT, path TEXT,
            status INT, latency_ms REAL, ua TEXT, action TEXT, score INT);
        CREATE TABLE IF NOT EXISTS alerts(ts REAL, client TEXT, rule TEXT, severity TEXT,
            score INT, detail TEXT);
        CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(ts);
        CREATE INDEX IF NOT EXISTS ix_al_ts ON alerts(ts);
        """)

    def add_event(self, e, res):
        with self.lock:
            self.db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?)",
                (e["ts"], e["client"], e.get("ip"), e.get("method"), e.get("path"),
                 e.get("status"), e.get("latency_ms"), e.get("user_agent"), res["action"], res["score"]))
            for a in res["alerts"]:
                self.db.execute("INSERT INTO alerts VALUES(?,?,?,?,?,?)",
                    (a["ts"], a["client"], a["rule"], a["severity"], a["score"], a["detail"]))
            self.db.commit()

    def alerts(self, limit=50):
        with self.lock:
            cur = self.db.execute("SELECT ts,client,rule,severity,score,detail FROM alerts ORDER BY ts DESC LIMIT ?", (limit,))
            return [dict(zip(("ts", "client", "rule", "severity", "score", "detail"), r)) for r in cur]

    def rule_counts(self):
        with self.lock:
            return dict(self.db.execute("SELECT rule, COUNT(*) FROM alerts GROUP BY rule").fetchall())

    def top_endpoints(self, since, limit=6):
        with self.lock:
            cur = self.db.execute("SELECT path, COUNT(*) c FROM events WHERE ts>? GROUP BY path ORDER BY c DESC LIMIT ?", (since, limit))
            return [{"path": p, "count": c} for p, c in cur]

    def totals(self):
        with self.lock:
            t = self.db.execute("SELECT COUNT(*), SUM(CASE WHEN action='block' THEN 1 ELSE 0 END), SUM(CASE WHEN action='throttle' THEN 1 ELSE 0 END) FROM events").fetchone()
            cur_a = self.db.execute("SELECT COUNT(*) FROM alerts").fetchone()
            a = cur_a[0] if cur_a else 0
        return {"events": (t[0] if t and t[0] is not None else 0),
                "blocked": (t[1] if t and t[1] is not None else 0),
                "throttled": (t[2] if t and t[2] is not None else 0),
                "alerts": a or 0}

    def reset(self):
        with self.lock:
            self.db.executescript("DELETE FROM events; DELETE FROM alerts;")
            self.db.commit()
