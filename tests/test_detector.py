import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.detector import Detector, normalize

UA = "Mozilla/5.0 Chrome"


def ev(t, client="k1", ip="1.1.1.1", path="/api/x", status=200, ua=UA):
    return {"ts": t, "client": client, "ip": ip, "path": path, "status": status, "user_agent": ua}


def run(d, events):
    rules, last = set(), None
    for e in events:
        last = d.process(e)
        rules |= set(last["rules"])
    return rules, last


class T(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize("/api/users/42?x=1"), "/api/users/{id}")

    def test_normal_user_clean(self):
        import random
        r = random.Random(1)
        t, evs = 1000.0, []
        for _ in range(20):
            t += r.uniform(1, 4)
            evs.append(ev(t, path=r.choice(["/a", "/b", "/c"])))
        rules, last = run(Detector(), evs)
        self.assertEqual(rules, set())
        self.assertEqual(last["action"], "allow")

    def test_burst(self):
        rules, _ = run(Detector(), [ev(1000 + i * 0.05) for i in range(80)])
        self.assertIn("RATE_BURST", rules)

    def test_credential_stuffing_blocks(self):
        evs = [ev(1000 + i * 0.3, client="ip:9.9.9.9", path="/api/auth/login", status=401, ua="python-requests/2") for i in range(25)]
        rules, last = run(Detector(), evs)
        self.assertIn("CREDENTIAL_STUFFING", rules)
        self.assertEqual(last["action"], "block")

    def test_enumeration(self):
        evs = [ev(1000 + i, path=f"/p{i}", status=404) for i in range(25)]
        rules, _ = run(Detector(), evs)
        self.assertIn("ENDPOINT_ENUMERATION", rules)

    def test_id_scanning(self):
        evs = [ev(1000 + i * 0.5, path=f"/api/users/{i}") for i in range(20)]
        rules, _ = run(Detector(), evs)
        self.assertIn("ID_SCANNING", rules)

    def test_key_sharing(self):
        evs = [ev(1000 + i, ip=f"5.5.5.{i}") for i in range(6)]
        rules, _ = run(Detector(), evs)
        self.assertIn("KEY_SHARING", rules)

    def test_bot_timing(self):
        evs = [ev(1000 + i * 0.5) for i in range(25)]
        rules, _ = run(Detector(), evs)
        self.assertIn("BOT_TIMING", rules)

    def test_block_expires(self):
        d = Detector({"block_seconds": 10})
        d.block("k1", now=1000)
        self.assertEqual(d.process(ev(1005))["action"], "block")
        self.assertNotEqual(d.process(ev(1020))["action"], "block")

    def test_robust_event_parsing(self):
        d = Detector()
        # Test event with missing/None status and empty user agent
        res = d.process({"client": "k_robust", "status": None, "user_agent": None, "path": None})
        self.assertIn(res["action"], ["allow", "throttle", "block"])
        self.assertTrue(d.is_blocked("k_robust") in [True, False])


if __name__ == "__main__":
    unittest.main()
