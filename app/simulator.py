"""Traffic simulator: normal users + 6 attack scenarios. `emit(event_dict)` is any callable."""
import random
import time

UAS = ["Mozilla/5.0 (Windows NT 10.0) Chrome/126.0", "Mozilla/5.0 (Macintosh) Safari/17.4",
       "Mozilla/5.0 (Linux; Android 14) Mobile Chrome/126.0", "MyApp-iOS/4.2 CFNetwork"]
NORMAL_PATHS = ["/api/products", "/api/products/{n}", "/api/cart", "/api/orders", "/api/profile", "/api/search?q=shoes"]
USERS = [f"key_user{i:02d}" for i in range(1, 9)]


def _ip(rng):
    return f"{rng.choice([49, 103, 117, 122])}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"


def _ev(client, ip, path, status, ua, method="GET"):
    return {"ts": time.time(), "client": client, "ip": ip, "method": method, "path": path,
            "status": status, "latency_ms": round(random.uniform(20, 180), 1), "user_agent": ua}


def normal(emit, rng):
    """One normal request from a random legitimate user."""
    i = rng.randrange(len(USERS))
    p = rng.choice(NORMAL_PATHS).replace("{n}", str(rng.randint(1, 500)))
    emit(_ev(USERS[i], f"49.37.{i + 10}.{i + 20}", p, rng.choices([200, 201, 304, 404], [80, 8, 8, 4])[0], UAS[i % len(UAS)]))


def burst(emit, rng):
    ip = _ip(rng)
    for _ in range(140):
        emit(_ev("key_burst_77", ip, "/api/search?q=" + str(rng.randint(1, 9999)), 200, UAS[0]))
        time.sleep(rng.uniform(0.01, 0.08))


def credential_stuffing(emit, rng):
    ip = _ip(rng)
    for _ in range(40):
        emit(_ev("ip:" + ip, ip, "/api/auth/login", 401, "python-requests/2.31", "POST"))
        time.sleep(rng.uniform(0.05, 0.2))


def enumeration(emit, rng):
    ip = _ip(rng)
    words = ["admin", "backup", "config", ".env", "debug", "internal", "v2", "users", "export", "swagger",
             "graphql", "actuator", "console", "db", "dump", "test", "old", "private", "keys", "secrets",
             "metrics", "health", "status", "api-docs", "phpinfo", "shell", "upload", "logs", "tmp", "git"]
    for w in words:
        emit(_ev("ip:" + ip, ip, "/" + w, 404, "Mozilla/5.0 (compatible; scanner)"))
        time.sleep(rng.uniform(0.05, 0.15))


def id_scanning(emit, rng):
    ip = _ip(rng)
    for i in range(1000, 1040):
        emit(_ev("key_scraper_12", ip, f"/api/users/{i}", 200, UAS[1]))
        time.sleep(rng.uniform(0.05, 0.25))


def key_sharing(emit, rng):
    for _ in range(18):
        emit(_ev("key_leaked_55", _ip(rng), "/api/orders", 200, rng.choice(UAS)))
        time.sleep(rng.uniform(0.1, 0.3))


def bot_timing(emit, rng):
    ip = _ip(rng)
    for _ in range(40):
        emit(_ev("key_cron_bot", ip, "/api/products", 200, "Go-http-client/2.0"))
        time.sleep(0.2)


SCENARIOS = {"burst": burst, "credential_stuffing": credential_stuffing, "enumeration": enumeration,
             "id_scanning": id_scanning, "key_sharing": key_sharing, "bot_timing": bot_timing}
