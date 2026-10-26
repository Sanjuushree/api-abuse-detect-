"""Start the platform:  python run.py [--port 8000] [--no-demo] [--fresh]"""
import argparse
import os

from app.server import serve

default_host = os.environ.get("HOST", "0.0.0.0")
default_port = int(os.environ.get("PORT", "8000"))

ap = argparse.ArgumentParser()
ap.add_argument("--host", default=default_host)
ap.add_argument("--port", type=int, default=default_port)
ap.add_argument("--no-demo", action="store_true", help="disable the built-in normal-traffic generator")
ap.add_argument("--fresh", action="store_true", help="delete the old database first")
a = ap.parse_args()
if a.fresh and os.path.exists("abuse.db"):
    os.remove("abuse.db")
serve(a.host, a.port, demo=not a.no_demo)
