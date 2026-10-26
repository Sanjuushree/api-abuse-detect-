"""Start the platform:  python run.py [--port 8000] [--no-demo] [--fresh]"""
import argparse
import os

from app.server import serve

ap = argparse.ArgumentParser()
ap.add_argument("--host", default="127.0.0.1")
ap.add_argument("--port", type=int, default=8000)
ap.add_argument("--no-demo", action="store_true", help="disable the built-in normal-traffic generator")
ap.add_argument("--fresh", action="store_true", help="delete the old database first")
a = ap.parse_args()
if a.fresh and os.path.exists("abuse.db"):
    os.remove("abuse.db")
serve(a.host, a.port, demo=not a.no_demo)
