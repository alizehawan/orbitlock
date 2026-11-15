"""OrbitLock ground-station console.  python run.py [--secure] [--port 5000]"""
import argparse
import logging

from orbitlock.web.app import create_app

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--secure", action="store_true", help="start with the secured link")
    ap.add_argument("--port", type=int, default=5000)
    a = ap.parse_args()
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    print("Training anomaly detector and starting simulation…")
    app = create_app(secure=a.secure)
    print(f"\n  OrbitLock console → http://127.0.0.1:{a.port}\n")
    app.run(host="127.0.0.1", port=a.port, threaded=True)
