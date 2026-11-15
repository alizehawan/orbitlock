"""Flask ground-station console."""
from __future__ import annotations

import json
import threading
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, send_from_directory

from .. import evaluate as EV
from .. import messages as M
from ..sim import Simulation, shared_detector


def create_app(secure: bool = False) -> Flask:
    app = Flask(__name__)
    shared_detector()  # train once at start-up
    sim_box = {"sim": Simulation(secure=secure)}
    ev = {"running": False, "msgs": [], "done": False, "error": None}
    lock = threading.Lock()

    def sim() -> Simulation:
        return sim_box["sim"]

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/state")
    def state():
        return jsonify(sim().snapshot())

    @app.post("/api/secure")
    def set_secure():
        want = bool(request.json.get("secure"))
        ok = sim().set_secure(want)
        return jsonify(ok=ok, secure=want)

    @app.post("/api/command")
    def command():
        d = request.json
        c = d.get("cmd")
        g = sim().ground
        try:
            if c == "mode":
                cid = g.send_command(M.OP_SET_MODE, int(d["mode"]))
            elif c == "attitude":
                cid = g.send_command(M.OP_ATTITUDE, float(d["roll"]), float(d["pitch"]), float(d["yaw"]))
            elif c == "payload":
                cid = g.send_command(M.OP_PAYLOAD, 1 if d["on"] else 0)
            elif c == "downlink":
                cid = g.send_command(M.OP_DOWNLINK, max(1, min(int(d.get("kb", 8)), 64)))
            elif c == "burn":
                cid = g.send_command(M.OP_BURN, float(d["dv"]))
            elif c == "ping":
                cid = g.send_command(M.OP_PING)
            else:
                return jsonify(ok=False, error="unknown command"), 400
        except (KeyError, ValueError, TypeError) as e:
            return jsonify(ok=False, error=str(e)), 400
        if cid is None:
            return jsonify(ok=False, error="link not established"), 409
        return jsonify(ok=True, cmd_id=cid)

    @app.post("/api/link")
    def link():
        a = request.json.get("action")
        g = sim().ground
        if a == "rotate":
            return jsonify(ok=g.rotate_keys())
        if a == "rekey":
            return jsonify(ok=g.emergency_rekey())
        if a == "auto":
            g.auto_rotate = bool(request.json.get("on"))
            return jsonify(ok=True)
        return jsonify(ok=False), 400

    @app.post("/api/attack")
    def attack():
        d = request.json
        t = d.get("type")
        at = sim().attacker
        if t == "replay":
            r = at.replay()
            return jsonify(ok=r is not None, error=None if r else "nothing captured yet")
        if t == "forge":
            op = d.get("op", "burn")
            if op == "burn":
                at.forge_command(M.OP_BURN, 25.0)
            elif op == "safe":
                at.forge_command(M.OP_SET_MODE, 0)
            elif op == "payload_off":
                at.forge_command(M.OP_PAYLOAD, 0)
            return jsonify(ok=True)
        if t == "downgrade":
            at.forge_clear_command(M.OP_BURN, 25.0)
            return jsonify(ok=True)
        if t == "tamper":
            at.arm_tamper(1)
            return jsonify(ok=True)
        if t == "spoof_tlm":
            at.forge_telemetry(battery=100.0, temp=20.0)
            return jsonify(ok=True)
        if t == "drop":
            at.set_drop(up=bool(d.get("up")), down=bool(d.get("down")))
            return jsonify(ok=True)
        if t == "flood":
            if d.get("on", True):
                at.flood(count=2400, rate=300.0)
            else:
                at.stop_flood()
            return jsonify(ok=True)
        return jsonify(ok=False, error="unknown attack"), 400

    @app.post("/api/fault")
    def fault():
        kind = request.json.get("kind")
        try:
            sim().satellite.inject_fault(kind)
        except ValueError:
            return jsonify(ok=False), 400
        return jsonify(ok=True)

    @app.post("/api/reset")
    def reset():
        sim().reset_counters()
        return jsonify(ok=True)

    # ---- evaluation ------------------------------------------------------
    def _run_eval():
        try:
            EV.run_all(trials=20, progress=lambda m: ev["msgs"].append(m))
            ev["error"] = None
        except Exception as e:  # pragma: no cover
            ev["error"] = repr(e)
        finally:
            ev["running"], ev["done"] = False, True

    @app.post("/api/evaluate")
    def evaluate():
        with lock:
            if ev["running"]:
                return jsonify(ok=False, error="already running"), 409
            ev.update(running=True, msgs=[], done=False, error=None)
        threading.Thread(target=_run_eval, daemon=True).start()
        return jsonify(ok=True)

    @app.get("/api/evaluate/status")
    def evaluate_status():
        return jsonify(running=ev["running"], msgs=ev["msgs"], done=ev["done"], error=ev["error"])

    @app.get("/api/results")
    def results():
        p = EV.RESULTS / "results.json"
        if not p.exists():
            return jsonify(available=False)
        data = json.loads(p.read_text())
        data["anomaly"].pop("trace", None)
        data["available"] = True
        return jsonify(data)

    @app.get("/api/capture.pcap")
    def capture_pcap():
        """Wire capture (incl. injected frames) as a Scapy-written pcap - open in Wireshark."""
        return Response(sim().attacker.export_pcap(), mimetype="application/vnd.tcpdump.pcap",
                        headers={"Content-Disposition": "attachment; filename=orbitlock_capture.pcap"})

    @app.get("/results/<path:name>")
    def result_file(name):
        return send_from_directory(EV.RESULTS, name)

    return app
