"""Wires ground <-> attacker <-> satellite over local UDP and keeps ground-truth impact stats."""
from __future__ import annotations

import hashlib
import socket
import threading
import time
from collections import deque
from typing import Optional

from . import messages as M
from . import protocol as P
from .anomaly import AnomalyDetector, LiveDetector
from .attacker import Attacker
from .ground import GroundStation
from .satellite import Satellite

SCID = 0x1A2B
DEFAULT_PSK = hashlib.sha256(b"orbitlock demo pre-launch long-term key").digest()  # stand-in for a key loaded before launch

_shared_detector: Optional[AnomalyDetector] = None
_det_lock = threading.Lock()


def shared_detector() -> AnomalyDetector:
    global _shared_detector
    with _det_lock:
        if _shared_detector is None:
            d = AnomalyDetector()
            d.train()
            _shared_detector = d
        return _shared_detector


def _udp() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    return s


class Simulation:
    """Owns all nodes. Ground truth ("impact") is computed here, never inside the protocol."""

    def __init__(self, secure: bool = False, warp: float = 60.0, seed: Optional[int] = None,
                 with_detector: bool = True, psk: Optional[bytes] = None):
        self.log = P.SecurityLog()
        self.psk = psk or DEFAULT_PSK
        g_sock, s_sock = _udp(), _udp()                 # real endpoints
        a_g, a_s = _udp(), _udp()                        # attacker's two faces
        self.live = LiveDetector(shared_detector()) if with_detector else None
        self.satellite = Satellite(SCID, s_sock, a_s.getsockname(), self.psk, self.log, warp, seed)
        self.attacker = Attacker(SCID, a_g, a_s, sat_addr=s_sock.getsockname(), ground_addr=g_sock.getsockname())
        self.ground = GroundStation(SCID, g_sock, a_g.getsockname(), self.psk, self.log, self.live)
        self.ground.is_injected = self.attacker.is_injected
        self.satellite.on_execute = self._on_execute
        self.impact_lock = threading.Lock()
        self.impact = dict(spoofed=0, replayed=0, tampered=0)
        self.impact_log: deque = deque(maxlen=60)
        self._exec_count: dict = {}
        self._socks = [g_sock, s_sock, a_g, a_s]
        self.started = time.time()
        self.attacker.start()
        self.satellite.start()
        self.ground.start()
        self.set_secure(secure)

    # -- ground truth ------------------------------------------------------
    def _on_execute(self, e: dict) -> None:
        cid = e["cmd_id"]
        sent = self.ground.sent.get(cid)
        kind = None
        with self.impact_lock:
            n = self._exec_count.get(cid, 0) + 1
            self._exec_count[cid] = n
            if sent is None:
                kind = "spoofed"
            elif (sent["op"], sent["args"]) != (e["op"], e["args"]):
                kind = "tampered"
            elif n > 1:
                kind = "replayed"
            if kind:
                self.impact[kind] += 1
                self.impact_log.append(dict(ts=time.time(), kind=kind, cmd_id=cid,
                                            text=M.describe_command(dict(op=e["op"], args=e["args"],
                                                                         unknown=e["op"] not in M.OP_NAMES))))

    def impact_snapshot(self) -> dict:
        with self.impact_lock:
            return dict(counts=dict(self.impact), log=list(self.impact_log)[-12:])

    # -- control -----------------------------------------------------------
    def set_secure(self, secure: bool) -> bool:
        self.satellite.set_secure(secure)
        self.ground.set_secure(secure)
        self.attacker.set_drop(False, False)
        self.attacker.reset()
        with self.impact_lock:
            self.impact = dict(spoofed=0, replayed=0, tampered=0)
            self.impact_log.clear()
            self._exec_count.clear()
        self.ground.sent.clear()
        self.log.clear()
        if secure:
            return self.ground.handshake()
        return True

    def reset_counters(self) -> None:
        with self.impact_lock:
            self.impact = dict(spoofed=0, replayed=0, tampered=0)
            self.impact_log.clear()
        self.log.clear()

    def shutdown(self) -> None:
        self.ground.stop()
        self.satellite.stop()
        self.attacker.stop()
        time.sleep(0.1)
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass

    # -- waiting helpers (used by tests / evaluation) ----------------------
    def wait_for(self, cond, timeout: float = 1.0, step: float = 0.005) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            if cond():
                return True
            time.sleep(step)
        return cond()

    def command_and_wait(self, op: int, *args, timeout: float = 1.0) -> Optional[dict]:
        cid = self.ground.send_command(op, *args)
        if cid is None:
            return None
        self.wait_for(lambda: cid in self.ground.acks, timeout)
        return self.ground.acks.get(cid)

    # -- full state for the UI --------------------------------------------
    def snapshot(self) -> dict:
        g = self.ground
        tl = list(g.telemetry)
        latest = tl[-1] if tl else None
        hist = [dict(t=x["recv"], battery=x["battery"], temp=x["temp"], roll=x["roll"], pitch=x["pitch"],
                     yaw=x["yaw"], lat=x["lat"], lon=x["lon"], anomaly=x["anomaly"], score=x["score"],
                     spoofed=x["spoofed"]) for x in tl[-200:]]
        sat = self.satellite.state()
        det = None
        if self.live:
            det = dict(trained=self.live.det.trained, flagged=self.live.flagged, total=self.live.total,
                       score=self.live.last_score, info=self.live.det.train_info,
                       recent=[dict(t=x["recv"], reason=x["anomaly_reason"], score=x["score"]) for x in tl[-200:] if x["anomaly"]][-8:])
        return dict(
            now=time.time(), secure=g.secure, link=g.link_info(),
            latest=latest, history=hist, satellite=sat,
            commands=list(g.cmd_history)[-14:], events=self.log.snapshot(60),
            reject_totals=dict(satellite=self.log.reasons("satellite"), ground=self.log.reasons("ground")),
            attacker=self.attacker.snapshot(30), impact=self.impact_snapshot(), detector=det,
            data_kb=g.data_bytes / 1024.0, spoofed_accepted=g.spoofed_accepted,
        )
