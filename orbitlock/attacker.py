"""Man-in-the-middle attacker toolkit: sniff, replay, forge, bit-flip, drop, flood.

The attacker sits between ground and satellite (all traffic is relayed through it).
It knows the *public* frame format but has no keys. The same attacks are run against
the clear and the secured link.

Networking is asyncio (one event loop for the node, datagram endpoints for both faces); frames are
crafted, dissected and exported to ``.pcap`` with Scapy (:mod:`orbitlock.scapy_layers`).
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import socket
import threading
import time
from collections import deque
from typing import Optional

from . import messages as M
from . import protocol as P
from . import scapy_layers as SL
from .net import AsyncRuntime, UdpEndpoint

ATTACK_CMD_BASE = 0xBAD00000


class Attacker:
    def __init__(self, scid: int, ground_side: socket.socket, sat_side: socket.socket,
                 sat_addr, ground_addr):
        self.scid = scid
        self.g_sock, self.s_sock = ground_side, sat_side
        self.sat_addr, self.ground_addr = sat_addr, ground_addr
        self.lock = threading.RLock()
        self.captures: deque = deque(maxlen=250)
        self._cap_id = 0
        self.raw: dict = {}                        # capture id -> raw bytes
        self.injected: set = set()                 # sha1 of frames the attacker injected
        self.tamper_armed = 0
        self.drop = dict(up=False, down=False)
        self.stats = dict(sniffed=0, replayed=0, forged=0, tampered=0, dropped=0, flooded=0)
        self.last_up_header: Optional[P.Header] = None
        self.last_down_header: Optional[P.Header] = None
        self.last_up_cmd_capture: Optional[int] = None
        self._forge_n = 0
        self.pcap_log: deque = deque(maxlen=4000)  # (ts, sport, dport, raw) incl. injected frames
        self._stop = threading.Event()
        self._flooding = threading.Event()
        self.rt: Optional[AsyncRuntime] = None
        self.g_ep: Optional[UdpEndpoint] = None
        self.s_ep: Optional[UdpEndpoint] = None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        self.rt = AsyncRuntime("attacker-net")
        self.g_ep = UdpEndpoint(self.rt, self.g_sock, lambda d, a: self._on_data(d, "up"))
        self.s_ep = UdpEndpoint(self.rt, self.s_sock, lambda d, a: self._on_data(d, "down"))

    def stop(self) -> None:
        self._stop.set()
        self._flooding.clear()
        if self.rt:
            for ep in (self.g_ep, self.s_ep):
                if ep:
                    ep.close()
            self.rt.stop()

    # -- passive path ------------------------------------------------------
    def _on_data(self, data: bytes, direction: str) -> None:
        """Runs on the attacker's event loop for every datagram that crosses the link."""
        status = "relayed"
        out = data
        with self.lock:
            if self.drop[direction]:
                status, out = "dropped", None
                self.stats["dropped"] += 1
            elif direction == "up" and self.tamper_armed > 0 and self._is_cmd(data):
                out = self._bitflip(data)
                self.tamper_armed -= 1
                status = "tampered"
                self.stats["tampered"] += 1
                self.injected.add(self._digest(out))
            cid = self._record(direction, data, status)
            if direction == "up" and self._is_cmd(data):
                self.last_up_cmd_capture = cid
        if out is not None:
            if direction == "up":
                self.s_ep.sendto(out, self.sat_addr)
            else:
                self.g_ep.sendto(out, self.ground_addr)

    @staticmethod
    def _digest(b: bytes) -> bytes:
        return hashlib.sha1(b).digest()

    def is_injected(self, frame: bytes) -> bool:
        with self.lock:
            return self._digest(frame) in self.injected

    @staticmethod
    def _is_cmd(data: bytes) -> bool:
        return len(data) > P.HEADER_LEN and data[4] == P.F_CMD  # ftype byte (ver,scid[2],vc,ftype)

    def _record(self, direction: str, data: bytes, status: str) -> int:
        self.stats["sniffed"] += 1
        self._cap_id += 1
        cid = self._cap_id
        try:
            h = P.parse_header(data)
        except P.FrameRejected:
            h = None
        if h:
            if direction == "up":
                self.last_up_header = h
            else:
                self.last_down_header = h
        self.raw[cid] = data
        ports = (self.ground_addr[1], self.sat_addr[1]) if direction == "up" else (self.sat_addr[1], self.ground_addr[1])
        self.pcap_log.append((time.time(), ports[0], ports[1], data))
        if len(self.raw) > 300:
            for k in sorted(self.raw)[:50]:
                del self.raw[k]
        self.captures.append(dict(id=cid, ts=time.time(), dir=direction, len=len(data), status=status,
                                  hex=data[:40].hex(" "), scapy=SL.summary(data),
                                  hdr=dict(ver=h.ver, vc=h.vc, type=P.FTYPE_NAMES.get(h.ftype, hex(h.ftype)),
                                           epoch=h.epoch, seq=h.seq) if h else None,
                                  decoded=self._decode(data, h)))
        return cid

    @staticmethod
    def _decode(data: bytes, h: Optional[P.Header]) -> dict:
        """What an eavesdropper can read from the wire."""
        if h is None:
            return dict(readable=False, text="(unparsable)")
        if h.ftype in (P.F_HELLO, P.F_HELLO_ACK):
            return dict(readable=False, text="handshake (public key + MAC)")
        if h.ver == P.VER_SECURE:
            return dict(readable=False, text=f"🔒 ciphertext ({len(data) - P.HEADER_LEN - P.TAG_LEN} B) + 16 B tag")
        body = data[P.HEADER_LEN:]
        try:
            if h.ftype == P.F_CMD:
                return dict(readable=True, text=M.describe_command(M.decode_command(body)))
            if h.ftype == P.F_TLM:
                t = M.decode_telemetry(body)
                return dict(readable=True, text=f"TLM {M.MODES[t['mode']] if t['mode'] < 4 else '?'} "
                                                 f"batt={t['battery']:.1f}% temp={t['temp']:.1f}°C")
            if h.ftype == P.F_ACK:
                a = M.decode_ack(body)
                return dict(readable=True, text=f"ACK cmd#{a['cmd_id']} status={a['status']}")
            if h.ftype == P.F_DATA:
                return dict(readable=True, text=f"DATA {len(body)} B")
        except Exception:
            pass
        return dict(readable=False, text="(unreadable)")

    # -- active attacks ----------------------------------------------------
    def _inject(self, frame: bytes, toward: str) -> None:
        with self.lock:
            self.injected.add(self._digest(frame))
            if toward == "sat":     # injected frames appear in the pcap too (attacker -> victim)
                self.pcap_log.append((time.time(), self.ground_addr[1], self.sat_addr[1], frame))
            else:
                self.pcap_log.append((time.time(), self.sat_addr[1], self.ground_addr[1], frame))
        if toward == "sat":
            self.s_ep.sendto(frame, self.sat_addr)
        else:
            self.g_ep.sendto(frame, self.ground_addr)

    def _clone_header(self, direction: str, ftype: int, vc: int, clear: bool) -> P.Header:
        ref = self.last_up_header if direction == "up" else self.last_down_header
        epoch = ref.epoch if ref else 0
        seq = (ref.seq + 1) if ref else 1
        return P.Header(P.VER_CLEAR if clear else P.VER_SECURE, self.scid, vc, ftype, epoch, seq)

    def _secure_mode_seen(self) -> bool:
        ref = self.last_up_header or self.last_down_header
        return bool(ref and ref.ver == P.VER_SECURE)

    def replay(self, capture_id: Optional[int] = None, toward: str = "sat") -> Optional[int]:
        with self.lock:
            cid = capture_id or self.last_up_cmd_capture
            raw = self.raw.get(cid) if cid else None
        if raw is None:
            return None
        self._inject(raw, toward)
        self.stats["replayed"] += 1
        return cid

    def forge_command(self, op: int, *args, clear: bool = False) -> int:
        """Craft a telecommand from scratch. Without keys the best it can do on a
        secured link is a well-formed frame with a guessed (random) tag."""
        with self.lock:
            self._forge_n += 1
            cmd_id = ATTACK_CMD_BASE + self._forge_n
            secure_link = self._secure_mode_seen() and not clear
            hdr = self._clone_header("up", P.F_CMD, P.VC_CMD, clear=not secure_link)
        payload = M.encode_command(cmd_id, op, *args)
        body = os.urandom(len(payload) + P.TAG_LEN) if hdr.ver == P.VER_SECURE else payload
        self._inject(SL.build_frame(hdr, body), "sat")
        self.stats["forged"] += 1
        return cmd_id

    def forge_clear_command(self, op: int, *args) -> int:
        """Downgrade attempt: inject a cleartext frame (ver=1) regardless of link mode."""
        return self.forge_command(op, *args, clear=True)

    def forge_telemetry(self, battery: float = 100.0, temp: float = 20.0) -> None:
        """Spoof telemetry towards the ground station (e.g. hide a real fault)."""
        with self.lock:
            secure_link = self._secure_mode_seen()
            hdr = self._clone_header("down", P.F_TLM, P.VC_TLM, clear=not secure_link)
        fake = dict(t=0.0, mode=1, payload_on=0, battery=battery, temp=temp, roll=0.0, pitch=0.0,
                    yaw=0.0, lat=0.0, lon=0.0, alt=550.0, dv=0.0, rx_frames=0, rx_rejects=0, last_cmd=0)
        payload = M.encode_telemetry(fake)
        body = os.urandom(len(payload) + P.TAG_LEN) if secure_link else payload
        self._inject(SL.build_frame(hdr, body), "ground")
        self.stats["forged"] += 1

    def _bitflip(self, data: bytes, bit: int = 0) -> bytes:
        idx = P.HEADER_LEN + 5            # first argument byte (cmd_id=4, op=1) / ciphertext byte
        idx = min(idx, len(data) - 1)
        b = bytearray(data)
        b[idx] ^= 1 << bit
        return bytes(b)

    def arm_tamper(self, n: int = 1) -> None:
        with self.lock:
            self.tamper_armed = n

    def set_drop(self, up: bool = False, down: bool = False) -> None:
        with self.lock:
            self.drop = dict(up=up, down=down)

    def flood(self, count: int = 1500, rate: float = 300.0) -> None:
        """Garbage-frame flood towards the satellite (rate-limited asyncio task)."""
        if self._flooding.is_set() or self.rt is None:
            return
        self._flooding.set()
        self.rt.spawn(self._flood_task(count, rate))

    async def _flood_task(self, count: int, rate: float) -> None:
        loop = asyncio.get_running_loop()
        period = 1.0 / rate
        nxt = loop.time()
        try:
            for _ in range(count):
                if not self._flooding.is_set() or self._stop.is_set():
                    break
                with self.lock:
                    secure_link = self._secure_mode_seen()
                    hdr = self._clone_header("up", P.F_CMD, P.VC_CMD, clear=not secure_link)
                    self._forge_n += 1
                    cid = ATTACK_CMD_BASE + self._forge_n
                body = os.urandom(5 + P.TAG_LEN) if secure_link else M.encode_command(cid, M.OP_PING)
                self.s_ep.sendto(SL.build_frame(hdr, body), self.sat_addr)
                self.stats["flooded"] += 1
                nxt += period
                await asyncio.sleep(max(0.0, nxt - loop.time()))
        finally:
            self._flooding.clear()

    def stop_flood(self) -> None:
        self._flooding.clear()

    def reset(self) -> None:
        with self.lock:
            self.captures.clear(); self.raw.clear(); self.injected.clear(); self.pcap_log.clear()
            self.tamper_armed = 0
            self.last_up_header = self.last_down_header = None
            self.last_up_cmd_capture = None
            self.stats = {k: 0 for k in self.stats}

    # -- views -------------------------------------------------------------
    def export_pcap(self) -> bytes:
        """Everything seen on / injected into the link as a Scapy-written .pcap (Ethernet/IP/UDP/OrbitLock)."""
        with self.lock:
            frames = list(self.pcap_log)
        return SL.pcap_bytes(frames)

    def snapshot(self, limit: int = 40) -> dict:
        with self.lock:
            return dict(captures=list(self.captures)[-limit:], stats=dict(self.stats),
                        tamper_armed=self.tamper_armed, drop=dict(self.drop),
                        flooding=self._flooding.is_set())
