"""Ground station: sends telecommands, receives telemetry, runs the anomaly detector."""
from __future__ import annotations

import asyncio
import hashlib
import socket
import threading
import time
from collections import deque
from typing import Callable, Optional

from . import messages as M
from . import protocol as P
from .anomaly import LiveDetector
from .net import AsyncRuntime, UdpEndpoint


class GroundStation:
    AUTO_ROTATE_S = 60.0

    def __init__(self, scid: int, sock: socket.socket, sat_addr, psk: bytes, log: P.SecurityLog,
                 detector: Optional[LiveDetector] = None):
        self.scid, self.sock, self.sat_addr, self.psk, self.log = scid, sock, sat_addr, psk, log
        self.detector = detector
        self.lock = threading.RLock()
        self.channel = None
        self.secure = False
        self.hs: Optional[P.GroundHandshake] = None
        self._hs_event = threading.Event()
        self.handshaking = False
        self._cmd_id = 1
        self.sent: dict = {}                       # cmd_id -> decoded command as sent
        self.acks: dict = {}                       # cmd_id -> ack dict
        self.cmd_history: deque = deque(maxlen=60)
        self.telemetry: deque = deque(maxlen=400)
        self.last_tlm_at = 0.0
        self.rx_accepted = 0
        self.data_bytes = 0
        self.is_injected: Callable[[bytes], bool] = lambda frame: False
        self.spoofed_accepted = 0
        self._stop = threading.Event()
        self.rt: Optional[AsyncRuntime] = None
        self.ep: Optional[UdpEndpoint] = None
        self._last_rotate = time.time()
        self.auto_rotate = True
        self.set_secure(False)

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        self.rt = AsyncRuntime("ground-net")
        self.ep = UdpEndpoint(self.rt, self.sock, self._on_datagram)
        self.rt.spawn(self._maint_task())

    def stop(self) -> None:
        self._stop.set()
        if self.rt:
            if self.ep:
                self.ep.close()
            self.rt.stop()

    def set_secure(self, secure: bool) -> None:
        with self.lock:
            self.secure = secure
            self.channel = None if secure else P.PlainChannel(self.scid, "ground")
            self._last_rotate = time.time()
        if self.detector:
            self.detector.reset()

    @property
    def link_up(self) -> bool:
        return self.channel is not None and not self.handshaking

    # -- handshake ---------------------------------------------------------
    def handshake(self, timeout: float = 4.0, announce: str = "session_established") -> bool:
        """X25519 handshake with retransmission. Blocks until done or timeout."""
        with self.lock:
            self.handshaking = True
        deadline = time.time() + timeout
        ok = False
        try:
            while time.time() < deadline and not self._stop.is_set():
                with self.lock:
                    self.hs = P.GroundHandshake(self.scid, self.psk)
                    self._hs_event.clear()
                    hello = self.hs.make_hello()
                self.ep.sendto(P.handshake_frame(self.scid, P.F_HELLO, hello), self.sat_addr)
                if self._hs_event.wait(0.5):
                    ok = True
                    break
        finally:
            with self.lock:
                self.handshaking = False
        if ok:
            self.log.add("ground", "info", announce,
                         text="X25519 handshake complete – fresh session keys (HKDF-SHA256)")
            self._last_rotate = time.time()
        return ok

    # -- tx ----------------------------------------------------------------
    def send_command(self, op: int, *args) -> Optional[int]:
        with self.lock:
            if self.channel is None or self.handshaking:
                return None
            cid = self._cmd_id
            self._cmd_id += 1
            payload = M.encode_command(cid, op, *args)
            self.sent[cid] = M.decode_command(payload)
            frame = self.channel.protect(P.F_CMD, P.VC_CMD, payload)
            self.cmd_history.append(dict(cmd_id=cid, text=M.describe_command(self.sent[cid]),
                                         ts=time.time(), status="pending"))
        self.ep.sendto(frame, self.sat_addr)
        return cid

    def rotate_keys(self) -> bool:
        """Periodic key rotation: tell the satellite, then ratchet our own keys."""
        with self.lock:
            ch = self.channel
            if not isinstance(ch, P.SecureChannel) or self.handshaking:
                return False
            target = ch.tx_epoch + 1
        cid = self.send_command(M.OP_ROTATE, target)
        if cid is None:
            return False
        with self.lock:
            ch.rotate(target)
            self._last_rotate = time.time()
        self.log.add("ground", "info", "key_rotated", text=f"Key rotated to epoch {target}")
        return True

    def emergency_rekey(self) -> bool:
        """REKEY telecommand followed by a brand-new ephemeral X25519 handshake."""
        if not self.secure:
            return False
        cid = self.send_command(M.OP_REKEY)
        if cid is None:
            return False
        time.sleep(0.15)
        return self.handshake(announce="emergency_rekey")

    # -- rx ----------------------------------------------------------------
    def _on_datagram(self, data: bytes, addr) -> None:
        try:
            self._handle(data)
        except Exception:
            pass

    def _reject(self, e: P.FrameRejected, size: int) -> None:
        h = e.header
        self.log.add("ground", "reject", e.reason, seq=h.seq if h else None,
                     epoch=h.epoch if h else None, vc=h.vc if h else None,
                     ftype=P.FTYPE_NAMES.get(h.ftype, "?") if h else None, size=size)

    def _handle(self, data: bytes) -> None:
        try:
            h = P.parse_header(data)
        except P.FrameRejected as e:
            return self._reject(e, len(data))
        if h.ftype == P.F_HELLO_ACK:
            with self.lock:
                hs = self.hs
            if not hs:
                return
            try:
                ch = hs.finish(data[P.HEADER_LEN:])
            except P.FrameRejected as e:
                e.header = h
                return self._reject(e, len(data))
            with self.lock:
                self.channel = ch
                self.hs = None
            self._hs_event.set()
            return
        with self.lock:
            ch = self.channel
        if ch is None:
            return self._reject(P.FrameRejected(P.R_NO_SESSION, h), len(data))
        try:
            hdr, payload = ch.unprotect(data)
        except P.FrameRejected as e:
            return self._reject(e, len(data))
        self.rx_accepted += 1
        injected = self.is_injected(data)
        if hdr.ftype == P.F_TLM:
            try:
                tlm = M.decode_telemetry(payload)
            except ValueError:
                return self._reject(P.FrameRejected(P.R_MALFORMED, hdr), len(data))
            now = time.time()
            verdict = self.detector.process(tlm, now) if self.detector else {}
            tlm.update(recv=now, anomaly=bool(verdict.get("anomaly")), score=verdict.get("score", 0.0),
                       anomaly_reason=verdict.get("reason", ""), spoofed=injected, epoch=hdr.epoch, seq=hdr.seq)
            if injected:
                self.spoofed_accepted += 1
            with self.lock:
                self.telemetry.append(tlm)
                self.last_tlm_at = now
        elif hdr.ftype == P.F_ACK:
            try:
                ack = M.decode_ack(payload)
            except Exception:
                return
            with self.lock:
                self.acks[ack["cmd_id"]] = ack
                for c in self.cmd_history:
                    if c["cmd_id"] == ack["cmd_id"]:
                        c["status"] = {0: "ok", 1: "invalid", 2: "unknown"}.get(ack["status"], "?")
        elif hdr.ftype == P.F_DATA:
            self.data_bytes += len(payload)

    async def _maint_task(self) -> None:
        while not self._stop.is_set():
            await asyncio.sleep(0.5)
            if (self.secure and self.auto_rotate and self.link_up
                    and time.time() - self._last_rotate > self.AUTO_ROTATE_S):
                self.rotate_keys()

    # -- views -------------------------------------------------------------
    def latest(self) -> Optional[dict]:
        with self.lock:
            return dict(self.telemetry[-1]) if self.telemetry else None

    def link_info(self) -> dict:
        with self.lock:
            ch = self.channel
            info = ch.info() if ch else dict(secure=self.secure, epoch=0, tx_seq=0, rx_highest=None)
            info.update(handshaking=self.handshaking, up=self.link_up,
                        last_tlm_age=(time.time() - self.last_tlm_at) if self.last_tlm_at else None)
            return info
