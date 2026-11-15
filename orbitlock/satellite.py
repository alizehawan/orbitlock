"""Software spacecraft: physics model + command executor + asyncio UDP link endpoint."""
from __future__ import annotations

import asyncio
import math
import random
import socket
import threading
import time
from collections import deque
from typing import Callable, Optional

from . import messages as M
from . import protocol as P
from .net import AsyncRuntime, UdpEndpoint

ORBIT_PERIOD = 5700.0       # s, ~LEO
SUNLIT_FRACTION = 0.62
INCLINATION = 51.6
DRAW = {0: 0.08, 1: 0.15, 2: 0.25, 3: 0.22}   # %/s battery draw per mode
PAYLOAD_DRAW = 0.15
SOLAR_GEN = 0.30


class SpacecraftModel:
    """Pure physics/state – no I/O, so the ML trainer can run it offline."""

    def __init__(self, warp: float = 60.0, seed: Optional[int] = None):
        self.rng = random.Random(seed)
        self.warp = warp
        self.sim_t = self.rng.uniform(0, ORBIT_PERIOD)
        self.mode = 1
        self.payload_on = 0
        self.battery = 88.0
        self.temp = 20.0
        self.att = [0.0, 0.0, 0.0]
        self.att_target = [0.0, 0.0, 0.0]
        self.lon0 = self.rng.uniform(-180, 180)
        self.alt = 550.0
        self.dv = 0.0
        self.data_buffer_kb = 256
        self.autosafed = False

    # -- orbit -------------------------------------------------------------
    @property
    def phase(self) -> float:
        return (self.sim_t % ORBIT_PERIOD) / ORBIT_PERIOD

    @property
    def sunlit(self) -> bool:
        return self.phase < SUNLIT_FRACTION

    def position(self) -> tuple[float, float]:
        ph = self.phase * 2 * math.pi
        lat = math.degrees(math.asin(math.sin(math.radians(INCLINATION)) * math.sin(ph)))
        lon = self.lon0 + math.degrees(math.atan2(math.cos(math.radians(INCLINATION)) * math.sin(ph), math.cos(ph)))
        lon -= 360.0 * (self.sim_t / 86164.0)      # Earth rotation
        lon = (lon + 540.0) % 360.0 - 180.0
        return lat, lon

    # -- dynamics ----------------------------------------------------------
    def step(self, dt: float) -> None:
        r = self.rng
        self.sim_t += dt * self.warp
        sun = self.sunlit
        gen = SOLAR_GEN if sun else 0.0
        draw = DRAW[self.mode] + PAYLOAD_DRAW * self.payload_on
        self.battery = min(100.0, max(0.0, self.battery + (gen - draw) * dt + r.gauss(0, 0.01)))
        if self.battery < 15.0 and not self.autosafed:        # autonomous safing
            self.mode, self.payload_on, self.autosafed = 0, 0, True
        if self.battery > 40.0:
            self.autosafed = False
        target_t = 12.0 + (16.0 if sun else 0.0) + 9.0 * self.payload_on + 3.0 * (self.mode == 2)
        self.temp += (target_t - self.temp) * min(1.0, dt / 8.0) + r.gauss(0, 0.03)
        k = min(1.0, dt / 3.0)
        for i in range(3):
            self.att[i] += (self.att_target[i] - self.att[i]) * k + r.gauss(0, 0.02)

    def telemetry(self, rx_frames: int, rx_rejects: int, last_cmd: int) -> dict:
        lat, lon = self.position()
        return dict(t=self.sim_t, mode=self.mode, payload_on=self.payload_on,
                    battery=self.battery, temp=self.temp, roll=self.att[0], pitch=self.att[1],
                    yaw=self.att[2], lat=lat, lon=lon, alt=self.alt + 0.25 * self.dv, dv=self.dv,
                    rx_frames=rx_frames, rx_rejects=rx_rejects, last_cmd=last_cmd)

    # -- commands ----------------------------------------------------------
    def execute(self, cmd: dict) -> int:
        """Apply a decoded command. Returns an ACK status."""
        if cmd.get("unknown"):
            return M.ACK_UNKNOWN
        op, a = cmd["op"], cmd["args"]
        if op == M.OP_SET_MODE:
            if a[0] >= len(M.MODES):
                return M.ACK_INVALID
            self.mode = a[0]
            if a[0] == 0:
                self.payload_on = 0
        elif op == M.OP_ATTITUDE:
            if not all(math.isfinite(x) and -180 <= x <= 180 for x in a):
                return M.ACK_INVALID
            self.att_target = list(a)
        elif op == M.OP_PAYLOAD:
            if a[0] > 1:
                return M.ACK_INVALID
            self.payload_on = a[0]
        elif op == M.OP_BURN:
            if not math.isfinite(a[0]) or abs(a[0]) > 50:
                return M.ACK_INVALID
            self.dv += a[0]
        elif op in (M.OP_DOWNLINK, M.OP_REKEY, M.OP_PING, M.OP_ROTATE):
            pass  # handled by the link layer
        return M.ACK_OK

    def inject_fault(self, kind: str) -> None:
        r = self.rng
        if kind == "battery_drop":
            self.battery = max(2.0, self.battery - r.uniform(30, 45))
        elif kind == "temp_spike":
            self.temp += r.uniform(30, 45)
        elif kind == "tumble":
            self.att = [x + r.choice([-1, 1]) * r.uniform(50, 120) for x in self.att]
        else:
            raise ValueError(kind)


class Satellite:
    """UDP endpoint wrapped around :class:`SpacecraftModel`."""

    TLM_HZ = 2.0
    PHYS_HZ = 20.0

    def __init__(self, scid: int, sock: socket.socket, downlink_addr, psk: bytes,
                 log: P.SecurityLog, warp: float = 60.0, seed: Optional[int] = None):
        self.scid, self.sock, self.downlink_addr, self.psk, self.log = scid, sock, downlink_addr, psk, log
        self.model = SpacecraftModel(warp=warp, seed=seed)
        self.lock = threading.RLock()
        self.channel: Optional[object] = None
        self.hs = P.SatelliteHandshake(scid, psk)
        self.secure = False
        self.rx_frames = 0
        self.rx_rejects = 0
        self.rx_accepted = 0
        self.last_cmd = 0
        self.executed: deque = deque(maxlen=3000)
        self.on_execute: Optional[Callable[[dict], None]] = None
        self.data_sent_kb = 0
        self.session_count = 0
        self._stop = threading.Event()
        self.rt: Optional[AsyncRuntime] = None
        self.ep: Optional[UdpEndpoint] = None
        self.set_secure(False)

    # -- configuration -----------------------------------------------------
    def set_secure(self, secure: bool) -> None:
        with self.lock:
            self.secure = secure
            self.channel = None if secure else P.PlainChannel(self.scid, "satellite")
            if secure:
                self.hs = P.SatelliteHandshake(self.scid, self.psk)

    @property
    def link_up(self) -> bool:
        return self.channel is not None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        self.rt = AsyncRuntime("satellite-net")
        self.ep = UdpEndpoint(self.rt, self.sock, self._on_datagram)
        self.rt.spawn(self._phys_task())

    def stop(self) -> None:
        self._stop.set()
        if self.rt:
            if self.ep:
                self.ep.close()
            self.rt.stop()

    # -- tx ----------------------------------------------------------------
    def _send(self, ftype: int, vc: int, payload: bytes) -> None:
        with self.lock:
            ch = self.channel
        if ch is None:
            return
        if self.ep:
            self.ep.sendto(ch.protect(ftype, vc, payload), self.downlink_addr)

    async def _phys_task(self) -> None:
        """Physics at PHYS_HZ, telemetry at TLM_HZ, on the satellite's event loop."""
        loop = asyncio.get_running_loop()
        dt = 1.0 / self.PHYS_HZ
        next_tlm = loop.time()
        nxt = loop.time()
        while not self._stop.is_set():
            nxt += dt
            with self.lock:
                self.model.step(dt)
            now = loop.time()
            if now >= next_tlm:
                next_tlm = now + 1.0 / self.TLM_HZ
                self._send_telemetry()
            await asyncio.sleep(max(0.0, nxt - loop.time()))

    def _send_telemetry(self) -> None:
        with self.lock:
            tlm = self.model.telemetry(self.rx_frames, self.rx_rejects, self.last_cmd)
        self._send(P.F_TLM, P.VC_TLM, M.encode_telemetry(tlm))

    # -- rx ----------------------------------------------------------------
    def _on_datagram(self, data: bytes, addr) -> None:
        try:
            self._handle(data)
        except Exception as exc:  # never let a bad frame kill the receiver
            self.log.add("satellite", "reject", P.R_MALFORMED, detail=f"{type(exc).__name__}")
            with self.lock:
                self.rx_rejects += 1

    def _reject(self, exc: P.FrameRejected, size: int) -> None:
        with self.lock:
            self.rx_rejects += 1
        h = exc.header
        self.log.add("satellite", "reject", exc.reason, seq=h.seq if h else None,
                     epoch=h.epoch if h else None, vc=h.vc if h else None,
                     ftype=P.FTYPE_NAMES.get(h.ftype, "?") if h else None, size=size)

    def _handle(self, data: bytes) -> None:
        with self.lock:
            self.rx_frames += 1
        try:
            h = P.parse_header(data)
        except P.FrameRejected as e:
            return self._reject(e, len(data))

        if h.ftype == P.F_HELLO and self.secure:
            return self._handle_hello(h, data)

        with self.lock:
            ch = self.channel
        if ch is None:
            return self._reject(P.FrameRejected(P.R_NO_SESSION, h), len(data))
        try:
            hdr, payload = ch.unprotect(data)
        except P.FrameRejected as e:
            return self._reject(e, len(data))
        with self.lock:
            self.rx_accepted += 1
        if hdr.ftype == P.F_CMD:
            self._exec_command(payload)

    def _handle_hello(self, h: P.Header, data: bytes) -> None:
        try:
            reply, new_ch = self.hs.respond(data[P.HEADER_LEN:])
        except P.FrameRejected as e:
            e.header = h
            return self._reject(e, len(data))
        with self.lock:
            self.channel = new_ch
            self.session_count += 1
        self.log.add("satellite", "info", "session_established",
                     text="New X25519 session established (keys derived with HKDF-SHA256)")
        self.ep.sendto(P.handshake_frame(self.scid, P.F_HELLO_ACK, reply), self.downlink_addr)

    def _exec_command(self, payload: bytes) -> None:
        try:
            cmd = M.decode_command(payload)
        except ValueError:
            with self.lock:
                self.rx_rejects += 1
            self.log.add("satellite", "reject", P.R_MALFORMED, detail="undecodable command")
            return
        with self.lock:
            status = self.model.execute(cmd)
            self.last_cmd = cmd["cmd_id"]
            entry = dict(cmd_id=cmd["cmd_id"], op=cmd["op"], args=cmd["args"], status=status,
                         ts=time.time())
            self.executed.append(entry)
        if self.on_execute:
            self.on_execute(entry)
        # ACK goes out under the *current* keys, before any rotation takes effect
        self._send(P.F_ACK, P.VC_CMD, M.encode_ack(cmd["cmd_id"], status, cmd["op"]))
        if status != M.ACK_OK:
            return
        op = cmd["op"]
        if op == M.OP_ROTATE and self.secure and isinstance(self.channel, P.SecureChannel):
            new = self.channel.rotate(cmd["args"][0])
            self.log.add("satellite", "info", "key_rotated", text=f"Key rotated to epoch {new}")
        elif op == M.OP_DOWNLINK:
            self.rt.spawn(self._downlink(cmd["args"][0]))
        elif op == M.OP_REKEY:
            self.log.add("satellite", "info", "rekey_requested",
                         text="Emergency rekey requested – awaiting fresh handshake")

    async def _downlink(self, kb: int) -> None:
        kb = min(kb, 64)
        for i in range(kb * 2):                       # 512-byte chunks
            self._send(P.F_DATA, P.VC_DATA, bytes([i & 0xFF]) * 512)
            self.data_sent_kb += 0.5
            await asyncio.sleep(0.002)

    # -- misc --------------------------------------------------------------
    def inject_fault(self, kind: str) -> None:
        with self.lock:
            self.model.inject_fault(kind)

    def state(self) -> dict:
        with self.lock:
            m = self.model
            return dict(mode=M.MODES[m.mode], payload_on=bool(m.payload_on),
                        battery=m.battery, temp=m.temp, att=list(m.att), dv=m.dv,
                        sunlit=m.sunlit, rx_frames=self.rx_frames, rx_rejects=self.rx_rejects,
                        rx_accepted=self.rx_accepted, session_count=self.session_count)
