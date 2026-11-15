"""OrbitLock protocol core.

A lightweight, transport-independent link-security layer inspired by CCSDS SDLS.

* Session establishment: ephemeral X25519, authenticated with a pre-shared
  long-term key (HMAC-SHA256), session keys derived with HKDF-SHA256.
* Frame protection: AES-256-GCM; the 15-byte frame header (version, spacecraft
  id, virtual channel, frame type, key epoch, sequence number) is authenticated
  as associated data.
* Anti-replay: monotonic sequence numbers + 64-frame sliding acceptance window.
* Key management: forward ratcheting key rotation (epochs) and an emergency
  rekey that runs a brand-new X25519 handshake.
* Security event logging of every rejected frame with the reason.

The module has no networking in it: ``protect`` turns (type, vc, payload) into
bytes and ``unprotect`` turns bytes back into (header, payload) or raises
``FrameRejected``.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# --------------------------------------------------------------------------
# Frame layout
# --------------------------------------------------------------------------
VER_CLEAR = 0x01   # unprotected ("clear mode") frame
VER_SECURE = 0x02  # OrbitLock-protected frame

HEADER = struct.Struct(">BHBBHQ")  # ver, scid, vc, ftype, epoch, seq
HEADER_LEN = HEADER.size           # 15
TAG_LEN = 16
SECURITY_OVERHEAD = TAG_LEN        # on top of the (shared) header

# frame types
F_CMD = 0x01
F_TLM = 0x02
F_ACK = 0x03
F_DATA = 0x04
F_HELLO = 0xF0
F_HELLO_ACK = 0xF1

# virtual channels
VC_CMD = 0
VC_TLM = 1
VC_DATA = 2

FTYPE_NAMES = {F_CMD: "CMD", F_TLM: "TLM", F_ACK: "ACK", F_DATA: "DATA",
               F_HELLO: "HELLO", F_HELLO_ACK: "HELLO_ACK"}

# rejection reasons
R_BAD_TAG = "bad_tag"
R_REPLAY = "replay"
R_OUT_OF_WINDOW = "out_of_window"
R_UNKNOWN_EPOCH = "unknown_epoch"
R_MALFORMED = "malformed"
R_WRONG_SC = "wrong_spacecraft"
R_CLEAR_FRAME = "clear_frame_on_secure_link"
R_NO_SESSION = "no_session"
R_BAD_HANDSHAKE = "bad_handshake_mac"
R_STALE_HANDSHAKE = "stale_handshake"

REASON_TEXT = {
    R_BAD_TAG: "Authentication tag mismatch (forged or tampered frame)",
    R_REPLAY: "Sequence number already seen (replayed frame)",
    R_OUT_OF_WINDOW: "Sequence number older than the acceptance window",
    R_UNKNOWN_EPOCH: "Frame uses a key epoch that is not valid",
    R_MALFORMED: "Frame too short / unparsable",
    R_WRONG_SC: "Frame addressed to another spacecraft",
    R_CLEAR_FRAME: "Unprotected frame refused on a secured link (downgrade)",
    R_NO_SESSION: "No session established yet",
    R_BAD_HANDSHAKE: "Handshake authentication failed (bad PSK MAC)",
    R_STALE_HANDSHAKE: "Handshake counter not fresh (replayed handshake)",
}


@dataclass(frozen=True)
class Header:
    ver: int
    scid: int
    vc: int
    ftype: int
    epoch: int
    seq: int

    def pack(self) -> bytes:
        return HEADER.pack(self.ver, self.scid, self.vc, self.ftype, self.epoch, self.seq)


def parse_header(data: bytes) -> Header:
    if len(data) < HEADER_LEN:
        raise FrameRejected(R_MALFORMED)
    return Header(*HEADER.unpack_from(data))


class FrameRejected(Exception):
    def __init__(self, reason: str, header: Optional[Header] = None, detail: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.header = header
        self.detail = detail


# --------------------------------------------------------------------------
# Security event log
# --------------------------------------------------------------------------
class SecurityLog:
    """Thread-safe ring buffer of security events with burst coalescing."""

    def __init__(self, capacity: int = 400):
        self._events: deque = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._next_id = 1
        self.counters: dict = {}

    def add(self, node: str, kind: str, reason: str, **fields) -> None:
        now = time.time()
        with self._lock:
            key = f"{node}:{kind}:{reason}"
            self.counters[key] = self.counters.get(key, 0) + 1
            if self._events:
                last = self._events[-1]
                # coalesce floods of identical rejects into a single row
                if (kind == "reject" and last["node"] == node and last["kind"] == kind
                        and last["reason"] == reason and now - last["ts_last"] < 0.4):
                    last["count"] += 1
                    last["ts_last"] = now
                    last.update({k: v for k, v in fields.items() if k in ("seq", "epoch")})
                    return
            ev = dict(id=self._next_id, ts=now, ts_last=now, node=node, kind=kind,
                      reason=reason, text=REASON_TEXT.get(reason, reason), count=1)
            ev.update(fields)
            self._next_id += 1
            self._events.append(ev)

    def snapshot(self, limit: int = 80) -> list:
        with self._lock:
            return [dict(e) for e in list(self._events)[-limit:]]

    def total(self, node: str, kind: str = "reject") -> int:
        with self._lock:
            return sum(v for k, v in self.counters.items() if k.startswith(f"{node}:{kind}:"))

    def reasons(self, node: str) -> dict:
        out = {}
        with self._lock:
            for k, v in self.counters.items():
                n, kind, reason = k.split(":", 2)
                if n == node and kind == "reject":
                    out[reason] = v
        return out

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self.counters.clear()


# --------------------------------------------------------------------------
# Anti-replay sliding window
# --------------------------------------------------------------------------
class ReplayWindow:
    def __init__(self, size: int = 64):
        self.size = size
        self.highest = -1
        self.bitmap = 0

    def check(self, seq: int) -> Optional[str]:
        if seq > self.highest:
            return None
        diff = self.highest - seq
        if diff >= self.size:
            return R_OUT_OF_WINDOW
        if (self.bitmap >> diff) & 1:
            return R_REPLAY
        return None

    def update(self, seq: int) -> None:
        if seq > self.highest:
            shift = seq - self.highest
            self.bitmap = ((self.bitmap << shift) | 1) & ((1 << self.size) - 1)
            self.highest = seq
        else:
            self.bitmap |= 1 << (self.highest - seq)


# --------------------------------------------------------------------------
# Key schedule
# --------------------------------------------------------------------------
def _hkdf(ikm: bytes, salt: Optional[bytes], info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def _epoch_keys(root: bytes, epoch: int) -> tuple[bytes, bytes]:
    material = _hkdf(root, None, b"OrbitLock/v1/keys" + struct.pack(">H", epoch), 64)
    return material[:32], material[32:]  # k_up (ground->sat), k_down (sat->ground)


def _next_root(root: bytes, new_epoch: int) -> bytes:
    return _hkdf(root, None, b"OrbitLock/v1/rotate" + struct.pack(">H", new_epoch), 32)


@dataclass
class _Epoch:
    k_up: bytes
    k_down: bytes
    window: ReplayWindow = field(default_factory=ReplayWindow)
    aead_up: AESGCM = None
    aead_down: AESGCM = None

    def __post_init__(self):
        self.aead_up = AESGCM(self.k_up)
        self.aead_down = AESGCM(self.k_down)


# --------------------------------------------------------------------------
# Channels
# --------------------------------------------------------------------------
class PlainChannel:
    """Baseline: framing only, no confidentiality/integrity/authenticity/replay protection."""

    secure = False

    def __init__(self, scid: int, role: str):
        self.scid = scid
        self.role = role
        self._seq = 0
        self._lock = threading.Lock()
        self.epoch = 0

    def protect(self, ftype: int, vc: int, payload: bytes) -> bytes:
        with self._lock:
            seq = self._seq
            self._seq += 1
        return Header(VER_CLEAR, self.scid, vc, ftype, 0, seq).pack() + payload

    def unprotect(self, frame: bytes) -> tuple[Header, bytes]:
        h = parse_header(frame)
        if h.ver != VER_CLEAR:
            raise FrameRejected(R_MALFORMED, h, "unsupported version")
        if h.scid != self.scid:
            raise FrameRejected(R_WRONG_SC, h)
        return h, frame[HEADER_LEN:]

    def info(self) -> dict:
        return dict(secure=False, epoch=0, tx_seq=self._seq, rx_highest=None)


class SecureChannel:
    """AES-256-GCM frame protection with replay window and key epochs."""

    secure = True

    def __init__(self, scid: int, role: str, root: bytes):
        assert role in ("ground", "satellite")
        self.scid = scid
        self.role = role
        self._lock = threading.Lock()
        self._root = root                 # root of the latest epoch
        self.tx_epoch = 0
        self._tx_seq = 0
        self._epochs: dict[int, _Epoch] = {0: _Epoch(*_epoch_keys(root, 0))}
        self._lookahead: Optional[tuple[int, bytes, _Epoch]] = None
        self.rotations = 0
        self.last_rx_epoch = 0

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _nonce(seq: int) -> bytes:
        return b"\x00\x00\x00\x00" + struct.pack(">Q", seq)

    def _tx_aead(self, ep: _Epoch) -> AESGCM:
        return ep.aead_up if self.role == "ground" else ep.aead_down

    def _rx_aead(self, ep: _Epoch) -> AESGCM:
        return ep.aead_down if self.role == "ground" else ep.aead_up

    # -- API ---------------------------------------------------------------
    def protect(self, ftype: int, vc: int, payload: bytes) -> bytes:
        with self._lock:
            seq = self._tx_seq
            self._tx_seq += 1
            ep = self._epochs[self.tx_epoch]
            hdr = Header(VER_SECURE, self.scid, vc, ftype, self.tx_epoch, seq).pack()
            ct = self._tx_aead(ep).encrypt(self._nonce(seq), payload, hdr)
        return hdr + ct

    def unprotect(self, frame: bytes) -> tuple[Header, bytes]:
        h = parse_header(frame)
        if h.ver == VER_CLEAR:
            raise FrameRejected(R_CLEAR_FRAME, h)
        if h.ver != VER_SECURE or len(frame) < HEADER_LEN + TAG_LEN:
            raise FrameRejected(R_MALFORMED, h)
        if h.scid != self.scid:
            raise FrameRejected(R_WRONG_SC, h)
        with self._lock:
            ep = self._epochs.get(h.epoch)
            adopt = False
            if ep is None:
                newest = max(self._epochs)
                if h.epoch == newest + 1:       # peer already rotated: one-epoch look-ahead
                    ep = self._get_lookahead(h.epoch)
                    adopt = True
                else:
                    raise FrameRejected(R_UNKNOWN_EPOCH, h)
            hdr = frame[:HEADER_LEN]
            try:
                pt = self._rx_aead(ep).decrypt(self._nonce(h.seq), frame[HEADER_LEN:], hdr)
            except InvalidTag:
                raise FrameRejected(R_BAD_TAG, h) from None
            # authenticated -> now (and only now) consult / update replay state
            reason = ep.window.check(h.seq)
            if reason:
                raise FrameRejected(reason, h)
            ep.window.update(h.seq)
            if adopt:
                self._commit_rotation(h.epoch, ep)
            self.last_rx_epoch = max(self.last_rx_epoch, h.epoch)
            # drop keys of epochs the peer has certainly moved past
            floor = min(h.epoch, self.tx_epoch)
            for e in [e for e in self._epochs if e < floor]:
                del self._epochs[e]
        return h, pt

    # -- key rotation ------------------------------------------------------
    def _get_lookahead(self, epoch: int) -> _Epoch:
        if self._lookahead and self._lookahead[0] == epoch:
            return self._lookahead[2]
        root = _next_root(self._root, epoch)
        ep = _Epoch(*_epoch_keys(root, epoch))
        self._lookahead = (epoch, root, ep)
        return ep

    def _commit_rotation(self, epoch: int, ep: _Epoch) -> None:
        root = self._lookahead[1] if self._lookahead and self._lookahead[0] == epoch else _next_root(self._root, epoch)
        self._root = root
        self._epochs[epoch] = ep
        self._lookahead = None
        if epoch > self.tx_epoch:
            self.tx_epoch = epoch
            self._tx_seq = 0
        self.rotations += 1

    def rotate(self, target_epoch: Optional[int] = None) -> int:
        """Ratchet to the next epoch (idempotent if ``target_epoch`` is already reached)."""
        with self._lock:
            newest = max(self._epochs)
            if target_epoch is not None and target_epoch <= newest:
                if self.tx_epoch < newest:
                    self.tx_epoch = newest
                    self._tx_seq = 0
                return self.tx_epoch
            new = newest + 1
            ep = self._get_lookahead(new)
            self._commit_rotation(new, ep)
            return new

    def info(self) -> dict:
        with self._lock:
            hi = self._epochs[max(self._epochs)].window.highest
            return dict(secure=True, epoch=self.tx_epoch, tx_seq=self._tx_seq,
                        rx_highest=hi, rotations=self.rotations)


# --------------------------------------------------------------------------
# Handshake (X25519 + PSK authentication + HKDF)
# --------------------------------------------------------------------------
HELLO_LEN = 8 + 32 + 16 + 32


def _mac(psk: bytes, *parts: bytes) -> bytes:
    return hmac.new(psk, b"|".join(parts), hashlib.sha256).digest()


def _pub_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _session_root(dh: bytes, psk: bytes, nonce_g: bytes, nonce_s: bytes, scid: int, ctr: int) -> bytes:
    info = b"OrbitLock/v1/session" + struct.pack(">HQ", scid, ctr)
    return _hkdf(dh + psk, nonce_g + nonce_s, info, 32)


class GroundHandshake:
    """Initiator side. ``make_hello`` -> send -> ``finish(ack_body)`` -> SecureChannel."""

    def __init__(self, scid: int, psk: bytes):
        self.scid, self.psk = scid, psk
        self.ctr = time.time_ns()
        self._priv = X25519PrivateKey.generate()
        self._pub = _pub_bytes(self._priv)
        self._nonce = os.urandom(16)

    def make_hello(self) -> bytes:
        c = struct.pack(">Q", self.ctr)
        mac = _mac(self.psk, b"HELLO", struct.pack(">H", self.scid), c, self._pub, self._nonce)
        return c + self._pub + self._nonce + mac

    def finish(self, body: bytes) -> SecureChannel:
        if len(body) != HELLO_LEN:
            raise FrameRejected(R_MALFORMED)
        ctr = struct.unpack(">Q", body[:8])[0]
        pub_s, nonce_s, mac = body[8:40], body[40:56], body[56:88]
        if ctr != self.ctr:
            raise FrameRejected(R_STALE_HANDSHAKE)
        expect = _mac(self.psk, b"ACK", struct.pack(">H", self.scid), body[:8],
                      self._pub, self._nonce, pub_s, nonce_s)
        if not hmac.compare_digest(mac, expect):
            raise FrameRejected(R_BAD_HANDSHAKE)
        dh = self._priv.exchange(X25519PublicKey.from_public_bytes(pub_s))
        root = _session_root(dh, self.psk, self._nonce, nonce_s, self.scid, self.ctr)
        return SecureChannel(self.scid, "ground", root)


class SatelliteHandshake:
    """Responder side. Keeps the highest accepted counter to refuse replayed HELLOs."""

    def __init__(self, scid: int, psk: bytes):
        self.scid, self.psk = scid, psk
        self.last_ctr = 0

    def respond(self, body: bytes) -> tuple[bytes, SecureChannel]:
        if len(body) != HELLO_LEN:
            raise FrameRejected(R_MALFORMED)
        ctr = struct.unpack(">Q", body[:8])[0]
        pub_g, nonce_g, mac = body[8:40], body[40:56], body[56:88]
        expect = _mac(self.psk, b"HELLO", struct.pack(">H", self.scid), body[:8], pub_g, nonce_g)
        if not hmac.compare_digest(mac, expect):
            raise FrameRejected(R_BAD_HANDSHAKE)
        if ctr <= self.last_ctr:
            raise FrameRejected(R_STALE_HANDSHAKE)
        self.last_ctr = ctr
        priv = X25519PrivateKey.generate()
        pub_s, nonce_s = _pub_bytes(priv), os.urandom(16)
        dh = priv.exchange(X25519PublicKey.from_public_bytes(pub_g))
        root = _session_root(dh, self.psk, nonce_g, nonce_s, self.scid, ctr)
        ack_mac = _mac(self.psk, b"ACK", struct.pack(">H", self.scid), body[:8],
                       pub_g, nonce_g, pub_s, nonce_s)
        return body[:8] + pub_s + nonce_s + ack_mac, SecureChannel(self.scid, "satellite", root)


def handshake_frame(scid: int, ftype: int, body: bytes) -> bytes:
    """Handshake frames are cleartext on the wire; their body is MAC-authenticated."""
    return Header(VER_SECURE, scid, VC_CMD, ftype, 0, 0).pack() + body
