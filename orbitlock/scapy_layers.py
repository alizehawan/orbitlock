"""Scapy integration: an ``OrbitLock`` frame layer, frame crafting, dissection and pcap export.

The attacker uses Scapy to (a) build forged / cloned frames, (b) dissect what it sniffs, and
(c) write the captured wire traffic to a ``.pcap`` that opens in Wireshark / ``scapy.rdpcap``.
The layer layout mirrors :data:`orbitlock.protocol.HEADER` exactly (tests assert the byte equality).
"""
from __future__ import annotations

import io
from typing import Iterable, Optional

from scapy.fields import ByteEnumField, ByteField, ShortField, LongField
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import PcapWriter

from . import protocol as P

VER_NAMES = {P.VER_CLEAR: "clear", P.VER_SECURE: "secure"}
FTYPE_NAMES = dict(P.FTYPE_NAMES)


class OrbitLock(Packet):
    """15-byte OrbitLock frame header: ``ver | scid | vc | type | epoch | seq``."""
    name = "OrbitLock"
    fields_desc = [
        ByteEnumField("ver", P.VER_SECURE, VER_NAMES),
        ShortField("scid", 0),
        ByteField("vc", 0),
        ByteEnumField("ftype", P.F_CMD, FTYPE_NAMES),
        ShortField("epoch", 0),
        LongField("seq", 0),
    ]

    def mysummary(self) -> str:
        return (f"OrbitLock {VER_NAMES.get(self.ver, self.ver)} {FTYPE_NAMES.get(self.ftype, self.ftype)} "
                f"scid={self.scid:#06x} vc={self.vc} epoch={self.epoch} seq={self.seq}")


def build_frame(hdr: P.Header, body: bytes) -> bytes:
    """Craft a frame (header + body) with Scapy."""
    pkt = OrbitLock(ver=hdr.ver, scid=hdr.scid, vc=hdr.vc, ftype=hdr.ftype, epoch=hdr.epoch, seq=hdr.seq)
    return bytes(pkt / Raw(body))


def dissect(data: bytes) -> Optional[Packet]:
    """Parse raw datagram bytes with Scapy. ``None`` if too short to be a frame."""
    if len(data) < P.HEADER_LEN:
        return None
    return OrbitLock(data)


def summary(data: bytes) -> str:
    pkt = dissect(data)
    return pkt.summary() if pkt is not None else "(runt frame)"


def wrap_udp(data: bytes, sport: int, dport: int) -> Packet:
    """Wrap a datagram payload in Ether/IP/UDP (loopback addresses) so a pcap is self-describing."""
    return (Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") /
            IP(src="127.0.0.1", dst="127.0.0.1") / UDP(sport=sport, dport=dport) / Raw(data))


def pcap_bytes(frames: Iterable[tuple]) -> bytes:
    """``frames`` = iterable of (timestamp, sport, dport, raw_bytes). Returns .pcap file content."""
    buf = io.BytesIO()
    w = PcapWriter(buf, linktype=1, sync=False)       # 1 = Ethernet
    for ts, sport, dport, raw in frames:
        pkt = wrap_udp(raw, sport, dport)
        pkt.time = ts
        w.write(pkt)
    w.flush()
    return buf.getvalue()
