"""Scapy layer, pcap export, asyncio networking and the generated report."""
import asyncio
import io
import json
import socket
import time

import pytest
from scapy.layers.inet import IP, UDP
from scapy.utils import rdpcap

from orbitlock import messages as M
from orbitlock import protocol as P
from orbitlock import scapy_layers as SL
from orbitlock.net import AsyncRuntime, UdpEndpoint
from orbitlock.sim import Simulation


def test_scapy_layer_matches_wire_format():
    h = P.Header(P.VER_SECURE, 0x1A2B, P.VC_CMD, P.F_CMD, 3, 12345)
    body = b"\x01\x02\x03"
    frame = SL.build_frame(h, body)
    assert frame == h.pack() + body                       # byte-identical to the native packer
    pkt = SL.dissect(frame)
    assert (pkt.ver, pkt.scid, pkt.vc, pkt.ftype, pkt.epoch, pkt.seq) == (2, 0x1A2B, 0, P.F_CMD, 3, 12345)
    assert bytes(pkt.payload) == body
    assert "OrbitLock" in pkt.summary() and "seq=12345" in pkt.summary()
    assert SL.dissect(b"\x01\x02") is None


def test_udp_endpoint_roundtrip_threadsafe():
    rt = AsyncRuntime("test")
    a, b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    a.bind(("127.0.0.1", 0)); b.bind(("127.0.0.1", 0))
    got = []
    ea = UdpEndpoint(rt, a, lambda d, ad: None)
    eb = UdpEndpoint(rt, b, lambda d, ad: got.append(d))
    try:
        for i in range(20):                               # called from this (non-loop) thread
            ea.sendto(bytes([i]), b.getsockname())
        end = time.time() + 2
        while len(got) < 20 and time.time() < end:
            time.sleep(0.01)
        assert got == [bytes([i]) for i in range(20)]     # delivered, in order
    finally:
        ea.close(); eb.close(); rt.stop()


def test_nodes_run_on_asyncio_loops():
    s = Simulation(secure=True, with_detector=False, seed=2)
    try:
        for node in (s.ground, s.satellite, s.attacker):
            assert isinstance(node.rt.loop, asyncio.AbstractEventLoop) and node.rt.loop.is_running()
        assert s.wait_for(lambda: s.ground.link_up, 3)
        assert s.wait_for(lambda: s.ground.latest() is not None, 2)   # telemetry flows via asyncio task
    finally:
        s.shutdown()
    assert not s.satellite.rt.loop.is_running() or s.satellite.rt._closed


def test_pcap_export_readable_by_scapy():
    s = Simulation(secure=False, with_detector=False, seed=3)
    try:
        assert s.command_and_wait(M.OP_PING)
        assert s.wait_for(lambda: any(c['hdr'] and c['hdr']['type'] == 'TLM'
                                      for c in s.attacker.snapshot()['captures']), 3)
        s.attacker.forge_command(M.OP_BURN, 5.0)
        time.sleep(0.2)
        data = s.attacker.export_pcap()
    finally:
        s.shutdown()
    pkts = rdpcap(io.BytesIO(data))
    assert len(pkts) >= 3
    frames = [SL.OrbitLock(bytes(p[UDP].payload)) for p in pkts if UDP in p and IP in p]
    assert frames and all(f.scid == 0x1A2B for f in frames)
    assert {P.F_CMD, P.F_TLM} <= {f.ftype for f in frames}


def test_wire_capture_has_scapy_summary_and_flood_runs():
    s = Simulation(secure=True, with_detector=False, seed=4)
    try:
        assert s.command_and_wait(M.OP_PING)
        caps = s.attacker.snapshot()["captures"]
        assert caps and all(c["scapy"].startswith("OrbitLock") for c in caps)
        s.attacker.flood(count=60, rate=600.0)
        assert s.wait_for(lambda: s.attacker.stats["flooded"] >= 60, 3)
        assert s.impact_snapshot()["counts"] == dict(spoofed=0, replayed=0, tampered=0)
    finally:
        s.shutdown()


def test_report_renders_from_results(tmp_path):
    from orbitlock import report
    res = json.loads((report.RESULTS / "results.json").read_text())
    md = report.render(res)
    for h in ("Threat model", "Attack success", "Cost of protection", "anomaly detection", "Residual risk"):
        assert h in md
    assert "Target met" in md
