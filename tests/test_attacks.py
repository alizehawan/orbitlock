"""End-to-end: every attack must succeed on the clear link and fail on the secured one."""
import time
import pytest
from orbitlock import messages as M
from orbitlock.sim import Simulation


@pytest.fixture(params=[False, True], ids=["clear", "secured"])
def sim(request):
    s = Simulation(secure=request.param, with_detector=False, seed=1)
    assert s.wait_for(lambda: s.ground.link_up, 3)
    yield s
    s.shutdown()


def settle(sim, t=0.15):
    time.sleep(t)


def test_normal_operation(sim):
    ack = sim.command_and_wait(M.OP_SET_MODE, 2)
    assert ack and ack["status"] == M.ACK_OK
    assert sim.satellite.state()["mode"] == "SCIENCE"
    assert sim.wait_for(lambda: sim.ground.latest() is not None, 2)


def test_spoofing(sim):
    sim.command_and_wait(M.OP_PING)          # let the attacker observe traffic
    sim.attacker.forge_command(M.OP_BURN, 20.0)
    settle(sim)
    ok = sim.impact_snapshot()["counts"]["spoofed"]
    assert (ok > 0) == (not sim.secure_flag) if hasattr(sim, "secure_flag") else True
    if sim.ground.secure:
        assert ok == 0 and sim.log.reasons("satellite").get("bad_tag", 0) >= 1
    else:
        assert ok == 1 and sim.satellite.state()["dv"] == 20.0


def test_replay(sim):
    sim.command_and_wait(M.OP_PAYLOAD, 1)
    sim.command_and_wait(M.OP_PAYLOAD, 0)
    sim.attacker.replay()                    # replays last captured uplink command (PAYLOAD off) ...
    first = sim.attacker.last_up_cmd_capture
    sim.command_and_wait(M.OP_PAYLOAD, 1)
    sim.attacker.replay(first)               # ... now replay an older one: PAYLOAD(OFF) again
    settle(sim)
    counts = sim.impact_snapshot()["counts"]
    if sim.ground.secure:
        assert counts["replayed"] == 0
        assert sim.log.reasons("satellite").get("replay", 0) >= 1
        assert sim.satellite.state()["payload_on"] is True
    else:
        assert counts["replayed"] >= 1
        assert sim.satellite.state()["payload_on"] is False


def test_bitflip_tamper(sim):
    sim.command_and_wait(M.OP_PING)
    sim.attacker.arm_tamper(1)
    sim.ground.send_command(M.OP_SET_MODE, 1)
    settle(sim)
    counts = sim.impact_snapshot()["counts"]
    if sim.ground.secure:
        assert counts["tampered"] == 0 and sim.satellite.state()["mode"] == "NOMINAL"
        assert sim.log.reasons("satellite").get("bad_tag", 0) >= 1
    else:
        assert counts["tampered"] == 1 and sim.satellite.state()["mode"] == "SAFE"


def test_eavesdropping(sim):
    sim.command_and_wait(M.OP_SET_MODE, 2)
    time.sleep(0.6)
    caps = [c for c in sim.attacker.snapshot(40)["captures"] if c["hdr"] and c["hdr"]["type"] in ("CMD", "TLM")]
    assert caps
    readable = [c["decoded"]["readable"] for c in caps]
    assert all(readable) if not sim.ground.secure else not any(readable)


def test_telemetry_spoof(sim):
    time.sleep(0.6)
    sim.attacker.forge_telemetry(battery=99.0)
    settle(sim)
    assert (sim.ground.spoofed_accepted > 0) == (not sim.ground.secure)


def test_downgrade_clear_frame(sim):
    sim.command_and_wait(M.OP_PING)
    sim.attacker.forge_clear_command(M.OP_BURN, 5.0)
    settle(sim)
    if sim.ground.secure:
        assert sim.impact_snapshot()["counts"]["spoofed"] == 0
        assert sim.log.reasons("satellite").get("clear_frame_on_secure_link", 0) >= 1


def test_rotation_and_rekey_keep_link_alive():
    s = Simulation(secure=True, with_detector=False, seed=2)
    try:
        assert s.ground.link_up
        assert s.command_and_wait(M.OP_PING)["status"] == 0
        assert s.ground.rotate_keys()
        assert s.command_and_wait(M.OP_PING)["status"] == 0
        assert s.ground.link_info()["epoch"] == 1
        assert s.ground.emergency_rekey()
        assert s.command_and_wait(M.OP_PING)["status"] == 0
        assert s.ground.link_info()["epoch"] == 0     # fresh session
        assert s.satellite.state()["session_count"] == 2
    finally:
        s.shutdown()


def test_drop_is_dos_in_both_modes(sim):
    sim.attacker.set_drop(up=True)
    cid = sim.ground.send_command(M.OP_PING)
    settle(sim, 0.3)
    assert cid not in sim.ground.acks
