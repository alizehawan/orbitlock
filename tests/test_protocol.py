import os, pytest
from orbitlock import protocol as P

PSK = os.urandom(32)

def pair():
    g = P.GroundHandshake(1, PSK); s = P.SatelliteHandshake(1, PSK)
    reply, sch = s.respond(g.make_hello())
    return g.finish(reply), sch

def test_roundtrip_and_overhead():
    g, s = pair()
    f = g.protect(P.F_CMD, 0, b"hello")
    assert len(f) == P.HEADER_LEN + 5 + P.TAG_LEN
    h, pt = s.unprotect(f)
    assert pt == b"hello" and h.seq == 0
    h, pt = g.unprotect(s.protect(P.F_ACK, 0, b"ok")); assert pt == b"ok"

def test_tamper_header_and_body():
    g, s = pair()
    f = g.protect(P.F_CMD, 0, b"hello")
    for i in range(len(f)):
        b = bytearray(f); b[i] ^= 1
        with pytest.raises(P.FrameRejected):
            s.unprotect(bytes(b))
    s.unprotect(f)  # original still fine (failed attempts must not burn the seq)

def test_replay_and_window():
    g, s = pair()
    frames = [g.protect(P.F_CMD, 0, bytes([i])) for i in range(100)]
    s.unprotect(frames[0])
    with pytest.raises(P.FrameRejected) as e: s.unprotect(frames[0])
    assert e.value.reason == P.R_REPLAY
    s.unprotect(frames[90])
    s.unprotect(frames[70])                       # reorder inside window ok
    with pytest.raises(P.FrameRejected) as e: s.unprotect(frames[70])
    assert e.value.reason == P.R_REPLAY
    with pytest.raises(P.FrameRejected) as e: s.unprotect(frames[5])
    assert e.value.reason == P.R_OUT_OF_WINDOW

def test_wrong_keys_forgery():
    g, s = pair()
    g2, _ = pair()
    with pytest.raises(P.FrameRejected) as e: s.unprotect(g2.protect(P.F_CMD, 0, b"x"))
    assert e.value.reason == P.R_BAD_TAG

def test_direction_separation():
    g, s = pair()
    f = g.protect(P.F_CMD, 0, b"x")
    with pytest.raises(P.FrameRejected): g.unprotect(f)   # reflection fails

def test_rotation_and_old_epoch_replay():
    g, s = pair()
    old = g.protect(P.F_CMD, 0, b"old")
    s.unprotect(old)
    g.rotate(); s.rotate()
    new = g.protect(P.F_CMD, 0, b"new")
    assert new[5:7] == b"\x00\x01"
    s.unprotect(new)
    with pytest.raises(P.FrameRejected) as e: s.unprotect(old)
    assert e.value.reason in (P.R_UNKNOWN_EPOCH, P.R_REPLAY)

def test_rotation_lookahead_when_rotate_cmd_lost():
    g, s = pair()
    g.rotate()                                   # satellite never told
    h, pt = s.unprotect(g.protect(P.F_CMD, 0, b"x"))
    assert h.epoch == 1 and s.tx_epoch == 1
    g.unprotect(s.protect(P.F_ACK, 0, b"y"))

def test_clear_frame_refused_on_secure_link():
    g, s = pair()
    plain = P.PlainChannel(1, "ground").protect(P.F_CMD, 0, b"x")
    with pytest.raises(P.FrameRejected) as e: s.unprotect(plain)
    assert e.value.reason == P.R_CLEAR_FRAME

def test_handshake_replay_and_bad_psk():
    g = P.GroundHandshake(1, PSK); s = P.SatelliteHandshake(1, PSK)
    hello = g.make_hello()
    s.respond(hello)
    with pytest.raises(P.FrameRejected) as e: s.respond(hello)
    assert e.value.reason == P.R_STALE_HANDSHAKE
    bad = P.GroundHandshake(1, os.urandom(32)).make_hello()
    with pytest.raises(P.FrameRejected) as e: s.respond(bad)
    assert e.value.reason == P.R_BAD_HANDSHAKE
