"""Compact binary command / telemetry encodings (what travels as frame payload)."""
from __future__ import annotations

import struct

# opcodes
OP_SET_MODE = 0x01
OP_ATTITUDE = 0x02
OP_PAYLOAD = 0x03
OP_DOWNLINK = 0x04
OP_REKEY = 0x05
OP_PING = 0x06
OP_BURN = 0x07
OP_ROTATE = 0x08

OP_NAMES = {OP_SET_MODE: "SET_MODE", OP_ATTITUDE: "ADJUST_ATTITUDE", OP_PAYLOAD: "PAYLOAD",
            OP_DOWNLINK: "DOWNLINK", OP_REKEY: "REKEY", OP_PING: "PING", OP_BURN: "ORBIT_BURN",
            OP_ROTATE: "KEY_ROTATE"}
_ARGS = {OP_SET_MODE: ">B", OP_ATTITUDE: ">fff", OP_PAYLOAD: ">B", OP_DOWNLINK: ">H",
         OP_REKEY: "", OP_PING: "", OP_BURN: ">f", OP_ROTATE: ">H"}

MODES = ["SAFE", "NOMINAL", "SCIENCE", "COMMS"]

ACK_OK, ACK_INVALID, ACK_UNKNOWN = 0, 1, 2

_CMD_HEAD = struct.Struct(">IB")
_ACK = struct.Struct(">IBB")
_TLM = struct.Struct(">dBB9fIII")

TLM_FIELDS = ("t", "mode", "payload_on", "battery", "temp", "roll", "pitch", "yaw",
              "lat", "lon", "alt", "dv", "rx_frames", "rx_rejects", "last_cmd")


def encode_command(cmd_id: int, op: int, *args) -> bytes:
    fmt = _ARGS[op]
    return _CMD_HEAD.pack(cmd_id, op) + (struct.pack(fmt, *args) if fmt else b"")


def decode_command(data: bytes) -> dict:
    """Raises ValueError on garbage. args is a tuple (canonical, comparable)."""
    if len(data) < _CMD_HEAD.size:
        raise ValueError("short command")
    cmd_id, op = _CMD_HEAD.unpack_from(data)
    if op not in _ARGS:
        return dict(cmd_id=cmd_id, op=op, args=(), unknown=True)
    fmt = _ARGS[op]
    need = struct.calcsize(fmt) if fmt else 0
    body = data[_CMD_HEAD.size:]
    if len(body) < need:
        raise ValueError("short args")
    args = struct.unpack(fmt, body[:need]) if fmt else ()
    return dict(cmd_id=cmd_id, op=op, args=tuple(args), unknown=False)


def encode_ack(cmd_id: int, status: int, op: int) -> bytes:
    return _ACK.pack(cmd_id, status, op)


def decode_ack(data: bytes) -> dict:
    cmd_id, status, op = _ACK.unpack(data[:_ACK.size])
    return dict(cmd_id=cmd_id, status=status, op=op)


def encode_telemetry(t: dict) -> bytes:
    return _TLM.pack(t["t"], t["mode"], t["payload_on"], t["battery"], t["temp"], t["roll"],
                     t["pitch"], t["yaw"], t["lat"], t["lon"], t["alt"], t["dv"],
                     t["rx_frames"] & 0xFFFFFFFF, t["rx_rejects"] & 0xFFFFFFFF, t["last_cmd"])


def decode_telemetry(data: bytes) -> dict:
    if len(data) < _TLM.size:
        raise ValueError("short telemetry")
    return dict(zip(TLM_FIELDS, _TLM.unpack(data[:_TLM.size])))


def describe_command(cmd: dict) -> str:
    if cmd.get("unknown"):
        return f"UNKNOWN_OP(0x{cmd['op']:02X})"
    name = OP_NAMES[cmd["op"]]
    a = cmd["args"]
    if cmd["op"] == OP_SET_MODE:
        m = MODES[a[0]] if a[0] < len(MODES) else f"?{a[0]}"
        return f"{name}({m})"
    if cmd["op"] == OP_PAYLOAD:
        return f"{name}({'ON' if a[0] else 'OFF'})"
    if not a:
        return f"{name}()"
    return f"{name}({', '.join(f'{x:g}' for x in a)})"
