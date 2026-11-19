#!/usr/bin/env python3
"""Send an RTMP connect command whose command object is nested DEPTH levels deep.

Without the AMF nesting limits, nginx-rtmp parses this recursively before any
authentication and a deep enough payload overflows the worker's stack (the
worker dies with signal 11 and takes every stream on it along). With the
limits, the worker logs "amf: tried to read object nested too deeply" and
closes only this connection.

    python3 test/amf_nesting.py HOST [PORT] [DEPTH] [APP]

Prints what the server did: "closed" (connection dropped) or "replied".
Only point this at a server you run.
"""
import os
import socket
import struct
import sys

host = sys.argv[1]
port = int(sys.argv[2]) if len(sys.argv) > 2 else 1935
depth = int(sys.argv[3]) if len(sys.argv) > 3 else 200000
app = sys.argv[4] if len(sys.argv) > 4 else "live"

CHUNK = 128


def amf_string(s):
    b = s.encode()
    return b"\x02" + struct.pack(">H", len(b)) + b


def key(s):
    b = s.encode()
    return struct.pack(">H", len(b)) + b


# connect(1, {app: ..., a: {a: {a: ... }}})
body = amf_string("connect") + b"\x00" + struct.pack(">d", 1.0)
body += b"\x03" + key("app") + amf_string(app)
body += (key("a") + b"\x03") * depth
body += b"\x00\x00\x09" * (depth + 1)

# Type 0 header on chunk stream 3, then type 3 continuation headers.
header = bytes([0x03]) + b"\x00\x00\x00" + struct.pack(">I", len(body))[1:] + b"\x14" + b"\x00\x00\x00\x00"
msg = bytearray(header)
for i in range(0, len(body), CHUNK):
    if i:
        msg.append(0xC3)
    msg += body[i:i + CHUNK]

s = socket.create_connection((host, port), timeout=10)
c1 = b"\x00" * 8 + os.urandom(1528)
s.sendall(b"\x03" + c1)
need = 1 + 1536 + 1536
got = b""
while len(got) < need:
    part = s.recv(need - len(got))
    if not part:
        sys.exit("handshake: server closed the connection")
    got += part
s.sendall(got[1:1 + 1536])  # C2 = S1

print(f"sending connect nested {depth} levels deep ({len(body)} bytes)")
try:
    s.sendall(bytes(msg))
    s.settimeout(5)
    reply = s.recv(4096)
    print("replied" if reply else "closed")
except (ConnectionResetError, BrokenPipeError):
    print("closed")
except socket.timeout:
    print("no reply within 5 s")
