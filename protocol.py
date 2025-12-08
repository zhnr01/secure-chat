import json
import struct
from typing import Any

# Simple length-prefixed framing: [4-byte big-endian length][payload bytes]

def send_json(sock, obj: Any):
    data = json.dumps(obj).encode()
    header = struct.pack('>I', len(data))
    sock.sendall(header + data)


def recv_json(sock):
    header = _recv_exact(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack('>I', header)
    payload = _recv_exact(sock, length)
    if payload is None:
        return None
    return json.loads(payload.decode())


def _recv_exact(sock, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)
