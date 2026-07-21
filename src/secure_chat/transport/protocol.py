"""Length-prefixed JSON framing.

TCP is a byte stream with no message boundaries, so a single ``recv`` may return
a partial message or several concatenated ones. We prefix every payload with a
4-byte big-endian length so the receiver always reads exactly one message.

Frame layout::

    [4-byte big-endian length N][N bytes of UTF-8 JSON]
"""
import json
import struct
from typing import Any

# Reject absurd frame sizes early to avoid a malicious peer forcing a huge
# allocation (a simple denial-of-service guard).
MAX_FRAME_BYTES = 1 << 20  # 1 MiB


def send_json(sock, obj: Any) -> None:
    """Serialize ``obj`` to JSON and send it as a single length-prefixed frame."""
    data = json.dumps(obj).encode()
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)


def recv_json(sock) -> Any | None:
    """Read exactly one framed JSON message. Returns None if the peer closed."""
    header = _recv_exact(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack(">I", header)
    if length > MAX_FRAME_BYTES:
        raise ValueError(f"Frame too large: {length} bytes (max {MAX_FRAME_BYTES})")
    payload = _recv_exact(sock, length)
    if payload is None:
        return None
    return json.loads(payload.decode())


def _recv_exact(sock, n: int) -> bytes | None:
    """Read exactly ``n`` bytes, or return None if the connection closes first."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)
