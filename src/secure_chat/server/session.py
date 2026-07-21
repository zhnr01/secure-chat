"""Connected-client bookkeeping for the server.

A ``ClientSession`` groups everything the relay needs to know about one
connected client. The ``SessionRegistry`` owns the set of active sessions and
guards it with a lock, since clients are handled on separate threads.
"""
import socket
import threading
from dataclasses import dataclass

from ..crypto.cipher import SessionKeys
from ..crypto.ecc import S256Point


@dataclass
class ClientSession:
    """One connected client: its socket, address, public key, and session keys."""

    connection: socket.socket
    address: tuple
    public_key: S256Point
    keys: SessionKeys

    @property
    def label(self) -> str:
        host, port = self.address[0], self.address[1]
        return f"{host}:{port}"


class SessionRegistry:
    """Thread-safe collection of the currently connected sessions."""

    def __init__(self) -> None:
        self._sessions: list[ClientSession] = []
        self._lock = threading.Lock()

    def add(self, session: ClientSession) -> None:
        with self._lock:
            self._sessions.append(session)

    def remove(self, session: ClientSession) -> None:
        with self._lock:
            if session in self._sessions:
                self._sessions.remove(session)

    def others(self, exclude: ClientSession) -> list[ClientSession]:
        """Return a snapshot of every session except ``exclude``."""
        with self._lock:
            return [s for s in self._sessions if s is not exclude]
