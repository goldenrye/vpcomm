"""Bounded, in-memory WebSocket relay. No media decoding or persistence."""

import argparse
import asyncio
import contextlib
import hmac
import json
import logging
import os
import re
import signal
import time
from dataclasses import dataclass, field
from http import HTTPStatus

from websockets.asyncio.server import ServerConnection, serve
from websockets.exceptions import ConnectionClosed

LOG = logging.getLogger("vpcomm")
ROOM_PATTERN = re.compile(r"[A-Za-z0-9_-]{22}")


@dataclass
class Room:
    peers: list[ServerConnection] = field(default_factory=list)
    ready: asyncio.Event = field(default_factory=asyncio.Event)
    closed: bool = False


class Relay:
    def __init__(
        self,
        access_token: str,
        *,
        max_connections: int = 32,
        wait_timeout: float = 120,
        call_timeout: float = 3600,
    ):
        if len(access_token) < 32 or not access_token.isascii():
            raise ValueError("Access token must be at least 32 ASCII characters")
        if max_connections < 2 or wait_timeout <= 0 or call_timeout <= 0:
            raise ValueError("Invalid relay limits")
        self.access_token = access_token
        self.max_connections = max_connections
        self.wait_timeout = wait_timeout
        self.call_timeout = call_timeout
        self.rooms: dict[str, Room] = {}
        self.connections = 0

    def authorize(self, connection, request):
        if request.path == "/healthz":
            return connection.respond(HTTPStatus.OK, "ok\n")
        if request.path != "/relay":
            return connection.respond(HTTPStatus.NOT_FOUND, "not found\n")
        # This is a native client endpoint; disallow browser-originated sockets.
        if request.headers.get_all("Origin"):
            return connection.respond(HTTPStatus.FORBIDDEN, "native clients only\n")
        values = request.headers.get_all("Authorization")
        expected = f"Bearer {self.access_token}".encode("ascii")
        if len(values) != 1 or not hmac.compare_digest(values[0].encode("utf-8"), expected):
            return connection.respond(HTTPStatus.UNAUTHORIZED, "unauthorized\n")
        return None

    async def handle(self, socket: ServerConnection):
        if self.connections >= self.max_connections:
            await socket.close(1013, "Relay at capacity")
            return
        self.connections += 1
        room = None
        room_id = None
        try:
            async with asyncio.timeout(10):
                raw = await socket.recv()
            if not isinstance(raw, str) or len(raw) > 128:
                raise ValueError("Invalid join")
            request = json.loads(raw)
            if not isinstance(request, dict) or set(request) != {"v", "room"}:
                raise ValueError("Invalid join")
            room_id = request["room"]
            if request["v"] != 1 or not isinstance(room_id, str):
                raise ValueError("Invalid join")
            if not ROOM_PATTERN.fullmatch(room_id):
                raise ValueError("Invalid room")
            candidate = self.rooms.setdefault(room_id, Room())
            if candidate.closed or len(candidate.peers) >= 2:
                await socket.close(1008, "Room unavailable")
                return
            room = candidate
            room.peers.append(socket)
            if len(room.peers) == 2:
                # Both ready messages must precede any relayed handshake.
                await asyncio.gather(*(peer.send('{"type":"ready"}') for peer in room.peers))
                room.ready.set()
            else:
                await socket.send('{"type":"waiting"}')
            async with asyncio.timeout(self.wait_timeout):
                ready = asyncio.create_task(room.ready.wait())
                disconnected = asyncio.create_task(socket.wait_closed())
                try:
                    await asyncio.wait([ready, disconnected], return_when=asyncio.FIRST_COMPLETED)
                    if disconnected.done() or room.closed:
                        return
                finally:
                    ready.cancel()
                    disconnected.cancel()
                    await asyncio.gather(ready, disconnected, return_exceptions=True)
            other = next(peer for peer in room.peers if peer is not socket)
            tokens = 100.0
            last = time.monotonic()
            async with asyncio.timeout(self.call_timeout):
                async for frame in socket:
                    now = time.monotonic()
                    tokens = min(100.0, tokens + (now - last) * 60)
                    last = now
                    if not isinstance(frame, bytes) or not 1 <= len(frame) <= 1024 or tokens < 1:
                        await socket.close(1008, "Frame policy violation")
                        return
                    tokens -= 1
                    if other.transport.get_write_buffer_size() > 65536:
                        await socket.close(1013, "Peer too slow")
                        return
                    async with asyncio.timeout(3):
                        await other.send(frame)
        except (ValueError, TypeError, TimeoutError):
            await socket.close(1008, "Invalid request or time limit")
        except ConnectionClosed:
            pass
        finally:
            self.connections -= 1
            if room is not None:
                room.closed = True
                room.ready.set()
                # Keep the closed room reserved until both old sockets are gone.
                await asyncio.gather(
                    *(peer.close(1000, "Call ended") for peer in room.peers),
                    return_exceptions=True,
                )
                if self.rooms.get(room_id) is room:
                    self.rooms.pop(room_id)


def build_server(relay: Relay, host: str, port: int):
    return serve(
        relay.handle,
        host,
        port,
        process_request=relay.authorize,
        max_size=1024,
        max_queue=4,
        write_limit=8192,
        compression=None,
        open_timeout=5,
        close_timeout=2,
        ping_interval=20,
        ping_timeout=20,
        server_header=None,
        # Never enable protocol DEBUG logging: it includes frames and credentials.
        logger=LOG,
    )


async def run(args):
    token = os.environ.get("VPCOMM_ACCESS_TOKEN", "")
    relay = Relay(
        token,
        max_connections=args.max_connections,
        wait_timeout=args.wait_timeout,
        call_timeout=args.call_timeout,
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)
    async with build_server(relay, args.host, args.port):
        LOG.warning(
            "Relay listening on %s:%s; TLS must terminate at the reverse proxy",
            args.host,
            args.port,
        )
        await stop.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--max-connections", type=int, default=32)
    parser.add_argument("--wait-timeout", type=float, default=120)
    parser.add_argument("--call-timeout", type=float, default=3600)
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    try:
        asyncio.run(run(args))
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Relay configuration/startup error: {exc}\n")


if __name__ == "__main__":
    main()
