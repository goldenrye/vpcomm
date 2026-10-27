"""Transport and audio lifecycle, independent of the desktop interface."""

import asyncio
import contextlib
import json
import ssl
import threading
from collections.abc import Callable
from urllib.parse import urlsplit

from websockets.asyncio.client import connect

from .crypto import AUDIO, CONFIRM, FRAME_BYTES, Handshake, Invitation, ProtocolError


def connection_options(url: str, ca_file: str | None = None) -> dict:
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"ws", "wss"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/relay"
    ):
        raise ValueError("Use wss://your-server/relay (no credentials, query, or fragment)")
    if parsed.scheme == "ws":
        if parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("Unencrypted WebSockets are allowed only on loopback")
        if ca_file:
            raise ValueError("A CA certificate requires wss://")
        return {}
    return {"ssl": ssl.create_default_context(cafile=ca_file)}


async def call(
    url: str,
    access_token: str,
    invitation: Invitation,
    audio,
    status: Callable[[str], None],
    *,
    ca_file: str | None = None,
):
    options = connection_options(url, ca_file)
    if len(access_token) < 32 or not access_token.isascii():
        raise ValueError("Enter the relay access token (at least 32 ASCII characters)")
    status("Connecting to relay...")
    async with connect(
        url,
        additional_headers={"Authorization": f"Bearer {access_token}"},
        max_size=1024,
        max_queue=4,
        write_limit=8192,
        compression=None,
        proxy=None,
        open_timeout=10,
        close_timeout=2,
        **options,
    ) as socket:
        await socket.send(json.dumps({"v": 1, "room": invitation.room_id}))
        async with asyncio.timeout(130):
            message = await socket.recv()
            if message == '{"type":"waiting"}':
                status("Waiting for the second participant (up to two minutes)...")
                message = await socket.recv()
            if message != '{"type":"ready"}':
                raise ProtocolError("Unexpected relay response")
        handshake = Handshake(invitation)
        async with asyncio.timeout(10):
            await socket.send(handshake.hello())
            cipher = handshake.finish(await socket.recv())
            await socket.send(cipher.encrypt(CONFIRM))
            if cipher.decrypt(await socket.recv()) != CONFIRM:
                raise ProtocolError("Peer key confirmation failed")
        status(f"Authenticated call. Verification: {cipher.code}")
        # Do not open the microphone before both endpoints confirm session keys.
        audio.start()

        async def send_audio():
            while True:
                frame = audio.capture()
                if frame is None:
                    await asyncio.sleep(0.005)
                    continue
                if len(frame) != FRAME_BYTES:
                    raise ProtocolError("Audio device returned an invalid frame")
                async with asyncio.timeout(3):
                    await socket.send(cipher.encrypt(AUDIO + frame))

        async def receive_audio():
            while True:
                async with asyncio.timeout(10):
                    packet = await socket.recv()
                plaintext = cipher.decrypt(packet)
                if len(plaintext) != FRAME_BYTES + 1 or plaintext[:1] != AUDIO:
                    raise ProtocolError("Unexpected encrypted payload")
                audio.play(plaintext[1:])

        try:
            async with asyncio.TaskGroup() as group:
                group.create_task(send_audio())
                group.create_task(receive_audio())
        finally:
            audio.close()


async def interruptible_call(*args, stop: threading.Event, **kwargs):
    task = asyncio.create_task(call(*args, **kwargs))
    try:
        while not task.done() and not stop.is_set():
            await asyncio.sleep(0.05)
        if stop.is_set():
            task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    finally:
        if not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
