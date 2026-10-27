import asyncio
import json
import ssl
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed, InvalidStatus

from vpcomm.client import call, connection_options
from vpcomm.crypto import Invitation
from vpcomm.server import Relay, build_server

TOKEN = "test-access-token-" + "a" * 32


@asynccontextmanager
async def running_relay(**kwargs):
    relay = Relay(TOKEN, **kwargs)
    async with build_server(relay, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        yield relay, f"ws://127.0.0.1:{port}/relay"


def socket(url, token=TOKEN, **kwargs):
    return connect(
        url,
        additional_headers={"Authorization": f"Bearer {token}"},
        proxy=None,
        compression=None,
        **kwargs,
    )


async def join(ws, room):
    await ws.send(json.dumps({"v": 1, "room": room}))


async def test_authentication_and_origin_rejection():
    async with running_relay() as (_, url):
        for options in ({"token": "wrong"}, {"origin": "https://example.com"}):
            with pytest.raises(InvalidStatus) as failure:
                async with socket(url, **options):
                    pass
            assert failure.value.response.status_code in {401, 403}
        with pytest.raises(InvalidStatus) as failure:
            async with socket(url + "?secret=bad"):
                pass
        assert failure.value.response.status_code == 404


async def test_two_peers_relay_third_rejected_and_cleanup():
    async with running_relay() as (relay, url):
        room = Invitation.create().room_id
        async with socket(url) as alice, socket(url) as bob:
            await join(alice, room)
            assert json.loads(await alice.recv())["type"] == "waiting"
            await join(bob, room)
            assert json.loads(await alice.recv())["type"] == "ready"
            assert json.loads(await bob.recv())["type"] == "ready"
            async with socket(url) as third:
                await join(third, room)
                with pytest.raises(ConnectionClosed):
                    await third.recv()
            await alice.send(b"opaque encrypted frame")
            assert await bob.recv() == b"opaque encrypted frame"
            await bob.send(b"reverse direction")
            assert await alice.recv() == b"reverse direction"
            await alice.close()
            with pytest.raises(ConnectionClosed):
                await bob.recv()
        async with asyncio.timeout(2):
            while relay.rooms or relay.connections:
                await asyncio.sleep(0.01)


async def test_waiting_timeout():
    async with running_relay(wait_timeout=0.05) as (_, url), socket(url) as alice:
        await join(alice, Invitation.create().room_id)
        await alice.recv()
        with pytest.raises(ConnectionClosed):
            await alice.recv()


async def test_waiting_disconnect_cleans_room():
    async with running_relay() as (relay, url):
        async with socket(url) as alice:
            await join(alice, Invitation.create().room_id)
            await alice.recv()
        async with asyncio.timeout(1):
            while relay.rooms:
                await asyncio.sleep(0.01)


@pytest.mark.parametrize("payload", ["[]", "null", "{}", '{"v":1,"room":"bad"}', b"\0"])
async def test_malformed_join(payload):
    async with running_relay() as (_, url), socket(url) as alice:
        await alice.send(payload)
        with pytest.raises(ConnectionClosed):
            await alice.recv()


async def test_rooms_are_isolated():
    async with running_relay() as (_, url):
        async with socket(url) as alice, socket(url) as bob:
            await join(alice, Invitation.create().room_id)
            await join(bob, Invitation.create().room_id)
            assert json.loads(await alice.recv())["type"] == "waiting"
            assert json.loads(await bob.recv())["type"] == "waiting"
            with pytest.raises(TimeoutError):
                async with asyncio.timeout(0.05):
                    await bob.recv()


async def test_capacity_is_bounded():
    async with running_relay(max_connections=2) as (_, url):
        async with socket(url) as alice, socket(url) as bob:
            await join(alice, Invitation.create().room_id)
            await join(bob, Invitation.create().room_id)
            await alice.recv()
            await bob.recv()
            async with socket(url) as third:
                with pytest.raises(ConnectionClosed):
                    await third.recv()


@pytest.mark.parametrize("bad_frame", ["plaintext", b"x" * 1025])
async def test_invalid_relay_frames_end_call(bad_frame):
    async with running_relay() as (_, url):
        async with socket(url) as alice, socket(url) as bob:
            room = Invitation.create().room_id
            await join(alice, room)
            await alice.recv()
            await join(bob, room)
            await asyncio.gather(alice.recv(), bob.recv())
            await alice.send(bad_frame)
            with pytest.raises(ConnectionClosed):
                await bob.recv()


async def test_call_duration_limit():
    async with running_relay(call_timeout=0.05) as (_, url):
        async with socket(url) as alice, socket(url) as bob:
            room = Invitation.create().room_id
            await join(alice, room)
            await alice.recv()
            await join(bob, room)
            await asyncio.gather(alice.recv(), bob.recv())
            with pytest.raises(ConnectionClosed):
                await bob.recv()


async def test_frame_rate_limit():
    async with running_relay() as (_, url):
        async with socket(url) as alice, socket(url) as bob:
            room = Invitation.create().room_id
            await join(alice, room)
            await alice.recv()
            await join(bob, room)
            await asyncio.gather(alice.recv(), bob.recv())

            async def flood():
                try:
                    for _ in range(500):
                        await alice.send(b"x")
                except ConnectionClosed:
                    pass

            sender = asyncio.create_task(flood())
            try:
                async with asyncio.timeout(3):
                    with pytest.raises(ConnectionClosed):
                        while True:
                            await bob.recv()
                assert bob.close_code == 1000
                assert alice.close_code == 1008
            finally:
                sender.cancel()
                await asyncio.gather(sender, return_exceptions=True)


class SyntheticAudio:
    def __init__(self, frame, expected):
        self.frame = frame
        self.expected = expected
        self.started = False
        self.closed = False
        self.received = 0
        self.next_frame = 0.0
        self.enough = asyncio.Event()

    def start(self):
        self.started = True

    def capture(self):
        if time.monotonic() < self.next_frame:
            return None
        self.next_frame = time.monotonic() + 0.02
        return self.frame

    def play(self, frame):
        assert self.started
        assert frame == self.expected
        self.received += 1
        if self.received >= 10:
            self.enough.set()

    def close(self):
        self.closed = True


async def test_real_clients_exchange_encrypted_audio_through_relay():
    async with running_relay() as (_, url):
        invitation = Invitation.create()
        first, second = b"\x00\x10" * 320, b"\x00\x20" * 320
        alice, bob = SyntheticAudio(first, second), SyntheticAudio(second, first)
        statuses = [[], []]
        tasks = [
            asyncio.create_task(call(url, TOKEN, invitation, device, statuses[i].append))
            for i, device in enumerate([alice, bob])
        ]
        try:
            async with asyncio.timeout(5):
                await asyncio.gather(alice.enough.wait(), bob.enough.wait())
            assert statuses[0][-1] == statuses[1][-1]
            assert "Authenticated" in statuses[0][-1]
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        assert alice.closed and bob.closed


async def test_wrong_secret_never_opens_microphone():
    async with running_relay() as (_, url):
        invitation = Invitation.create()
        impostor = Invitation(invitation.room, Invitation.create().secret)
        alice, bob = SyntheticAudio(b"", b""), SyntheticAudio(b"", b"")
        async with asyncio.timeout(5):
            results = await asyncio.gather(
                call(url, TOKEN, invitation, alice, lambda _: None),
                call(url, TOKEN, impostor, bob, lambda _: None),
                return_exceptions=True,
            )
        assert all(isinstance(result, Exception) for result in results)
        assert not alice.started and not bob.started


@pytest.mark.parametrize(
    "url",
    [
        "ws://example.com/relay",
        "https://example.com/relay",
        "wss://user:pw@example.com/relay",
        "wss://example.com/relay?secret=x",
        "wss://example.com/relay#x",
        "wss://example.com/",
    ],
)
def test_client_rejects_unsafe_addresses(url):
    with pytest.raises(ValueError):
        connection_options(url)


def test_client_requires_tls_except_loopback():
    assert connection_options("ws://127.0.0.1:8765/relay") == {}
    context = connection_options("wss://example.com/relay")["ssl"]
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname


async def test_tls_untrusted_rejected_and_private_ca_audio_succeeds(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "VPComm test CA")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ip_address("127.0.0.1"))]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp_path / "ca.pem", tmp_path / "key.pem"
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert_file, key_file)
    relay = Relay(TOKEN)
    async with serve(
        relay.handle,
        "127.0.0.1",
        0,
        ssl=tls,
        process_request=relay.authorize,
        compression=None,
        max_size=1024,
    ) as server:
        url = f"wss://127.0.0.1:{server.sockets[0].getsockname()[1]}/relay"
        invitation = Invitation.create()
        with pytest.raises(ssl.SSLCertVerificationError):
            await call(url, TOKEN, invitation, SyntheticAudio(b"", b""), lambda _: None)
        # The explicitly trusted certificate still must match the server hostname.
        wrong_host = url.replace("127.0.0.1", "localhost")
        with pytest.raises(ssl.SSLCertVerificationError):
            await call(
                wrong_host,
                TOKEN,
                invitation,
                SyntheticAudio(b"", b""),
                lambda _: None,
                ca_file=str(cert_file),
            )
        frame = b"\x00\x10" * 320
        alice, bob = SyntheticAudio(frame, frame), SyntheticAudio(frame, frame)
        tasks = [
            asyncio.create_task(
                call(url, TOKEN, invitation, audio, lambda _: None, ca_file=str(cert_file))
            )
            for audio in (alice, bob)
        ]
        try:
            async with asyncio.timeout(5):
                await asyncio.gather(alice.enough.wait(), bob.enough.wait())
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        assert alice.closed and bob.closed
