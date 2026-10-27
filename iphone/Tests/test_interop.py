"""Run with VPCOMM_IPHONE_PROBE pointing to the compiled macOS probe."""

import asyncio
import json
import os
import ssl
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve

from vpcomm.crypto import AUDIO, CONFIRM, Handshake, Invitation
from vpcomm.server import Relay

PROBE = os.environ.get("VPCOMM_IPHONE_PROBE")
pytestmark = pytest.mark.skipif(
    not PROBE, reason="Set VPCOMM_IPHONE_PROBE to the compiled Swift probe"
)
TOKEN = "iphone-test-only-" + "a" * 40


def tls_fixture(path, expired=False):
    now = datetime.now(UTC)
    ca_key, key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(2))
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(issuer)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=3))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), True
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False), True
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ip_address("127.0.0.1"))]), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    root, cert, private = (path / name for name in ("root.pem", "leaf.pem", "key.pem"))
    root.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, private)
    return context, root


async def probe(url, invitation, root=None, token=TOKEN, cancel=False):
    process = await asyncio.create_subprocess_exec(
        PROBE,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    config = dict(
        address=url,
        token=token,
        invitation=invitation.export(),
        root=str(root) if root else None,
        cancel=cancel,
    )
    try:
        async with asyncio.timeout(15):
            output, errors = await process.communicate(json.dumps(config).encode())
        return process.returncode, output.decode(), errors.decode()
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


@pytest.mark.parametrize("tls", [False, True])
async def test_python_swift_bidirectional_audio(tmp_path, tls):
    relay = Relay(TOKEN)
    invitation = Invitation.create()
    context, root = tls_fixture(tmp_path) if tls else (None, None)
    async with serve(
        relay.handle, "127.0.0.1", 0, ssl=context, process_request=relay.authorize, compression=None
    ) as server:
        url = f"{'wss' if tls else 'ws'}://127.0.0.1:{server.sockets[0].getsockname()[1]}/relay"
        task = asyncio.create_task(probe(url, invitation, root))
        try:
            options = {"ssl": ssl.create_default_context(cafile=str(root))} if tls else {}
            async with asyncio.timeout(15):
                async with connect(
                    url,
                    additional_headers={"Authorization": f"Bearer {TOKEN}"},
                    proxy=None,
                    compression=None,
                    **options,
                ) as socket:
                    await socket.send(json.dumps({"v": 1, "room": invitation.room_id}))
                    response = json.loads(await socket.recv())
                    if response["type"] == "waiting":
                        response = json.loads(await socket.recv())
                    assert response["type"] == "ready"
                    exchange = Handshake(invitation)
                    await socket.send(exchange.hello())
                    keys = exchange.finish(await socket.recv())
                    await socket.send(keys.encrypt(CONFIRM))
                    assert keys.decrypt(await socket.recv()) == CONFIRM
                    for _ in range(10):
                        assert keys.decrypt(await socket.recv()) == AUDIO + b"\x12\x34" * 320
                        await socket.send(keys.encrypt(AUDIO + b"\x56\x78" * 320))
                    code, output, errors = await task
                    assert code == 0, errors + output
                    assert output.strip() == f"PASS {keys.code}"
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("failure", ["untrusted", "hostname", "expired", "token"])
async def test_tls_and_authentication_rejections(tmp_path, failure):
    context, root = tls_fixture(tmp_path, expired=failure == "expired")
    relay = Relay(TOKEN)
    async with serve(
        relay.handle, "127.0.0.1", 0, ssl=context, process_request=relay.authorize
    ) as server:
        host = "localhost" if failure == "hostname" else "127.0.0.1"
        url = f"wss://{host}:{server.sockets[0].getsockname()[1]}/relay"
        code, output, _ = await probe(
            url,
            Invitation.create(),
            None if failure == "untrusted" else root,
            token="b" * 40 if failure == "token" else TOKEN,
        )
        assert code != 0 and output.startswith("FAIL")
        assert not relay.rooms


@pytest.mark.parametrize("cancel", [False, True])
async def test_stalled_connection_deadline_and_hangup(cancel):
    async def stall(socket):
        await socket.wait_closed()

    async with serve(stall, "127.0.0.1", 0) as server:
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}/relay"
        async with asyncio.timeout(14 if not cancel else 3):
            code, output, _ = await probe(url, Invitation.create(), cancel=cancel)
        assert code != 0 and output.startswith("FAIL")
