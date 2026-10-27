"""Version-one wire crypto. Experimental protocol, not independently audited."""

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CONTEXT = b"vpcomm/v1/x25519-hkdf-sha256-aes256gcm/pcm16le-16000-320"
CONFIRM = b"\x00vpcomm/v1/confirmed"
AUDIO = b"\x01"
FRAME_BYTES = 640


class ProtocolError(ValueError):
    """Untrusted or unexpected peer data."""


def encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def decode(value: str, size: int) -> bytes:
    if not isinstance(value, str) or len(value) != (size * 8 + 5) // 6:
        raise ProtocolError("Invalid encoded value")
    try:
        result = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, UnicodeError) as exc:
        raise ProtocolError("Invalid encoded value") from exc
    if len(result) != size or encode(result) != value:
        raise ProtocolError("Non-canonical encoded value")
    return result


@dataclass(frozen=True, repr=False)
class Invitation:
    room: bytes
    secret: bytes

    @classmethod
    def create(cls) -> "Invitation":
        return cls(secrets.token_bytes(16), secrets.token_bytes(32))

    @classmethod
    def parse(cls, value: str) -> "Invitation":
        parts = value.strip().split(".")
        if len(parts) != 3 or parts[0] != "vp1":
            raise ProtocolError("Expected a vp1 invitation")
        return cls(decode(parts[1], 16), decode(parts[2], 32))

    def export(self) -> str:
        return f"vp1.{encode(self.room)}.{encode(self.secret)}"

    @property
    def room_id(self) -> str:
        return encode(self.room)


class Handshake:
    def __init__(self, invitation: Invitation):
        self.invitation = invitation
        self.private = X25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def _proof(self, public: bytes) -> bytes:
        return hmac.digest(
            self.invitation.secret, CONTEXT + self.invitation.room + public, "sha256"
        )

    def hello(self) -> bytes:
        return json.dumps(
            {"v": 1, "public": encode(self.public), "proof": encode(self._proof(self.public))},
            separators=(",", ":"),
        ).encode("ascii")

    def finish(self, message: bytes) -> "SessionCipher":
        if not isinstance(message, bytes) or len(message) > 512:
            raise ProtocolError("Invalid handshake frame")
        try:
            data = json.loads(message)
            if not isinstance(data, dict) or data.get("v") != 1:
                raise ProtocolError("Unsupported handshake")
            peer = decode(data["public"], 32)
            proof = decode(data["proof"], 32)
        except (ValueError, KeyError, TypeError) as exc:
            raise ProtocolError("Invalid handshake") from exc
        if peer == self.public or not hmac.compare_digest(proof, self._proof(peer)):
            raise ProtocolError("Peer authentication failed; invitation mismatch or tampering")
        transcript = CONTEXT + self.invitation.room + b"".join(sorted([self.public, peer]))
        try:
            shared = self.private.exchange(X25519PublicKey.from_public_bytes(peer))
        except ValueError as exc:
            raise ProtocolError("Invalid peer key") from exc
        material = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=self.invitation.secret,
            info=transcript,
        ).derive(shared)
        low, high = material[:32], material[32:]
        tx, rx = (low, high) if self.public < peer else (high, low)
        code = hashlib.sha256(b"verification" + transcript + material).hexdigest()[:24]
        return SessionCipher(tx, rx, hashlib.sha256(transcript).digest(), code)


class SessionCipher:
    def __init__(self, tx: bytes, rx: bytes, aad: bytes, code: str):
        self._tx = AESGCM(tx)
        self._rx = AESGCM(rx)
        self._aad = aad
        self._sent = 0
        self._received = 0
        self.code = "-".join(code[i : i + 4] for i in range(0, len(code), 4))

    def encrypt(self, plaintext: bytes) -> bytes:
        if self._sent >= 2**32:
            raise ProtocolError("Session frame limit reached; start a new call")
        if len(plaintext) > FRAME_BYTES + 1:
            raise ProtocolError("Oversized audio frame")
        counter = self._sent.to_bytes(8, "big")
        ciphertext = self._tx.encrypt(b"\0" * 4 + counter, plaintext, self._aad + counter)
        self._sent += 1
        return counter + ciphertext

    def decrypt(self, packet: bytes) -> bytes:
        if not isinstance(packet, bytes) or not 24 <= len(packet) <= FRAME_BYTES + 25:
            raise ProtocolError("Invalid encrypted frame")
        counter = packet[:8]
        if int.from_bytes(counter, "big") != self._received or self._received >= 2**32:
            raise ProtocolError("Replayed or out-of-order frame")
        try:
            plaintext = self._rx.decrypt(b"\0" * 4 + counter, packet[8:], self._aad + counter)
        except InvalidTag as exc:
            raise ProtocolError("Audio authentication failed") from exc
        self._received += 1
        return plaintext
