import json

import pytest

from vpcomm.crypto import CONFIRM, Handshake, Invitation, ProtocolError, decode, encode


def pair():
    invitation = Invitation.create()
    alice, bob = Handshake(invitation), Handshake(invitation)
    return alice.finish(bob.hello()), bob.finish(alice.hello())


def test_invitation_round_trip():
    invitation = Invitation.create()
    assert Invitation.parse(invitation.export()) == invitation
    assert invitation.secret.hex() not in repr(invitation)


@pytest.mark.parametrize("value", ["", "vp0.a.b", "vp1.a.b", "vp1." + "a" * 200, "vp1.a.b.c"])
def test_invalid_invitations(value):
    with pytest.raises(ProtocolError):
        Invitation.parse(value)


def test_encoding_is_canonical():
    value = encode(b"\xff" * 16)
    assert decode(value, 16) == b"\xff" * 16
    with pytest.raises(ProtocolError):
        decode(value[:-1] + "x", 16)


def test_authenticated_bidirectional_audio():
    alice, bob = pair()
    assert alice.code == bob.code
    packet = alice.encrypt(CONFIRM)
    assert CONFIRM not in packet
    assert bob.decrypt(packet) == CONFIRM
    assert alice.decrypt(bob.encrypt(b"reply")) == b"reply"
    for _ in range(100):
        assert bob.decrypt(alice.encrypt(b"\x01" + b"\x12\x34" * 320)) == (
            b"\x01" + b"\x12\x34" * 320
        )


def test_wrong_invitation_secret_fails():
    invitation = Invitation.create()
    wrong = Invitation(invitation.room, Invitation.create().secret)
    alice, impostor = Handshake(invitation), Handshake(wrong)
    with pytest.raises(ProtocolError, match="authentication"):
        alice.finish(impostor.hello())


def test_reflection_fails():
    alice = Handshake(Invitation.create())
    with pytest.raises(ProtocolError):
        alice.finish(alice.hello())


def test_modified_public_key_fails():
    invitation = Invitation.create()
    alice, bob = Handshake(invitation), Handshake(invitation)
    message = json.loads(bob.hello())
    message["public"] = encode(b"\x42" * 32)
    with pytest.raises(ProtocolError):
        alice.finish(json.dumps(message).encode())


@pytest.mark.parametrize("message", [b"[]", b"null", b"{}", b"\xff", b"0", b"x" * 513])
def test_malformed_handshakes(message):
    with pytest.raises(ProtocolError):
        Handshake(Invitation.create()).finish(message)


def test_tampering_does_not_advance_receive_counter():
    alice, bob = pair()
    packet = alice.encrypt(b"audio")
    with pytest.raises(ProtocolError, match="authentication"):
        bob.decrypt(packet[:-1] + bytes([packet[-1] ^ 1]))
    assert bob.decrypt(packet) == b"audio"


def test_replay_and_out_of_order_fail():
    alice, bob = pair()
    first, second = alice.encrypt(b"first"), alice.encrypt(b"second")
    with pytest.raises(ProtocolError, match="out-of-order"):
        bob.decrypt(second)
    assert bob.decrypt(first) == b"first"
    with pytest.raises(ProtocolError, match="Replayed"):
        bob.decrypt(first)
    assert bob.decrypt(second) == b"second"


def test_direction_and_session_separation():
    alice, bob = pair()
    other_alice, other_bob = pair()
    packet = alice.encrypt(b"audio")
    with pytest.raises(ProtocolError):
        alice.decrypt(packet)
    with pytest.raises(ProtocolError):
        other_bob.decrypt(packet)
    assert bob.decrypt(packet) == b"audio"
    assert other_alice.code == other_bob.code
    assert alice.code != other_alice.code


def test_fresh_keys_with_reused_invitation():
    invitation = Invitation.create()
    alice, bob, charlie = (Handshake(invitation) for _ in range(3))
    old = alice.finish(bob.hello())
    fresh = bob.finish(charlie.hello())
    with pytest.raises(ProtocolError):
        fresh.decrypt(old.encrypt(b"old"))


def test_frame_limits():
    alice, bob = pair()
    with pytest.raises(ProtocolError):
        alice.encrypt(b"x" * 642)
    with pytest.raises(ProtocolError):
        bob.decrypt(b"short")
    alice._sent = 2**32
    with pytest.raises(ProtocolError):
        alice.encrypt(b"limit")
