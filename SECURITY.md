# Security Model and Wire Protocol

## Intended Protection

The intent is audio-content confidentiality and integrity between two trusted
desktop installations, even when the relay or network is untrusted. The relay
terminates TLS but receives only end-to-end ciphertext after the handshake.
TLS remains necessary to protect relay credentials and reduce exposure of
room identifiers and handshake metadata to network observers.

This is an experimental application protocol using standard cryptographic
primitives, not a standardized or independently audited secure messenger.
Passing tests does not prove its security. Do not treat stage one as approved
for high-sensitivity use.

## Assumptions and Limitations

- Clients, operating systems, audio devices, dependencies, and the initial
  application distribution must be trustworthy. Malware can read audio before
  encryption or after decryption.
- The invitation must reach the intended participant over an authenticated,
  confidential channel. Anyone holding its secret can impersonate a
  participant, including a malicious relay that obtains it.
- Sharing an invitation in a messenger transfers trust to that messenger for
  that call's initial authentication. For stronger assurance, exchange it in
  person or over an already authenticated encrypted channel.
- This is group-secret authentication for a group of two, not durable
  person-to-person identity authentication. A relay token is not a peer identity.
- Compare the session verification code through an independent trusted channel.
  A mismatch requires hanging up. This check is user-operated, not a UI gate;
  the microphone opens after authenticated key confirmation.
- The other participant can record or retransmit the conversation.
- AWS, the network, and the relay can observe source IPs, connection timing,
  duration, packet sizes, approximate usage, and denial-of-service effects.
  The relay also sees room identifiers and ephemeral public handshake data.
- No anonymity, metadata-hiding, censorship-resistance, or availability claim
  is made. Network operators can block this traffic.
- Python does not guarantee erasure of secret material from memory. Process
  dumps, swap, terminal scrollback, clipboard history, and OS snapshots matter.
- Dependencies and desktop updates must be obtained through trusted channels.
  The client is installed locally; it is not mutable JavaScript served by
  the relay. A malicious client update can defeat encryption.
- There is no in-call key ratchet or post-compromise recovery. A compromised
  active session key exposes its direction for that session.

## Credential Separation

`VPCOMM_ACCESS_TOKEN` is a server-wide bearer credential. It is supplied in the
HTTP `Authorization` header inside TLS, and visible to the proxy and server.
It authorizes resource use only. Generate it from at least 32 random bytes.

An invitation is generated locally:

```text
vp1.<base64url-no-padding(16 random room bytes)>.<base64url-no-padding(32 random secret bytes)>
```

The room identifier alone goes to the relay. The invitation secret never does.
Do not replace the invitation secret with a memorable password: handshake
proofs permit offline guessing of low-entropy secrets.

Generate a new invitation for every call. The relay does not persist a spent
invitation database, so the one-time recommendation is a client/user policy,
not a server-enforced property. The GUI clears an invitation at hang-up;
terminal callers must avoid reuse themselves.

## Transport

- Production endpoint: `wss://<host>/relay`.
- `ws://` is accepted by the client only for the literal hostnames `localhost`,
  `127.0.0.1`, and `::1`, for development. Remote plaintext URLs are rejected.
- Server TLS certificates are validated with hostname verification. `--ca`
  chooses a private trust root; there is no insecure/skip-validation option.
- Client proxy auto-discovery is disabled. No external media service is called.
- WebSocket compression is disabled, frames are at most 1024 bytes at the
  relay, and relay payloads must be binary after the initial join.
- Initial join: `{"v":1,"room":"<room identifier>"}` as a text frame.
- Relay responses are `{"type":"waiting"}` followed by `{"type":"ready"}`, or
  just `{"type":"ready"}` for the second participant.
- Exactly two sockets occupy a room. Either socket closing ends both sides.
  The server reserves a closing room until socket closure completes, then
  removes it. No reconnect/resume state is retained.
- `/healthz` is intentionally unauthenticated and returns only `ok`.
- Browser-originated WebSocket requests are rejected. The protocol is for a
  locally installed native client, not a web page.

## Authenticated Key Exchange

All byte concatenations below have fixed-width components except the fixed
context string. Both endpoints independently generate fresh X25519 private
keys per connection. Public keys are 32 raw bytes.

Context is exactly the following ASCII byte string, without a newline:

```text
vpcomm/v1/x25519-hkdf-sha256-aes256gcm/pcm16le-16000-320
```

After `ready`, each client sends one binary UTF-8 JSON frame containing:

```json
{"v":1,"public":"<32-byte public key, base64url>","proof":"<32-byte HMAC, base64url>"}
```

Proof:

```text
HMAC-SHA256(invitation_secret, context || room_bytes || public_key)
```

Each client requires version 1, canonical encodings, a valid proof, a peer
public key different from its own, and a valid nonzero X25519 shared secret.
Sort the two public keys lexicographically by their raw byte values:

```text
transcript = context || room_bytes || smaller_public || larger_public
material = HKDF-SHA256(
    IKM = X25519(local_private, peer_public),
    salt = invitation_secret,
    info = transcript,
    length = 64
)
```

The endpoint with the smaller public key sends using the first 32 material
bytes and receives using the last 32. The other endpoint uses the reverse
assignment. Distinct directional keys prevent reflection and nonce sharing.

Clients send an encrypted confirmation plaintext of exactly:

```text
0x00 || ASCII("vpcomm/v1/confirmed")
```

Both sides must successfully decrypt the peer confirmation before audio
devices are opened. This provides fresh shared-key possession confirmation;
a recorded valid hello alone cannot establish a call.

The displayed verification code is the first 24 hexadecimal characters
(96 bits) of:

```text
SHA256(ASCII("verification") || transcript || material)
```

It is grouped into six four-character groups. It is not an encryption key.

Ephemeral X25519 keys provide forward secrecy against later invitation-secret
disclosure, assuming the ephemeral private/session keys are no longer
recoverable. Python memory behavior means secure erasure is not guaranteed.

## Encrypted Frames

AES-256-GCM with a 128-bit authentication tag:

```text
counter = unsigned 64-bit big-endian integer, starts at 0 independently per direction
nonce   = 4 zero bytes || counter
AAD     = SHA256(transcript) || counter
packet  = counter || AESGCM.encrypt(nonce, plaintext, AAD)
```

Each directional key is fresh for a call. Counters must match the next
expected value exactly. Authentication failures do not advance counters.
Counter exhaustion at 2^32 frames is rejected; default server call limits
expire much earlier.

The confirmation consumes counter zero. Each subsequent audio plaintext is:

```text
0x01 || 640 bytes of PCM16 little-endian mono, 16000 Hz, 320 samples
```

Encrypted audio packets are 665 bytes. There is no codec negotiation in v1.
Any wrong encrypted payload type, size, order, authentication, or peer
confirmation ends the call. Muted frames contain encrypted silence at the same
nominal rate. Device scheduling and TCP behavior mean this is not rigorous
constant-rate traffic padding.

## Resource and Logging Policy

The relay has a connection admission limit, per-socket 60-frame/s replenishing
budget with a 100-frame burst, 1024-byte message limit, bounded WebSocket queues,
bounded sends, wait/call timeouts, and ping-based liveness. Audio device queues
hold at most five frames per direction. Full queues discard the oldest
untransmitted/unplayed audio. Encrypted stream counters remain contiguous.

These controls do not stop network floods, TLS exhaustion, or cost attacks.
Use security-group restrictions and protect the relay token.

The code does not persist audio, invitations, rooms, or contacts. Operational
warnings/errors can be logged. Caddy access logs are disabled in the supplied
configuration. Administrators can still enable packet capture or logging;
encryption does not make those capabilities disappear.

## Before Production

Obtain an independent protocol and implementation review, assess using a
well-reviewed established secure media protocol, add interoperability vectors,
test actual desktop hardware and hostile network conditions, harden abuse
controls, introduce authenticated contact identities and signed updates, and
define an explicit vulnerability-response/update process.
