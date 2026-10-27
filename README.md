# VPComm

A self-hosted, two-person audio calling prototype. A Python desktop client sends
end-to-end encrypted audio through your own relay on EC2. There is no hosted
calling API, database, analytics SDK, STUN service, TURN service, or recording
service.

**Status: stage-one prototype, not independently security audited.** This is
not a claim of anonymity, guaranteed protection from interception, or security
equivalence to any established messenger.

## Architecture

```text
Desktop A -- TLS + encrypted audio --> Caddy / relay on EC2
Desktop B <-- TLS + encrypted audio -- Caddy / relay on EC2

End-to-end keys: A and B only
Relay: pairs exactly two connections and forwards opaque binary frames
```

- A 256-bit random invitation secret authenticates ephemeral X25519 keys.
- HKDF-SHA256 derives separate sending and receiving AES-256-GCM keys.
- Both clients confirm the session keys before opening the microphone.
- Every encrypted frame has an authenticated sequence counter. Tampering,
  reflection, wrong keys, replay, and out-of-order frames fail closed.
- A matching verification code is displayed on both clients.
- TLS certificate validation is mandatory outside loopback.
- Rooms exist only in RAM and are removed when either participant leaves.
- A separate relay access token limits who can use your server.
- No automatic reconnect: a dropped call must be restarted with a new invitation.

See [the protocol and threat model](SECURITY.md) before using this for sensitive
conversations.

## Requirements

- Python 3.11 or newer; tested here with Python 3.14.
- Desktop: macOS, Linux, or Windows with PortAudio, a microphone, and headphones.
  Actual hardware audio and platform packaging need further validation.
- Tk is required only for the desktop window. Terminal mode does not need it.
- EC2: Linux and Docker Engine with the Compose plugin for the provided deployment.

On macOS with Homebrew, install `python-tk@3.14` for a Homebrew Python 3.14
interpreter, adjusting the version to match your Python. Homebrew Python does
not always bundle Tk. The sounddevice wheels generally supply PortAudio on
macOS and Windows. On Debian/Ubuntu desktops, install `python3-venv`,
`python3-tk`, and `libportaudio2`.

## Run Locally

From this project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-server.txt
python -m pip install -e '.[desktop]'
```

On Windows, activate with `.venv\Scripts\Activate.ps1` in PowerShell.

Generate a relay token once:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Treat the result as a credential, not as an invitation. In the server terminal,
set `VPCOMM_ACCESS_TOKEN` without putting its value in command history:

```bash
read -s -p "Relay token: " VPCOMM_ACCESS_TOKEN
export VPCOMM_ACCESS_TOKEN
vpcomm-server
```

The Bash `read` command above is also usable in a Bash terminal on macOS.
The default listener is **127.0.0.1:8765**, not a public interface.

Open two desktop clients in separate terminals:

```bash
vpcomm-desktop
```

1. Enter `ws://127.0.0.1:8765/relay` and the relay token on both clients.
2. On client A, choose **New invitation**, then **Copy invitation**.
3. Give that invitation to B through a trusted channel; B pastes it.
4. Click **Start / Join** on both. The first client waits up to two minutes.
5. Compare the displayed verification codes through a trusted independent
   channel. A mismatch means you should hang up.
6. Use **Mute** or **Hang up**. Generate a new invitation for the next call.

Both endpoints open their microphones once the authenticated handshake
finishes. There is no additional incoming-call acceptance screen. Headphones
are important: stage one has no acoustic echo cancellation.

The invitation is deliberately not a URL or command-line argument, and it is
never sent to the relay. The GUI masks it, clears it when a call ends, and does
not save settings. Copying it puts it on your OS clipboard; clipboard history
or synchronization can retain it. Clear the clipboard after sharing.

### Terminal Client

```bash
# A: generates and prints an invitation, then waits
vpcomm-desktop --cli --new

# B: securely prompts for the same invitation
vpcomm-desktop --cli
```

Both commands prompt for the relay token unless `VPCOMM_ACCESS_TOKEN` is set.
Terminal mode prints a new invitation into terminal scrollback, which is a
privacy tradeoff. Ctrl+C hangs up; mute is available only in the GUI.

Select devices if necessary:

```bash
vpcomm-desktop --list-devices
vpcomm-desktop --input-device 1 --output-device 2
```

Indices are examples; use those listed on your machine. The selected devices
must support 16 kHz mono PCM. Grant microphone permission to the terminal or
Python application when prompted by the operating system.

## EC2 Deployment

See [the deployment guide](deploy/README.md). For a remote server, both clients
use:

```bash
vpcomm-desktop --server wss://voice.example.com/relay
```

No managed AWS service is required. EC2 billing is not necessarily just
compute and traffic: EBS storage, public IPv4, domain registration, taxes, and
applicable transfer charges may also apply. Use an existing domain/DNS or the
private-certificate option in the guide. This implementation creates no AWS
resources on your behalf.

## Tests

```bash
python -m pip install -e '.[desktop,test]'
python -m pytest -q
ruff check .
ruff format --check .
```

Tests include cryptographic tamper/replay rejection, key confirmation,
unauthorized access, room isolation/capacity, malformed input, cleanup,
timeouts, and two real client transports exchanging synthetic audio through a
real local WebSocket relay. Synthetic tests do not record or play real sound.

## Stage-One Tradeoffs

- Audio is raw PCM16 little-endian, mono, 16 kHz, 20 ms per frame.
- Payload bandwidth is 256 kbit/s per direction. Encrypted application frames
  total approximately 266 kbit/s per direction before WebSocket/TLS/TCP overhead.
  The relay sends about **240 MB/hour per active two-person call**, plus transport
  overhead; ingress is similar. This is not an AWS cost quote.
- Audio travels over TCP/WebSockets, so packet loss can cause head-of-line
  blocking and audible delay. Queues are bounded, but this is not an adaptive
  jitter buffer. A production media transport should use a reviewed real-time
  stack with congestion control.
- Use headphones; no echo cancellation, automatic gain, or noise suppression.
- The default relay allows 32 connected sockets, a two-minute wait, and a
  one-hour call. These are safety limits, not measured capacity guarantees.
- There are no accounts, persistent contact identities, push notifications,
  ringing, recovery, or per-user access-token revocation.
- Dependencies must be updated regularly. The server lock file records tested
  runtime versions; Docker base tags and development extras are not immutable
  supply-chain locks.

## Stage Two: iPhone

Keep the server relay boundary, but agree on a reviewed production protocol
before freezing a mobile implementation. An iOS client can use CryptoKit for
the existing X25519/HKDF/AES-GCM primitives, URLSession WebSockets for transport,
and AVAudioEngine for audio. Add protocol interoperability vectors first.

Before wider deployment: independent protocol review, durable contact
authentication, Opus compression, echo cancellation, device lifecycle and
network-change handling, stronger abuse controls, signed client releases,
and a real-time media transport evaluation.

iOS background calling and incoming-call UX need a separate design. CallKit
and APNs can introduce Apple infrastructure and developer-program costs;
foreground-only calls avoid relying on push delivery, but have usability
limits. Stage one does not implement an iPhone client.
