# iPhone Client

A fresh native SwiftUI implementation for iOS 16+, using only Apple frameworks.
It works with the existing Python desktop client and relay without server changes.
The source project is self-contained: no package downloads or project generator
are needed.

## Install

1. Open `iphone/VPComm.xcodeproj` in Xcode 15 or newer.
2. Select the **VPComm** target and open **Signing & Capabilities**.
3. Select your development team. Change `org.vpcomm.iphone` to a unique bundle
   identifier if required for your account.
4. Connect your iPhone, select it as the run destination, enable Developer Mode
   when prompted, and click Run.
5. Grant microphone access when starting a call.

No signing credentials are stored here. Local personal-device provisioning is
subject to Apple's current personal-team restrictions and expiry. App Store or
TestFlight distribution generally requires Apple Developer Program membership.
This is a development project, not an App Store-ready release: app icons,
distribution signing, privacy declarations, export compliance, and submission
review remain release tasks.

## Call a Desktop or Another iPhone

Use a relay deployed according to [`../deploy/README.md`](../deploy/README.md).

1. Generate an invitation on one client and share it through an authenticated,
   private channel. Anyone with the invitation secret can impersonate a peer.
2. On each client, enter the exact relay URL, for example
   `wss://voice.example.com/relay` or `wss://voice.example.com:8443/relay`.
3. Enter the relay access token. It is different from the invitation.
4. Paste the same invitation on the other client and tap **Start / Join** on
   both. The first participant waits up to two minutes.
5. Compare verification codes through an independent trusted channel. Hang up
   if they differ.
6. Use **Mute**, **Unmute**, and **Hang up**. Generate a new invitation next time.

The microphone opens only after authenticated key exchange and bidirectional
key confirmation. Comparing the verification code is user-operated, not a
separate microphone gate.

Generate/share the invitation before entering the token: switching apps clears
the token. An unused invitation stays in memory so sharing works. Clipboard
copies are local-only and expire after two minutes. The app clears its own
copied invitation when the call ends, without clearing unrelated clipboard
contents. A recipient app may retain a copy.

## TLS and Private Certificates

The app accepts only `wss://` and never bypasses TLS validation. A custom port,
including 8443, is supported. No App Transport Security exceptions are enabled.

For a normal publicly trusted certificate, leave **TLS certificate** unchanged.

For the Caddy private-CA deployment:

1. Export the server's **public root certificate** following the deployment
   guide. Never transfer a private key to the iPhone.
2. Transfer that certificate securely to Files on your phone.
3. Tap **Import private CA from Files**. Choose one PEM or DER root certificate.
4. Verify the displayed SHA-256 fingerprint against a trusted computer:

   ```bash
   openssl x509 -in vpcomm-root.crt -outform DER | openssl dgst -sha256
   ```

   The app inserts colons between fingerprint bytes; the bytes must match.

5. Use the exact hostname or IP covered by the server certificate.

The imported CA is trusted only inside this app and only until it is removed
or the process exits. With a private CA selected, system trust roots are not
used for the connection. Hostname, validity, and chain verification still apply.
Network fetching during private-CA evaluation is disabled; the server must
send its necessary intermediate certificates.

An iPhone's `127.0.0.1` is the iPhone, not your Mac. Use a reachable server
address with TLS. Only the test-only macOS probe permits plaintext loopback.
No relay address, access token, invitation, or CA private key is bundled.

## Behavior and Privacy

- Foreground-only calls. Backgrounding or locking ends the call; the screen
  stays awake during an active call. There is no background-audio entitlement.
- Audio interruptions, route changes, and audio-service resets end the call.
  Connect your preferred headphones before starting.
- A brief inactive state obscures the interface but does not alone hang up.
  Transitioning to the background does.
- No CallKit, APNs, background ringing, contacts, automatic reconnect, or accounts.
- No app-managed recording, analytics, cloud storage, or credential persistence.
  Credentials and session keys exist in memory; secure memory erasure is not
  guaranteed. OS diagnostics, clipboard recipients, or compromised devices
  remain outside these protections.
- End-to-end encryption uses the project's existing experimental protocol.
  It is not independently audited. The relay sees IPs, timing, duration, and
  traffic volume. Your partner can record or retransmit the conversation.

## Audio

The client converts device audio to mono 16 kHz PCM16 little-endian, 320 samples
per 20 ms frame. It uses AVAudioEngine voice processing on supported hardware
for echo cancellation. Headphones are still recommended.

Capture and scheduled playback queues are bounded to five frames. Full capture
queues discard old unsent audio; full playback queues discard incoming audio.
Muting clears queued microphone frames and sends encrypted silence. Previously
sent frames cannot be recalled.

This is not an adaptive real-time transport: WebSocket/TCP packet loss can
cause delay. Five seconds without microphone frames, ten seconds without
received frames, or a blocked send ends the call. Raw PCM uses approximately
240 MB/hour of relay egress per two-person call before transport overhead.
Opus compression and a reviewed real-time media transport remain future work.

## Tests

From the repository root:

```bash
# Simulator build
xcodebuild -project iphone/VPComm.xcodeproj -scheme VPComm \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath /tmp/vpcomm-iphone-build CODE_SIGNING_ALLOWED=NO build

# Native protocol checks, without recording or playing audio
xcrun swiftc -parse-as-library iphone/Core/*.swift \
  iphone/Tests/ProtocolChecks.swift -o /tmp/vpcomm-iphone-checks
/tmp/vpcomm-iphone-checks

# Live Swift/Python encrypted audio and TLS tests
xcrun swiftc -parse-as-library iphone/Core/*.swift \
  iphone/Tests/Probe.swift -o /tmp/vpcomm-iphone-probe
VPCOMM_IPHONE_PROBE=/tmp/vpcomm-iphone-probe \
  python -m pytest iphone/Tests/test_interop.py tests -q
```

Install the root project's `test` dependencies in your Python environment first.
Interop tests are skipped unless `VPCOMM_IPHONE_PROBE` is set. The probe reads
test credentials from stdin rather than command-line arguments.

Run the UI test with Command-U in Xcode using an installed iPhone simulator.
It checks invitation creation and insecure-address rejection. Test outputs and
builds should live outside the repository, using `-derivedDataPath /tmp/...`.

Verification covers real Swift-to-Python key exchange and encrypted PCM in both
directions, matching verification codes, private-CA TLS, rejection of expired/
untrusted/wrong-host certificates and bad tokens, stalled-connection deadlines,
and hang-up cancellation. Separate native checks cover tampering, replay,
reflection, wrong secrets, ordering, frame limits, and URL policy.

## Physical-Device Acceptance

Build and simulator tests do not verify real microphone/speaker quality. Before
relying on this client, run iPhone-to-desktop and iPhone-to-iPhone calls and check:

- Both audio directions, echo, volume, latency, and a ten-minute call.
- Built-in audio, wired headphones, and Bluetooth HFP.
- Permission denial, later permission grant, mute, and hang-up.
- Backgrounding, screen lock, headphone removal, and incoming phone calls.
- Wi-Fi/cellular interruption, relay restart, and token rotation.
- Public certificate and private-CA deployments, including a nonstandard port.

Independent security review remains necessary before high-sensitivity use.
