# Deploy on One EC2 Instance

This guide does not provision or modify AWS resources automatically. Docker
builds and deployment must be validated on your chosen EC2 OS and architecture.

## 1. Prepare the Instance

Use a small Linux EC2 instance initially, such as an Ubuntu instance with at
least 1 GiB RAM. Pick a region near the participants. Benchmark before increasing
call volume; there is no measured production capacity claim.

Install Docker Engine and the Docker Compose plugin from their official
distribution instructions. Avoid public load balancers, API Gateway, managed
databases, NAT gateways, or third-party calling services; none is needed.

Security group:

- TCP 443: allow your participants' source networks where feasible.
- TCP 80: allow publicly if using ACME HTTP validation for a public certificate.
- TCP 22: allow only your own administration address.
- Do not expose TCP 8765. It is internal to Docker.
- No UDP ports are needed by this prototype.

Keep SSH keys protected and the OS patched. Docker-published ports can bypass
some host firewall configurations; rely on the EC2 security group as well.

Copy this repository to a directory on the instance. Use an existing domain,
for example `voice.example.com`, with an A record pointing at the public IPv4.
If an AAAA record exists, it must route to this instance as well.

## 2. Set the Relay Credential

Generate a cryptographically random token with:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Create `.env` in the project directory using a local editor and restrict its
permissions to the owner (`chmod 600 .env`). It must contain:

```dotenv
VPCOMM_DOMAIN=voice.example.com
VPCOMM_ACCESS_TOKEN=REPLACE_WITH_THE_RANDOM_TOKEN
```

Do not keep the example value. Give the random token only to intended users.
This shared token authorizes relay use, not audio decryption. It appears in the
container environment and is visible to instance/Docker administrators.
Do not paste output from `docker compose config` into logs or support chats:
it expands environment values.

## 3. Start the Services

Run from the project directory:

```bash
docker compose up -d --build
docker compose ps
curl --fail https://voice.example.com/healthz
```

The response should be `ok`. Caddy obtains and renews a free public TLS
certificate. DNS and inbound port 80 must be correct for initial issuance.
Certificate issuance contacts public certificate authorities, but does not
send them your audio or invitation. Public certificate names appear in
certificate-transparency records.

The relay has a Docker health check. Caddy starts after it becomes healthy.
No access-log directive is enabled. Container operational logs are size-bounded.
Do not enable WebSocket debug logs or HTTP header/body capture.

On each desktop:

```bash
vpcomm-desktop --server wss://voice.example.com/relay
```

Enter the relay token, then create or join a call using a fresh invitation.
Verify microphone permission and selected audio devices. Use headphones.

## Without a Domain

You can use the instance public IP and Caddy's private certificate authority,
at the cost of securely distributing a CA certificate to both desktops.
This is not a "skip TLS verification" mode.

Set `.env` as follows (the address below is a documentation example):

```dotenv
VPCOMM_DOMAIN=203.0.113.10
VPCOMM_ACCESS_TOKEN=REPLACE_WITH_THE_RANDOM_TOKEN
VPCOMM_CADDYFILE=./deploy/Caddyfile.private
```

Start services as above, then export **only the public root certificate**:

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./vpcomm-root.crt
```

Copy that certificate to each desktop over authenticated SSH or another trusted
channel. Verify the SSH host identity. Never copy the CA private key or the
entire Caddy data directory to clients.

```bash
vpcomm-desktop --server wss://203.0.113.10/relay --ca /path/to/vpcomm-root.crt
```

Health checking from a machine holding the root certificate:

```bash
curl --cacert ./vpcomm-root.crt https://203.0.113.10/healthz
```

For this private-CA mode, public ACME validation is not used; inbound TCP 80
is optional and can be removed from the security group and Compose ports.
The CA file is trusted only by this client process, not installed system-wide.
If the public IP changes, update `.env`, recreate Caddy, and update client URLs.
Preserve the Caddy data volume to keep the same CA. If you replace that volume,
securely distribute the new root certificate.

## Operations

- `docker compose logs --tail=50 relay caddy`: inspect operational failures.
  Review before sharing logs; do not add verbose protocol logging.
- `docker compose down`: disconnect calls and stop services. Rooms vanish.
- `docker compose up -d --build`: build changed source and recreate services
  as necessary. In-progress calls may be disconnected.
- Change the token in `.env`, then run
  `docker compose up -d --force-recreate relay` to revoke the old token.
  This disconnects calls; distribute the replacement credential securely.
- Maintain the OS, Docker, Caddy, and Python dependencies. The sample image
  tags are versioned but not pinned by digest.
- No audio backups are needed. Keep credentials and Caddy private keys secure.
  Instance snapshots, crash dumps, and memory inspection remain operator risks.

To change relay limits, add a `command` to the `relay` service, for example:

```yaml
command: ["vpcomm-server", "--host", "0.0.0.0", "--max-connections", "8",
          "--wait-timeout", "120", "--call-timeout", "1800"]
```

The service permits two participants per room. Once one leaves, both sockets
close. Relay state is in memory, so run **one replica**. Multiple replicas need
explicit room routing; adding replicas blindly can separate participants.

The relay bounds admitted connections, frame size/rate, queues, send time,
waiting time, and call duration. This is not DDoS protection. Invalid HTTP
handshakes and TLS setup still consume proxy resources. Restrict ingress where
possible and use a small trusted user population. Flooding can cause downtime
and bandwidth charges even when audio remains encrypted.

## Cost Boundaries

There are no per-minute communications charges or required paid APIs.
However, AWS may bill EC2 compute, EBS, public IPv4, and applicable data
transfer; a domain registrar may bill domain registration. Review current
regional pricing and your own account terms. An Elastic IP can also incur
charges. Do not assume a free tier covers this.

One two-person call causes roughly 240 MB/hour of relay audio egress before
transport overhead. PCM is deliberately simple but costly compared with Opus.
For long calls, compression should be prioritized in the next stage.

## Release Checklist

- Confirm `pytest`, Ruff checks, and image build on the deployment platform.
- Confirm `/healthz`, valid TLS, and rejection of the wrong relay token.
- Make a two-computer call across different networks and check both directions.
- Verify mute, hang-up, microphone permission denial, waiting timeout, and
  network interruption.
- Confirm security-group rules and that 8765 is not published.
- Review certificate trust and invitation delivery with both participants.
- Perform an independent security review before high-sensitivity use.
