# cursus

**English** | [简体中文](README_zh.md)

**cursus** is a VPN server and client built on the [Talaria](https://github.com/X-VPN/Talaria) protocol library:
**one binary, two roles**, selected by the `-role server|client` command-line flag.

- Protocols: `TalariaUDP` (UDP/443) / `TalariaTCP` (TCP/443)
- TLS: TLS 1.3, certificates required —
  **verification cannot be skipped**
- Configuration: a single YAML file, with identical fields on both ends
- Under the hood: Talaria handles the encrypted data channel (outer wire-secret wrapping,
  Retry, AEAD, session authorization, forwarding policy); cursus only handles the process
  lifecycle, certificate loading, TUN, routing/NAT, and the local proxy

> UDP and TCP both use port 443 (their port spaces are independent), so a single firewall
> rule covers both.

## Single binary

```
cursus -version
cursus -print-config -role server > cursus.yaml
cursus -role server -config cursus.yaml
cursus -role client -config cursus.yaml
cursus server -config cursus.yaml     # subcommand alias
cursus client -config cursus.yaml     # subcommand alias
```

The `-role` flag or subcommand picks the role, and the YAML `mode` must match
(`Validate` checks this). `-firewall` prints the ports to open, `-duration 30s`
exits automatically, and `Ctrl-C` shuts down gracefully.

## Server: one process serves both TCP and UDP

`cursus -role server` starts two Talaria listeners **in the same process**:

| Protocol | Listen | VIP pool | TUN |
|---|---|---|---|
| `TalariaUDP` | UDP/443 | `10.77.0.0/24` | `cursus-s0` |
| `TalariaTCP` | TCP/443 | `10.78.0.0/24` | `cursus-t0` |

Both share the certificates, static accounts, `wire_secret` and destination policy;
VIP pools and nft tables are isolated by TUN name to avoid reply-routing conflicts.
Only one systemd unit, `cursus-server`, is needed.

```sh
cursus -role server -config configs/cursus-server.yaml -firewall
# UDP/443 + TCP/443
```

The client picks one: `protocol: TalariaUDP` or `protocol: TalariaTCP`.

## Two client access modes

### 1) TUN mode (Layer-3 VPN, default)

The client creates a virtual NIC and needs root / `CAP_NET_ADMIN`. LAN devices point
their **default gateway at the client machine** (or get it via DHCP), so all
TCP/UDP/ICMP traffic naturally enters the tunnel. No proxy is needed.

```yaml
protocol: TalariaUDP          # or TalariaTCP
client:
  proxy:
    enabled: false
tun:
  mode: tun
```

### 2) Local proxy mode

The client listens on `0.0.0.0:1080` (SOCKS5) and `0.0.0.0:8080` (HTTP).
LAN devices simply point their browser/app proxy at the client machine's IP to
reach the internet through the server — **no default-gateway changes, no client
installed on every device, no root required**.

```yaml
protocol: TalariaTCP          # proxy mode requires TCP
client:
  proxy:
    enabled: true
    listen_host: 0.0.0.0
    socks5_port: 1080
    http_port: 8080
tun:
  mode: echo                  # proxy mode creates no TUN
```

```sh
cursus -role client -config configs/cursus-client-proxy.yaml

# From any device on the LAN:
curl -x http://<client-lan-ip>:8080 https://example.com
curl --socks5-hostname <client-lan-ip>:1080 https://example.com
```

How it works: each proxy connection maps to one TalariaTCP `DialStream`
(a SOCKS5 CONNECT stream); the server runs destination-policy checks and dials
out. The HTTP proxy supports plain requests and `CONNECT` tunnels. This is
application-layer access and only covers apps that support proxy configuration;
TUN mode is the full-traffic Layer-3 option.

> Proxy mode requires `TalariaTCP`; `Validate` rejects `TalariaUDP + proxy.enabled`.

## Censorship resistance and performance positioning

cursus / Talaria is a **speed-oriented** VPN data channel, not a
censorship-circumvention protocol.

**Censorship weaknesses:**

- On TCP/443 it is "mutated TLS": real certificates and SNI, but the preamble is
  randomized by the wire secret, so it is not a standard ClientHello. To DPI this
  is a high-value anomaly — "claims TLS but doesn't look like TLS".
- No traffic shaping: fixed record header (`type‖epoch‖seq`), fixed packet
  lengths, no random padding, no length jitter, no low-entropy mode. Sustained
  high-volume flows are easy to cluster statistically by length distribution
  and entropy.
- Fixed port + fixed SNI: SNI, certificate domain and port 443 are stable
  fingerprints that can be blocked directly.
- Active-probing protection is decent (packets without the wire secret are
  silently dropped, a bare TLS ClientHello gets no response), but that only
  solves "being scanned", not "being classified".
- No multiple entry points, no camouflage-site reuse, no SNI rotation, no
  traffic-pattern switching.

X-VPN itself positions Talaria as a speed solution; restricted networks use the
Everest family and obfuscation, and its official technical docs explicitly state
that "Talaria focuses on speed and efficiency, while Everest is better suited to
restrictive networks". If censorship resistance is the main goal, use a
purpose-built protocol such as mieru/mita with random padding, low-entropy mode
and no TLS fingerprint, rather than cursus.

**Speed (X-VPN's official claims, internal tests, not measured in this project):**

- 10 Gbps LAN tests: combined download/upload improved by **200%+** over their
  older protocols (including WireGuard); on a Windows Singapore route, P50
  download went from 1,536 → 5,706 Mbps.
- 1 Gbps / 100 Mbps tests: Windows/macOS download speed loss **< 5%**
  (>95% of baseline retained).
- Techniques: independent per-connection channels for multi-core parallelism,
  batched packet processing, stream-level forwarding to cut per-packet overhead.
- Test scale: 8,451 runs / 6,590 valid samples, 2026-08 to 09, initiated from
  Singapore to Singapore/UK/US.

These are results from X-VPN's own commercial network plus client optimizations;
the open-source library itself has no server cluster, AI routing or platform
acceleration paths. cursus is a prototype: measured throughput is on the order
of 3–4 MB/s, and the numbers above are not reproducible here — MTU capped at
1314, single process, no offload optimizations.

## Configuration

| Config | Role / mode |
|---|---|
| `configs/cursus-server.yaml` | server (single process, both protocols) |
| `configs/cursus-client.yaml` | client / TalariaUDP + TUN |
| `configs/cursus-client-tcp.yaml` | client / TalariaTCP + TUN |
| `configs/cursus-client-proxy.yaml` | client / TalariaTCP + local HTTP/SOCKS5 proxy |
| `configs/echo-local.yaml` | root-free loopback self-check |

**Placeholders you must change before deploying:**

| Field | Meaning |
|---|---|
| `identity` | Matches the certificate SNI, identical on both ends, unique per endpoint |
| `wire_secret` | ≥32-byte deployment-level secret, identical on both ends |
| `server.cert_file` / `key_file` | Paths to your own certificate chain and private key |
| `client.server_ip` | Your server's public IP |
| `server.auth.*` / `client.client_id` / `secret_key` | Your own credentials |
| `client.proxy.listen_host` | Keep `0.0.0.0` to serve the LAN |

The client **needs no certificate files**: it uses the system trust store plus
SNI verification. SNI must not be a bare IP.

## Build and test

```sh
make build          # -> bin/cursus (the only binary)
make test           # unit + race + dual-protocol end-to-end
make release        # linux amd64/arm64 + windows amd64 static binaries
```

Statically linked Go (`CGO_ENABLED=0`) with no runtime dependencies. Builds on
Linux/macOS/Windows; real TUN forwarding is Linux-only — on other platforms use
`tun.mode: echo` or proxy mode.

> Default MTU is **1314** (Talaria's cap for the UDP carrier: `1460-48-21-77`).
> Raising it does not improve speed; it only causes large packets to be dropped.
> Proxy mode does not involve MTU.

## Installation (Linux .deb)

CI publishes `cursus_<version>_amd64.deb` / `_arm64.deb` (containing
`/usr/bin/cursus`, `/etc/cursus/*.yaml`, systemd units) and
`cursus-<version>-linux-{amd64,arm64}.tar.zst` (single static binary archive).

```sh
sudo dpkg -i cursus_<version>_amd64.deb
sudo vi /etc/cursus/cursus-server.yaml       # replace all placeholders
sudo systemctl enable --now cursus-server
sudo ss -lntup | grep ':443\b'
```

## Installation (Windows setup.exe)

CI publishes `cursus-<version>-setup.exe` (NSIS), which installs to
`C:\Program Files\cursus\` with `cursus.exe` and YAML configs.

```
cursus.exe -role client -config "C:\Program Files\cursus\config\cursus-client-proxy.yaml"
```

Windows has no real TUN provider; use proxy mode.

## Release pipeline (entirely in CI)

```
git tag v0.1.1 && git push origin v0.1.1
      ├─ build      : go test / vet / static cross-compilation + Linux tar.zst
      ├─ deb        : dpkg-deb builds amd64 + arm64 .deb packages
      ├─ windows    : makensis builds setup.exe (the only Windows artifact)
      └─ publish    : GitHub Release + SHA256SUMS
```

Workflow: `.github/workflows/release.yml`. Locally you only change code, tag,
and push.

## Layout

```
cmd/cursus/              single main; -role / subcommand picks the role
internal/config/         YAML schema + validation
internal/app/            server/client assembly, certificates, TUN, routing, local proxy
configs/                 example YAML files
deploy/                  systemd units
packaging/deb/           dpkg-deb control templates
packaging/windows/       NSIS setup.nsi
.github/workflows/       CI static builds + packaging + Release
scripts/                 install references, firewall hints, benchmark scripts
third_party/talaria/     upstream Talaria source snapshot (LICENSE, go.mod)
```

## Limitations

- The example `wire_secret` and credentials are for testing only; replace them
  before deploying.
- `TunDevice.ReleaseVirtualIP` does not flush conntrack in this prototype;
  production needs it.
- Proxy mode is TCP-only (SOCKS5 CONNECT / HTTP CONNECT + plain HTTP); no UDP
  proxy. Use TUN mode if you need full-traffic UDP.
- No DNS push, no reconnect, no per-user quotas, no per-user firewall.
- Upstream Talaria is AGPL-3.0-only; the snapshot license is kept at
  `third_party/talaria/LICENSE`.

## License

**AGPL-3.0-only**. See `LICENSE` and `NOTICE`.
