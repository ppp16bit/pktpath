# pktpath

`pktpath` is a Linux CLI for inspecting the network path to an IPv4
destination. It sends ICMP probes with increasing TTL values, similar to
traceroute, and reports responding hops with information such as:

- IP address;
- reverse DNS hostname;
- estimated geographic location;
- ASN and network organization;
- round-trip time (RTT).

`pktpath` performs the tracing itself. It is not a wrapper around `traceroute`,
`tracepath`, `ping`, or another system command.

## Build

The project requires Go 1.26.5 or newer.

Build a local `./pktpath` binary with the Makefile:

```console
make
```

This is equivalent to:

```console
go build -o pktpath ./cmd/pktpath
```

The Linux implementation uses raw ICMP sockets. Grant the built binary the
required capability before running it as a regular user:

```console
make setcap
./pktpath google.com
```

To build, install in `/usr/local/bin`, and grant the installed binary the
required capability, run:

```console
make install
```

Compilation runs as the current user; `make install` uses `sudo` only to copy
the binary and apply `CAP_NET_RAW`. After installation, `pktpath` can be run
from any directory:

```console
pktpath google.com
```

The installation prefix can be changed with `PREFIX`, for example
`make install PREFIX=/custom/prefix`. Capabilities are attached to a specific
file: rerun `make setcap` after rebuilding the local binary. `make install`
applies the capability to the installed binary each time.

## Usage

```text
pktpath [options] <destination>
```

```console
pktpath google.com
pktpath 1.1.1.1
```

The commands below assume that `pktpath` is installed. For a locally built
binary, use `./pktpath` instead. Options may appear before or after the
destination.

- `-s, --size <bytes>` — intended total IPv4 packet size, including the normal
  20-byte IPv4 header, 8-byte ICMP header, and payload. Default: `64`. Range:
  `28`–`65535` bytes.

- `-m, --max-hops <n>` — maximum number of TTL/hop probes. Default: `30`.
  Range: `1`–`255`.

- `-t, --timeout <duration>` — maximum time to wait for each probe response.
  Default: `2s`. Accepts Go-style durations such as `500ms`, `1s`, or `2s` and
  must be greater than zero.

- `--no-geo` — disables external GeoIP, ASN, and organization enrichment.

- `--no-dns` — disables reverse-DNS/PTR lookups.

- `--show-private` — reveals complete private and shared/possible-CGNAT
  addresses in human-readable output. They are masked by default, for example:

  ```text
  192.168.1.1   → 192.168.x.x
  10.230.94.130 → 10.x.x.x
  ```

- `--debug` — writes compact resolution, tracing, reverse-DNS, GeoIP/ASN, and
  stage-timing diagnostics to stderr. Debug mode disables the spinner.

- `--json` — emits structured machine-readable JSON to stdout without ANSI
  styling. JSON retains the actual observed hop addresses.

- `-h, --help` — displays command help.

- `-v, --version` — displays the `pktpath` version.

During normal interactive execution, `pktpath` displays a temporary single-line
spinner while tracing and enriching hops. Animation is disabled for piped or
redirected output, JSON, and debug mode.

## Examples

Trace a hostname:

```console
pktpath cloudflare.com
```

Trace an IPv4 address:

```console
pktpath 1.1.1.1
```

Reveal private addresses:

```console
pktpath google.com --show-private
```

Disable GeoIP/ASN enrichment:

```console
pktpath google.com --no-geo
```

Disable reverse DNS:

```console
pktpath google.com --no-dns
```

Wait at most one second for each probe response:

```console
pktpath github.com --timeout 1s
```

Limit the trace to 15 hops:

```console
pktpath github.com --max-hops 15
```

Use a 128-byte IPv4 probe packet:

```console
pktpath google.com --size 128
```

Show diagnostics and stage timings:

```console
pktpath github.com --debug
```

Produce JSON:

```console
pktpath github.com --json
pktpath github.com --json | jq .
```

Keep debug diagnostics in a file while piping clean JSON to `jq`:

```console
pktpath github.com --debug --json 2>pktpath-debug.log | jq .
```

## Notes

- `pktpath` currently supports IPv4 destinations only.
- RTT is round-trip time, not one-way latency.
- GeoIP locations are estimates and are not proof of a router's physical
  location.
- A timeout means no matching ICMP response arrived before the probe deadline;
  it does not necessarily mean packet loss or that traffic stopped at that hop.
- Private and other non-public addresses are not sent to the GeoIP provider.
- Public-hop GeoIP/ASN enrichment uses the [IPWho API](https://ipwhois.io/documentation).
  Use `--no-geo` to disable these external requests.
