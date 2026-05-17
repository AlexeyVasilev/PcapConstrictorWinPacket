# PcapConstrictorWinPacket

PcapConstrictorWinPacket is a planned Windows Npcap/libpcap live recorder with TLS/QUIC-aware adaptive PCAP capture. This first milestone establishes an independent Windows-oriented skeleton with the offline policy pipeline and golden compatibility tests, based on the PcapConstrictorAFPacket policy architecture.

## Current Milestone

Current scope:

- independent `PcapConstrictorWinPacket` repository and targets
- offline PCAP compatibility pipeline only
- Npcap/libpcap interface discovery
- copied/adapted TLS, QUIC, decode, writer, reader, and live-policy core
- byte-for-byte golden tests for `final_only` compatibility behavior
- standalone minimal C++ tests with no external test framework

Current non-goals:

- Npcap live capture
- Npcap SDK dependency
- WFP, NDIS, driver, service, or low-level `Packet.dll` code
- pcapng output
- TLS stream or bulk continuation policies

## CLI

Supported commands:

```text
PcapConstrictorWinPacket --help
PcapConstrictorWinPacket --list-interfaces
PcapConstrictorWinPacket --config config.ini
PcapConstrictorWinPacket --config config.ini --offline-input input.pcap
```

For this milestone:

- `--offline-input` runs the deterministic offline pipeline:
  `input.pcap -> PcapReader -> OfflinePacketFeed -> LiveCapturePolicy -> PcapWriter -> output.pcap`
- `--config config.ini` without `--offline-input` prints a clear message that Npcap live capture is not implemented yet and returns non-zero.
- `--list-interfaces` enumerates interfaces via the Npcap/libpcap API.
- Live packet capture is still not implemented.

Example:

```text
PcapConstrictorWinPacket --list-interfaces

[0]
  name: \Device\NPF_{...}
  description: Ethernet
  addresses: 192.168.1.10, fe80::...
  flags: up, running
```

## Config

See `config.example.ini`.

The capture section is already shaped for the future Windows backend:

```ini
[capture]
backend = npcap
interface =
output = output.pcap
promiscuous = true
default_snaplen = 65535
max_capture_len = 65535
max_packets = 0
duration_sec = 0
read_timeout_ms = 100
```

Copy the reported `name:` value into `interface =` when preparing for future live capture milestones.

TLS currently keeps `app_data_continuation_policy = final_only` only. `stream` and `bulk` remain recognized but unsupported. Offline tests do not require Npcap.

## Build Notes

`--list-interfaces` uses the Npcap/libpcap SDK. A simple CMake setup is supported via `NPCAP_SDK_DIR`.

Example:

```text
cmake -S . -B build -DNPCAP_SDK_DIR="C:/path/to/Npcap-SDK"
```

If `NPCAP_SDK_DIR` is not provided, the project falls back to an offline-only build and
`--list-interfaces` will report that Npcap interface listing is unavailable in that build.

This milestone expects:

- `${NPCAP_SDK_DIR}/Include/pcap.h`
- `${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib` for 64-bit builds, or `${NPCAP_SDK_DIR}/Lib/wpcap.lib` otherwise
- matching `Packet.lib`

If you only want the offline pipeline, you can disable interface-listing support at configure time:

```text
cmake -S . -B build -DPCAP_CONSTRICTOR_WINPACKET_ENABLE_NPCAP_INTERFACE_LISTING=OFF
```

## Known Limitations

- Windows-oriented project structure
- no live capture yet
- classic PCAP output only
- no pcapng
- no custom Windows driver
- no WFP/NDIS kernel filtering
- no `Packet.dll` low-level backend
- no TLS/QUIC decryption
- TLS `final_only` only
- TLS stream/bulk unsupported
- QUIC no migration support
- malformed or ambiguous packets fall back conservatively

## Testing

Golden fixtures under `tests/fixtures/golden/` are retained for offline compatibility checks so policy behavior can stay aligned with the AFPacket and main PcapConstrictor `final_only` workflows while this Windows codebase grows independently.
