# PcapConstrictorWinPacket

PcapConstrictorWinPacket is a planned Windows Npcap/libpcap live recorder with TLS/QUIC-aware adaptive PCAP capture. The current codebase already includes offline compatibility workflows plus the first simple Npcap live capture path, based on the PcapConstrictorAFPacket policy architecture.

## Current Milestone

Current scope:

- independent `PcapConstrictorWinPacket` repository and targets
- offline PCAP compatibility pipeline
- Npcap/libpcap interface discovery
- basic Npcap/libpcap live capture via `pcap_open_live`
- copied/adapted TLS, QUIC, decode, writer, reader, and live-policy core
- byte-for-byte golden tests for `final_only` compatibility behavior
- standalone minimal C++ tests with no external test framework

Current non-goals:

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
- `--config config.ini` runs the first basic Npcap live capture path when Npcap support is compiled in.
- `--list-interfaces` enumerates interfaces via the Npcap/libpcap API.
- Live capture currently uses the simplest `pcap_open_live` + `pcap_next_ex` backend.

Example:

```text
PcapConstrictorWinPacket --list-interfaces

[0]
  name: \Device\NPF_{...}
  description: Ethernet
  addresses: 192.168.1.10, fe80::...
  flags: up, running

PcapConstrictorWinPacket --config config.ini
```

Loopback example for localhost traffic:

```ini
[capture]
backend = npcap
interface = \Device\NPF_Loopback
output = loopback-test.pcap
max_packets = 100
duration_sec = 10
read_timeout_ms = 100
```

## Stopping Capture

- `Ctrl+C` stops live capture cooperatively.
- Already written packets are kept in the output classic PCAP.
- `max_packets` and `duration_sec` are recommended for bounded smoke tests.
- `read_timeout_ms` affects how quickly the capture loop notices cancellation and limit checks.

## Promiscuous Mode

- `promiscuous = true` requests promiscuous mode through `pcap_open_live`.
- `promiscuous = false` opens the adapter in non-promiscuous mode.
- On switched Ethernet, promiscuous mode does not guarantee visibility into all LAN traffic.
- On Wi-Fi, promiscuous mode is not the same as monitor mode and may be limited by driver, hardware, or Npcap behavior.
- Loopback capture does not meaningfully use promiscuous mode.
- Depending on the Npcap installation mode, live capture and promiscuous capture may require administrator privileges.

## Capture Statistics And Drops

- The final live summary includes application counters and a separate `Npcap/libpcap stats` section.
- `ps_drop` can indicate packets dropped before delivery to the application.
- `ps_ifdrop` may be unavailable or backend-dependent.
- Exact `pcap_stats` semantics are platform-dependent and should not be treated as identical to the application-level packet counts.
- High drop counts can suggest lowering traffic volume, improving capture performance, using a narrower capture setup, or reducing processing overhead.

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

Copy the reported `name:` value into `interface =`. Npcap interface names typically look like
`\Device\NPF_{GUID}`.

Small live smoke example:

```ini
[capture]
backend = npcap
interface = \Device\NPF_{GUID}
output = live-test.pcap
max_packets = 100
duration_sec = 0
read_timeout_ms = 100
```

Loopback smoke guidance:

- run `PcapConstrictorWinPacket --list-interfaces`
- choose `\Device\NPF_Loopback`
- set `max_packets = 100` or `duration_sec = 10`
- generate localhost traffic
- open the output PCAP in Wireshark

TLS currently keeps `app_data_continuation_policy = final_only` only. `stream` and `bulk` remain recognized but unsupported. Offline tests do not require Npcap.

## Build Notes

`--list-interfaces` and live capture use the Npcap/libpcap SDK. A simple CMake setup is supported via `NPCAP_SDK_DIR`.

Example:

```text
cmake -S . -B build -DNPCAP_SDK_DIR="C:/path/to/Npcap-SDK"
```

If `NPCAP_SDK_DIR` is not provided, the project falls back to an offline-only build and
`--list-interfaces` and live capture will report that Npcap support is unavailable in that build.

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
- classic PCAP output only
- no pcapng
- no custom Windows driver
- no WFP/NDIS kernel filtering
- no `Packet.dll` low-level backend
- live capture currently uses only the simplest `pcap_open_live` backend
- live capture currently supports Ethernet `DLT_EN10MB` and Npcap loopback `DLT_NULL`
- loopback capture is useful for localhost traffic
- unsupported linktypes fail clearly
- no BPF filtering yet
- no TLS/QUIC decryption
- TLS `final_only` only
- TLS stream/bulk unsupported
- QUIC no migration support
- malformed or ambiguous packets fall back conservatively
- Npcap installation and runtime DLL availability may be required to run live features
- administrator rights may be required depending on the Npcap installation mode and interface

## Testing

Golden fixtures under `tests/fixtures/golden/` are retained for offline compatibility checks so policy behavior can stay aligned with the AFPacket and main PcapConstrictor `final_only` workflows while this Windows codebase grows independently.
