# PcapConstrictorWinPacket

PcapConstrictorWinPacket is a Windows live PCAP recorder that uses Npcap/libpcap to capture traffic, then reduces encrypted TLS and QUIC payload bytes while preserving enough packet structure for analysis in tools such as Wireshark. It is based on the policy architecture of PcapConstrictorAFPacket and PcapConstrictor, and it writes classic PCAP output.

## Current Status

This repository is prepared for an initial `v0.1.0` release with:

- live capture on Windows through Npcap/libpcap
- offline PCAP compatibility mode
- Ethernet `DLT_EN10MB` support
- Npcap loopback `DLT_NULL` support
- TLS Application Data constriction
- `tls.app_data_continuation_policy = final_only`
- QUIC short-header constriction when the DCID is known
- clean `Ctrl+C` / `Ctrl+Break` shutdown
- capture summary reporting with application counters and Npcap/libpcap statistics

## CLI

Supported commands:

```text
PcapConstrictorWinPacket --help
PcapConstrictorWinPacket --list-interfaces
PcapConstrictorWinPacket --config config.ini
PcapConstrictorWinPacket --config config.ini --offline-input input.pcap
```

`--offline-input` runs the deterministic offline pipeline:
`input.pcap -> PcapReader -> OfflinePacketFeed -> LiveCapturePolicy -> PcapWriter -> output.pcap`

`--config config.ini` runs live capture when Npcap support is compiled in.

`--list-interfaces` enumerates interfaces through Npcap/libpcap so you can copy an adapter name into the config.

## Runtime Requirements For Prebuilt Binary

Requirements for the Windows x64 prebuilt binary package:

- Windows x64
- Npcap runtime installed separately
- administrator privileges may be required depending on Npcap installation options

The prebuilt package does not include Npcap. The Npcap runtime is required to use `--list-interfaces` and live capture in an Npcap-enabled build.

## Build From Source

Requirements for building from source:

- C++20 compiler
- CMake
- Npcap SDK available and passed through `NPCAP_SDK_DIR` for live-capture builds

The Npcap SDK is only needed to build from source. It is not needed just to run a prebuilt binary.

If `NPCAP_SDK_DIR` is provided, the resulting build can include `--list-interfaces` and live capture support. The Npcap runtime must still be installed on the machine where that binary is used.

Example:

```powershell
cmake -S . -B build -DNPCAP_SDK_DIR="C:\Path\To\Npcap-SDK"
cmake --build build --config Release
```

Offline-only builds are also supported:

- offline tools and offline compatibility workflows can build without `NPCAP_SDK_DIR`
- when `NPCAP_SDK_DIR` is missing, CMake can fall back to an offline-only build
- offline-only builds do not provide `--list-interfaces` or live capture
- offline compatibility workflows can still run without live Npcap support if built that way

If you want an offline-only build explicitly:

```powershell
cmake -S . -B build -DPCAP_CONSTRICTOR_WINPACKET_ENABLE_NPCAP_INTERFACE_LISTING=OFF
cmake --build build --config Release
```

## Prebuilt Binary Package

Expected release artifact layout:

```text
PcapConstrictorWinPacket-v0.1.0-windows-x64.zip
  PcapConstrictorWinPacket.exe
  config.example.ini
  README.md
  CHANGELOG.md
  LICENSE or license note
```

Package notes:

- the package does not include Npcap
- install Npcap from the official Npcap website before using `--list-interfaces` or live capture
- if Npcap is missing, `--list-interfaces` and live capture will not work in an Npcap-enabled build
- the Npcap SDK is not required for users of the prebuilt binary package
- this repository does not currently contain a `LICENSE` file, so a project license should be chosen before publishing the repository or distributing binaries

## Quick Start

For an Npcap-enabled build or prebuilt binary with the Npcap runtime installed:

1. List interfaces:

```powershell
PcapConstrictorWinPacket.exe --list-interfaces
```

2. Copy `config.example.ini` to `config.ini`, then copy an interface name into it.

3. Run a bounded capture:

```powershell
PcapConstrictorWinPacket.exe --config config.ini
```

Example capture section:

```ini
[capture]
backend = npcap
interface = \Device\NPF_{GUID}
output = live-test.pcap
promiscuous = true
default_snaplen = 65535
max_capture_len = 65535
max_packets = 1000
duration_sec = 30
read_timeout_ms = 100
```

Offline-only builds can still run the deterministic offline pipeline with `--config config.ini --offline-input input.pcap`, but they do not support `--list-interfaces` or live capture.

## Loopback Example

Use this interface for localhost traffic:

```ini
interface = \Device\NPF_Loopback
```

Loopback capture is useful when you want to inspect traffic between processes on the same machine. Npcap exposes this as `DLT_NULL`, and PcapConstrictorWinPacket preserves that linktype in the output PCAP.

## Promiscuous Mode

- `promiscuous = true` requests promiscuous mode through `pcap_open_live`
- `promiscuous = false` opens the adapter in non-promiscuous mode
- on switched Ethernet, promiscuous mode does not guarantee visibility into all LAN traffic
- on Wi-Fi, promiscuous mode is not the same as monitor mode and may be limited by driver, hardware, or Npcap behavior
- loopback capture does not meaningfully use promiscuous mode
- depending on the Npcap installation mode, live capture and promiscuous capture may require administrator privileges

## Capture Statistics And Drops

- the final live summary includes application counters and a separate `Npcap/libpcap stats` section
- `ps_drop` can indicate packets dropped before delivery to the application
- `ps_ifdrop` may be unavailable or backend-dependent
- exact `pcap_stats` semantics are platform-dependent and are not identical to application-level packet counts
- high drop counts can suggest lowering traffic volume, improving performance, using a narrower capture setup, or reducing processing overhead

## Limitations

- Windows-oriented project
- requires Npcap for live capture
- classic PCAP output only
- no pcapng output
- no TLS or QUIC decryption
- no WFP, NDIS, or custom driver backend
- no `Packet.dll` low-level backend
- no monitor mode
- no BPF or capture filter support yet
- no TLS stream or bulk continuation policies
- QUIC migration is not supported
- unsupported linktypes fail clearly

## Verification Checklist

See [RELEASE_CHECKLIST.md](C:/My2/Projects/C++/PcapConstrictorWinPacket/PcapConstrictorWinPacket/RELEASE_CHECKLIST.md) for the `v0.1.0` packaging and smoke-test checklist.

## Testing

Golden fixtures under `tests/fixtures/golden/` are kept for offline compatibility checks so policy behavior can stay aligned with the AFPacket and main PcapConstrictor `final_only` workflows while this Windows codebase grows independently.

## Release Notes

See [RELEASE_NOTES.md](C:/My2/Projects/C++/PcapConstrictorWinPacket/PcapConstrictorWinPacket/RELEASE_NOTES.md) for the `v0.1.0` release notes and [CHANGELOG.md](C:/My2/Projects/C++/PcapConstrictorWinPacket/PcapConstrictorWinPacket/CHANGELOG.md) for the project change summary.

`LICENSE` is currently missing in this repository. A license must be chosen before publishing the repository or distributing binaries.
