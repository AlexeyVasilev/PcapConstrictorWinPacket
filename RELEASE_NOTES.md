# PcapConstrictorWinPacket v0.1.0

Initial Windows release of PcapConstrictorWinPacket.

## Highlights

- Windows live capture through Npcap/libpcap.
- Ethernet `DLT_EN10MB` capture support.
- Npcap loopback `DLT_NULL` capture support.
- TLS/QUIC-aware adaptive PCAP reduction.
- Offline PCAP compatibility mode.
- Clean `Ctrl+C` / `Ctrl+Break` shutdown with valid partial PCAP output.
- Capture summary with application counters and Npcap/libpcap stats.

## Runtime Requirement

- Npcap runtime must be installed separately.
- The binary package does not include Npcap.
- If the Npcap runtime is missing, `--list-interfaces` and live capture should report that with a clear console error.

## Known Limitations

- Classic PCAP output only.
- No pcapng.
- No TLS/QUIC decryption.
- No custom Windows driver / WFP / NDIS backend.
- No `Packet.dll` low-level backend.
- No monitor mode.
- No capture filter support yet.
- Unsupported linktypes fail clearly.
- TLS stream/bulk policies are not supported.
- QUIC migration is not supported.
