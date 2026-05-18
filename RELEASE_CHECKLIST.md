# Release Checklist

- Build Release x64 with `NPCAP_SDK_DIR`.
- Run tests.
- Run `--help`.
- Run `--list-interfaces`.
- Run offline smoke.
- Run live real-adapter smoke.
- Run loopback smoke.
- Run `Ctrl+C` smoke.
- Open output PCAP in Wireshark.
- Create zip without Npcap files.
- Attach zip to GitHub release.
- State Npcap runtime requirement in release notes.
- Choose and include a project license before publishing or distributing binaries.
