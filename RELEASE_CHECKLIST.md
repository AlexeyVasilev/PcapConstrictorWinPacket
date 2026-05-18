# Release Checklist

- Build Release x64 with `NPCAP_SDK_DIR`.
- Build official release binary with MSVC x64.
- Run tests.
- Run `--help`.
- Run `--list-interfaces`.
- Run offline smoke.
- Run live real-adapter smoke.
- Run loopback smoke.
- Run `Ctrl+C` smoke.
- Verify missing-Npcap runtime behavior on the MSVC release binary.
- Open output PCAP in Wireshark.
- Create zip without Npcap files.
- Attach zip to GitHub release.
- Do not use a MinGW Npcap-enabled build as the official binary unless missing-runtime behavior is retested and documented.
- State Npcap runtime requirement in release notes.
- Choose and include a project license before publishing or distributing binaries.
