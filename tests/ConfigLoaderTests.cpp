#include <iostream>
#include <string_view>

#include "config/ConfigLoader.hpp"

namespace {

int Fail(std::string_view message) {
    std::cerr << "[ConfigLoaderTests] " << message << '\n';
    return 1;
}

}  // namespace

int RunConfigLoaderTests() {
    using namespace pcap_constrictor_winpacket;

    {
        const ConfigLoadResult defaults = ConfigLoader::LoadFromString("", "defaults.ini");
        if (!defaults) {
            return Fail("default config should load successfully");
        }
        if (defaults.config.capture.backend != CaptureBackend::Npcap) {
            return Fail("capture.backend default mismatch");
        }
        if (!defaults.config.capture.promiscuous) {
            return Fail("capture.promiscuous default mismatch");
        }
        if (defaults.config.capture.default_snaplen != 65535U) {
            return Fail("capture.default_snaplen default mismatch");
        }
        if (defaults.config.capture.max_capture_len != 65535U) {
            return Fail("capture.max_capture_len default mismatch");
        }
        if (defaults.config.capture.max_packets != 0U) {
            return Fail("capture.max_packets default mismatch");
        }
        if (defaults.config.capture.duration_sec != 0U) {
            return Fail("capture.duration_sec default mismatch");
        }
        if (defaults.config.capture.read_timeout_ms != 100U) {
            return Fail("capture.read_timeout_ms default mismatch");
        }
        if (!defaults.config.capture.interface.empty()) {
            return Fail("capture.interface default mismatch");
        }
        if (defaults.config.capture.output != "output.pcap") {
            return Fail("capture.output default mismatch");
        }
        if (defaults.config.general.min_saved_bytes_per_packet != 16U) {
            return Fail("general.min_saved_bytes_per_packet default mismatch");
        }
        if (!defaults.config.tls.enabled || defaults.config.tls.ports.size() != 2U) {
            return Fail("TLS defaults mismatch");
        }
        if (defaults.config.tls.app_data_continuation_policy !=
            TlsAppDataContinuationPolicy::FinalOnly) {
            return Fail("tls.app_data_continuation_policy default mismatch");
        }
        if (!defaults.config.quic.enabled || defaults.config.quic.ports.size() != 2U) {
            return Fail("QUIC defaults mismatch");
        }
        if (defaults.config.quic.short_header_keep_packet_bytes != 64U) {
            return Fail("quic.short_header_keep_packet_bytes default mismatch");
        }
        if (!defaults.config.quic.require_dcid_match ||
            defaults.config.quic.allow_short_header_without_known_dcid) {
            return Fail("QUIC boolean defaults mismatch");
        }
        if (!defaults.config.stats.enabled) {
            return Fail("stats.enabled default mismatch");
        }
    }

    {
        constexpr std::string_view config_text = R"ini(
; comment
[capture]
backend = npcap
interface = \Device\NPF_Loopback
promiscuous = false
default_snaplen = 4096
max_capture_len = 1024
max_packets = 123456789
duration_sec = 90
read_timeout_ms = 250
output = constrained-output.pcap

[tls]
enabled = false
ports = 443, 993
app_data_keep_record_bytes = 32
app_data_continuation_keep_bytes = 16
app_data_continuation_policy = final_only

[quic]
enabled = 1
ports = 443, 8443
short_header_keep_packet_bytes = 77
require_dcid_match = true
allow_short_header_without_known_dcid = 0

[stats]
enabled = false

[general]
min_saved_bytes_per_packet = 24
)ini";

        const ConfigLoadResult parsed = ConfigLoader::LoadFromString(config_text, "parsed.ini");
        if (!parsed) {
            return Fail(parsed.error);
        }

        if (parsed.config.capture.backend != CaptureBackend::Npcap) {
            return Fail("capture.backend npcap did not parse");
        }
        if (parsed.config.capture.promiscuous) {
            return Fail("capture.promiscuous did not parse");
        }
        if (parsed.config.capture.default_snaplen != 4096U ||
            parsed.config.capture.max_capture_len != 1024U) {
            return Fail("capture snaplen settings did not parse");
        }
        if (parsed.config.capture.max_packets != 123456789ULL ||
            parsed.config.capture.duration_sec != 90ULL) {
            return Fail("capture live limits did not parse");
        }
        if (parsed.config.capture.read_timeout_ms != 250U) {
            return Fail("capture.read_timeout_ms did not parse");
        }
        if (parsed.config.capture.interface != "\\Device\\NPF_Loopback") {
            return Fail("capture.interface did not parse");
        }
        if (parsed.config.capture.output != "constrained-output.pcap") {
            return Fail("capture.output did not parse");
        }
        if (parsed.config.general.min_saved_bytes_per_packet != 24U) {
            return Fail("general.min_saved_bytes_per_packet did not parse");
        }
        if (parsed.config.tls.enabled) {
            return Fail("tls.enabled did not parse");
        }
        if (parsed.config.tls.app_data_continuation_policy !=
            TlsAppDataContinuationPolicy::FinalOnly) {
            return Fail("tls.app_data_continuation_policy did not parse");
        }
        if (parsed.config.tls.ports.size() != 2U ||
            parsed.config.tls.ports[0] != 443U ||
            parsed.config.tls.ports[1] != 993U) {
            return Fail("tls.ports did not parse");
        }
        if (parsed.config.quic.ports.size() != 2U ||
            parsed.config.quic.ports[1] != 8443U) {
            return Fail("quic.ports did not parse");
        }
        if (!parsed.config.quic.require_dcid_match ||
            parsed.config.quic.allow_short_header_without_known_dcid) {
            return Fail("quic booleans did not parse");
        }
        if (parsed.config.stats.enabled) {
            return Fail("stats.enabled did not parse");
        }
    }

    {
        const ConfigLoadResult parsed = ConfigLoader::LoadFromString(
            "[tls]\napp_data_continuation_policy = final_only\n",
            "tls-final-only.ini");
        if (!parsed) {
            return Fail("tls.app_data_continuation_policy=final_only should parse");
        }
        if (parsed.config.tls.app_data_continuation_policy !=
            TlsAppDataContinuationPolicy::FinalOnly) {
            return Fail("tls.app_data_continuation_policy=final_only mismatch");
        }
    }

    {
        const ConfigLoadResult invalid = ConfigLoader::LoadFromString(
            "[tls]\napp_data_continuation_policy = stream\n",
            "tls-stream.ini");
        if (invalid) {
            return Fail("tls.app_data_continuation_policy=stream should fail for now");
        }
        if (invalid.error.find("not supported") == std::string::npos) {
            return Fail("tls.app_data_continuation_policy=stream should report unsupported");
        }
    }

    {
        const ConfigLoadResult invalid = ConfigLoader::LoadFromString(
            "[tls]\napp_data_continuation_policy = bulk\n",
            "tls-bulk.ini");
        if (invalid) {
            return Fail("tls.app_data_continuation_policy=bulk should fail for now");
        }
        if (invalid.error.find("not supported") == std::string::npos) {
            return Fail("tls.app_data_continuation_policy=bulk should report unsupported");
        }
    }

    {
        const ConfigLoadResult invalid = ConfigLoader::LoadFromString(
            "[tls]\napp_data_continuation_policy = aggressive\n",
            "tls-invalid-policy.ini");
        if (invalid) {
            return Fail("invalid tls.app_data_continuation_policy should fail");
        }
        if (invalid.error.find("tls.app_data_continuation_policy") == std::string::npos) {
            return Fail("invalid tls.app_data_continuation_policy should report a useful error");
        }
    }

    {
        const ConfigLoadResult parsed =
            ConfigLoader::LoadFromString("[capture]\npromiscuous = true\n", "promiscuous-true.ini");
        if (!parsed) {
            return Fail("capture.promiscuous=true should parse");
        }
        if (!parsed.config.capture.promiscuous) {
            return Fail("capture.promiscuous=true mismatch");
        }
    }

    {
        const ConfigLoadResult parsed =
            ConfigLoader::LoadFromString("[capture]\ninterface =\n", "empty-interface.ini");
        if (!parsed) {
            return Fail("empty capture.interface should parse");
        }
        if (!parsed.config.capture.interface.empty()) {
            return Fail("empty capture.interface should remain empty");
        }
    }

    {
        const ConfigLoadResult invalid =
            ConfigLoader::LoadFromString("[capture]\npromiscuous = maybe\n", "invalid-promiscuous.ini");
        if (invalid) {
            return Fail("invalid capture.promiscuous should fail");
        }
        if (invalid.error.find("invalid boolean for capture.promiscuous") == std::string::npos) {
            return Fail("invalid capture.promiscuous should report a useful error");
        }
    }

    {
        const ConfigLoadResult invalid =
            ConfigLoader::LoadFromString("[capture]\nbackend = mystery\n", "invalid-backend.ini");
        if (invalid) {
            return Fail("unknown backend should fail");
        }
        if (invalid.error.find("unknown capture.backend value") == std::string::npos) {
            return Fail("unknown backend should report a useful error");
        }
    }

    {
        const ConfigLoadResult invalid =
            ConfigLoader::LoadFromString("[capture]\nbackend = tpacket_v3\n", "linux-backend.ini");
        if (invalid) {
            return Fail("linux-only backend should fail");
        }
    }

    {
        const ConfigLoadResult invalid =
            ConfigLoader::LoadFromString("[capture]\nring_block_size = 4096\n", "unexpected-ring.ini");
        if (invalid) {
            return Fail("unexpected ring option should fail");
        }
        if (invalid.error.find("unknown key in [capture]") == std::string::npos) {
            return Fail("unexpected ring option should report capture section error");
        }
    }

    {
        const ConfigLoadResult invalid =
            ConfigLoader::LoadFromString("[capture]\ndefault_snaplen = 0\n", "invalid-snaplen.ini");
        if (invalid) {
            return Fail("zero capture.default_snaplen should fail");
        }
    }

    {
        const ConfigLoadResult invalid =
            ConfigLoader::LoadFromString("[capture]\nmax_capture_len = 0\n", "invalid-capture-len.ini");
        if (invalid) {
            return Fail("zero capture.max_capture_len should fail");
        }
    }

    {
        const ConfigLoadResult invalid =
            ConfigLoader::LoadFromString("[stats]\nenabled = maybe\n", "invalid-stats.ini");
        if (invalid) {
            return Fail("invalid stats.enabled should fail");
        }
    }

    return 0;
}
