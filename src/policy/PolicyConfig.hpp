#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace pcap_constrictor_winpacket {

enum class CaptureBackend {
    Npcap,
};

enum class TlsAppDataContinuationPolicy {
    FinalOnly,
    Stream,
    Bulk,
};

struct PolicyConfig {
    struct GeneralOptions {
        std::uint32_t min_saved_bytes_per_packet{16};
    } general;

    struct CaptureOptions {
        CaptureBackend backend{CaptureBackend::Npcap};
        std::string interface{};
        std::filesystem::path output{"output.pcap"};
        bool promiscuous{true};
        std::uint32_t default_snaplen{65535};
        std::uint32_t max_capture_len{65535};
        std::uint64_t max_packets{0};
        std::uint64_t duration_sec{0};
        std::uint32_t read_timeout_ms{100};
    } capture;

    struct TlsOptions {
        bool enabled{true};
        std::vector<std::uint16_t> ports{443, 8443};
        std::uint32_t app_data_keep_record_bytes{256};
        std::uint32_t app_data_continuation_keep_bytes{64};
        TlsAppDataContinuationPolicy app_data_continuation_policy{
            TlsAppDataContinuationPolicy::FinalOnly};
    } tls;

    struct QuicOptions {
        bool enabled{true};
        std::vector<std::uint16_t> ports{443, 8443};
        std::uint32_t short_header_keep_packet_bytes{64};
        bool require_dcid_match{true};
        bool allow_short_header_without_known_dcid{false};
    } quic;

    struct StatsOptions {
        bool enabled{true};
    } stats;
};

}  // namespace pcap_constrictor_winpacket
