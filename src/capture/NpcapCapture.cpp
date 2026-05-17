#include "capture/NpcapCapture.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>

#if PCAP_CONSTRICTOR_WINPACKET_HAS_NPCAP
#include <winsock2.h>

#include <pcap.h>

#ifdef interface
#undef interface
#endif
#endif

#include "capture/CapturedPacket.hpp"
#include "policy/LiveCapturePolicy.hpp"
#include "writer/PcapWriter.hpp"

namespace pcap_constrictor_winpacket {
namespace {

void AccumulateDecisionStats(CaptureStats& stats, const DecisionReason reason) {
    switch (reason) {
        case DecisionReason::TlsApplicationDataConstricted:
            ++stats.tls_appdata_constricted;
            break;
        case DecisionReason::TlsMalformedFallback:
        case DecisionReason::TlsNoRecordFallback:
            ++stats.tls_fallback;
            break;
        case DecisionReason::QuicLongHeader:
            ++stats.quic_long_header;
            break;
        case DecisionReason::QuicShortHeaderMatched:
            ++stats.quic_short_matched;
            break;
        case DecisionReason::QuicShortHeaderConstricted:
            ++stats.quic_short_constricted;
            break;
        case DecisionReason::QuicShortHeaderUnknownCidFallback:
        case DecisionReason::QuicShortHeaderDcidMismatchFallback:
        case DecisionReason::QuicMalformedFallback:
            ++stats.quic_fallback;
            break;
        default:
            break;
    }
}

bool StopRequested(const volatile std::sig_atomic_t* stop_requested) noexcept {
    return stop_requested != nullptr && *stop_requested != 0;
}

bool DurationLimitReached(const std::chrono::steady_clock::time_point start_time,
                          const std::uint64_t duration_sec) noexcept {
    if (duration_sec == 0U) {
        return false;
    }

    return (std::chrono::steady_clock::now() - start_time) >= std::chrono::seconds(duration_sec);
}

std::chrono::system_clock::time_point ToTimestamp(std::int64_t seconds,
                                                  std::int64_t microseconds) {
    return std::chrono::system_clock::time_point{
        std::chrono::seconds(seconds) + std::chrono::microseconds(microseconds)};
}

std::string UnsupportedDatalinkError(const int datalink) {
    return "unsupported live datalink " + std::to_string(datalink) +
           "; only DLT_EN10MB is supported in this milestone";
}

}  // namespace

NpcapCapture::NpcapCapture(PolicyConfig::CaptureOptions config) noexcept
    : config_(std::move(config)) {}

bool NpcapCapture::HasSupport() noexcept {
#if PCAP_CONSTRICTOR_WINPACKET_HAS_NPCAP
    return true;
#else
    return false;
#endif
}

NpcapCaptureRunResult NpcapCapture::Run(const PolicyConfig& policy_config,
                                        const std::filesystem::path& output_path,
                                        volatile std::sig_atomic_t* stop_requested) const {
    NpcapCaptureRunResult result;

#if PCAP_CONSTRICTOR_WINPACKET_HAS_NPCAP
    const std::uint32_t output_snaplen =
        std::min(config_.default_snaplen, config_.max_capture_len);

    char error_buffer[PCAP_ERRBUF_SIZE] = {};
    const int snaplen = static_cast<int>(output_snaplen);
    const int promiscuous = config_.promiscuous ? 1 : 0;
    const int read_timeout_ms = static_cast<int>(config_.read_timeout_ms);

    pcap_t* handle = pcap_open_live(config_.interface.c_str(),
                                    snaplen,
                                    promiscuous,
                                    read_timeout_ms,
                                    error_buffer);
    if (handle == nullptr) {
        result.error = error_buffer[0] != '\0'
                           ? std::string(error_buffer)
                           : "pcap_open_live failed with no error details";
        return result;
    }

    struct HandleCloser {
        pcap_t* handle{nullptr};
        ~HandleCloser() {
            if (handle != nullptr) {
                pcap_close(handle);
            }
        }
    } handle_closer{handle};

    if (error_buffer[0] != '\0') {
        result.warning = error_buffer;
    }

    const int datalink = pcap_datalink(handle);
    if (datalink != DLT_EN10MB) {
        result.error = UnsupportedDatalinkError(datalink);
        return result;
    }

    std::ofstream output_stream(output_path, std::ios::binary);
    if (!output_stream) {
        result.error = "failed to open output file '" + output_path.string() + "'";
        return result;
    }

    PcapWriter writer(output_stream, output_snaplen);
    LiveCapturePolicy policy(policy_config);

    const auto start_time = std::chrono::steady_clock::now();

    try {
        writer.WriteGlobalHeader();
    } catch (const std::exception& exception) {
        result.error = exception.what();
        return result;
    }

    while (!StopRequested(stop_requested)) {
        if (config_.max_packets != 0U &&
            result.stats.packets_total >= config_.max_packets) {
            result.stop_reason = "max_packets limit reached";
            break;
        }
        if (DurationLimitReached(start_time, config_.duration_sec)) {
            result.stop_reason = "duration_sec limit reached";
            break;
        }

        pcap_pkthdr* header = nullptr;
        const unsigned char* bytes = nullptr;
        const int packet_status = pcap_next_ex(handle, &header, &bytes);

        if (packet_status == 0) {
            continue;
        }
        if (packet_status == PCAP_ERROR_BREAK) {
            result.stop_reason = "capture loop ended";
            break;
        }
        if (packet_status < 0) {
            const char* handle_error = pcap_geterr(handle);
            result.error = handle_error != nullptr && handle_error[0] != '\0'
                               ? std::string(handle_error)
                               : "pcap_next_ex failed with no error details";
            ++result.stats.receive_errors;
            break;
        }
        if (header == nullptr || bytes == nullptr) {
            ++result.stats.receive_errors;
            result.error = "pcap_next_ex returned success without packet data";
            break;
        }

        const auto packet_bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(bytes),
            static_cast<std::size_t>(header->caplen));
        const CapturedPacket packet{
            .packet = PacketView(packet_bytes, header->caplen, header->len),
            .timestamp = ToTimestamp(header->ts.tv_sec, header->ts.tv_usec),
            .ifindex = 0,
            .direction = PacketDirection::Unknown,
        };

        const LiveCaptureDecision decision = policy.Evaluate(packet);
        try {
            writer.WritePacket(packet, decision.output_len);
        } catch (const std::exception& exception) {
            result.error = exception.what();
            break;
        }

        ++result.stats.packets_total;
        ++result.stats.packets_written;
        result.stats.bytes_input += header->caplen;
        result.stats.bytes_output += decision.output_len;
        AccumulateDecisionStats(result.stats, decision.reason);
    }

    if (StopRequested(stop_requested) && result.stop_reason == "stopped") {
        result.stop_reason = "signal received";
    }

    result.stats.bytes_saved = result.stats.bytes_input - result.stats.bytes_output;
    result.elapsed_seconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - start_time).count();
    return result;
#else
    (void)policy_config;
    (void)output_path;
    (void)stop_requested;
    result.error = "Npcap live capture is unavailable in this build";
    return result;
#endif
}

}  // namespace pcap_constrictor_winpacket
