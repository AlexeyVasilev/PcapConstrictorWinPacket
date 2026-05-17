#include "capture/LiveCaptureReporting.hpp"

#include <sstream>

namespace pcap_constrictor_winpacket {

std::string_view LiveCaptureTerminationReasonString(
    const LiveCaptureTerminationReason reason) noexcept {
    switch (reason) {
        case LiveCaptureTerminationReason::Stopped:
            return "stopped";
        case LiveCaptureTerminationReason::MaxPacketsReached:
            return "max_packets limit reached";
        case LiveCaptureTerminationReason::DurationReached:
            return "duration_sec limit reached";
        case LiveCaptureTerminationReason::Interrupted:
            return "interrupted";
        case LiveCaptureTerminationReason::CaptureLoopEnded:
            return "capture loop ended";
        case LiveCaptureTerminationReason::Error:
            return "error";
    }

    return "unknown";
}

bool LiveCaptureTerminationIsSuccess(const LiveCaptureTerminationReason reason) noexcept {
    return reason != LiveCaptureTerminationReason::Error;
}

std::string_view PcapLinkTypeString(const PcapLinkType link_type) noexcept {
    switch (link_type) {
        case PcapLinkType::Ethernet:
            return "DLT_EN10MB";
        case PcapLinkType::Null:
            return "DLT_NULL";
    }

    return "unknown";
}

std::string FormatLiveCaptureStartupSummary(const std::string_view interface_name,
                                            const std::filesystem::path& output_path,
                                            const std::uint32_t snaplen,
                                            const std::uint32_t read_timeout_ms,
                                            const bool promiscuous,
                                            const PcapLinkType link_type,
                                            const std::uint64_t max_packets,
                                            const std::uint64_t duration_sec) {
    std::ostringstream output;
    output << "Opening Npcap capture:\n"
           << "  interface: " << interface_name << '\n'
           << "  output: " << output_path.string() << '\n'
           << "  snaplen: " << snaplen << '\n'
           << "  read_timeout_ms: " << read_timeout_ms << '\n'
           << "  promiscuous: " << (promiscuous ? "enabled" : "disabled") << '\n'
           << "  linktype: " << PcapLinkTypeString(link_type) << '\n';

    if (max_packets != 0U) {
        output << "  max_packets: " << max_packets << '\n';
    }
    if (duration_sec != 0U) {
        output << "  duration_sec: " << duration_sec << '\n';
    }

    return output.str();
}

std::string FormatLiveCaptureSummary(const LiveCaptureTerminationReason reason,
                                     const CaptureStats& stats,
                                     const double elapsed_seconds,
                                     const std::filesystem::path& output_path,
                                     const bool promiscuous) {
    std::ostringstream output;
    output << "Capture summary:\n"
           << "termination: " << LiveCaptureTerminationReasonString(reason) << '\n'
           << "output: " << output_path.string() << '\n'
           << "promiscuous: " << (promiscuous ? "enabled" : "disabled") << '\n'
           << "elapsed_seconds: " << elapsed_seconds << '\n'
           << "packets_seen: " << stats.packets_total << '\n'
           << "packets_written: " << stats.packets_written << '\n'
           << "bytes_seen: " << stats.bytes_input << '\n'
           << "bytes_written: " << stats.bytes_output << '\n'
           << "bytes_saved: " << stats.bytes_saved << '\n'
           << "receive_errors: " << stats.receive_errors << '\n'
           << "tls_appdata_constricted: " << stats.tls_appdata_constricted << '\n'
           << "quic_short_constricted: " << stats.quic_short_constricted << '\n';
    return output.str();
}

}  // namespace pcap_constrictor_winpacket
