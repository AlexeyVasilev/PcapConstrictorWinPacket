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

std::string FormatLiveCaptureSummary(const LiveCaptureTerminationReason reason,
                                     const CaptureStats& stats,
                                     const double elapsed_seconds,
                                     const std::filesystem::path& output_path) {
    std::ostringstream output;
    output << "Capture summary:\n"
           << "termination: " << LiveCaptureTerminationReasonString(reason) << '\n'
           << "output: " << output_path.string() << '\n'
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
