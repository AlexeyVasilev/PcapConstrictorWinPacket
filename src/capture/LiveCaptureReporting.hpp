#pragma once

#include <filesystem>
#include <string>
#include <string_view>

#include "stats/CaptureStats.hpp"

namespace pcap_constrictor_winpacket {

enum class LiveCaptureTerminationReason {
    Stopped,
    MaxPacketsReached,
    DurationReached,
    Interrupted,
    CaptureLoopEnded,
    Error,
};

[[nodiscard]] std::string_view LiveCaptureTerminationReasonString(
    LiveCaptureTerminationReason reason) noexcept;
[[nodiscard]] bool LiveCaptureTerminationIsSuccess(
    LiveCaptureTerminationReason reason) noexcept;
[[nodiscard]] std::string FormatLiveCaptureSummary(
    LiveCaptureTerminationReason reason,
    const CaptureStats& stats,
    double elapsed_seconds,
    const std::filesystem::path& output_path);

}  // namespace pcap_constrictor_winpacket
