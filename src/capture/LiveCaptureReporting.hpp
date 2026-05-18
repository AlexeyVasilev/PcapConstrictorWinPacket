#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include "capture/NpcapDriverStats.hpp"
#include "capture/PcapLinkType.hpp"
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
[[nodiscard]] std::string_view PcapLinkTypeString(PcapLinkType link_type) noexcept;
[[nodiscard]] std::string FormatLiveCaptureStartupSummary(
    std::string_view interface_name,
    const std::filesystem::path& output_path,
    std::uint32_t snaplen,
    std::uint32_t read_timeout_ms,
    bool promiscuous,
    PcapLinkType link_type,
    std::uint64_t max_packets,
    std::uint64_t duration_sec);
[[nodiscard]] std::string FormatLiveCaptureSummary(
    LiveCaptureTerminationReason reason,
    const CaptureStats& stats,
    const NpcapDriverStats& driver_stats,
    double elapsed_seconds,
    const std::filesystem::path& output_path,
    bool promiscuous);

}  // namespace pcap_constrictor_winpacket
