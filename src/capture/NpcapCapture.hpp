#pragma once

#include <atomic>
#include <filesystem>
#include <string>
#include <string_view>

#include "capture/LiveCaptureReporting.hpp"
#include "policy/PolicyConfig.hpp"
#include "stats/CaptureStats.hpp"

namespace pcap_constrictor_winpacket {

struct NpcapCaptureRunResult {
    CaptureStats stats{};
    std::string error{};
    std::string warning{};
    LiveCaptureTerminationReason termination_reason{LiveCaptureTerminationReason::Stopped};
    PcapLinkType link_type{PcapLinkType::Ethernet};
    double elapsed_seconds{0.0};

    [[nodiscard]] bool ok() const noexcept {
        return error.empty();
    }

    explicit operator bool() const noexcept {
        return ok();
    }
};

class NpcapCapture {
public:
    explicit NpcapCapture(PolicyConfig::CaptureOptions config) noexcept;

    [[nodiscard]] static bool HasSupport() noexcept;
    [[nodiscard]] NpcapCaptureRunResult Run(
        const PolicyConfig& policy_config,
        const std::filesystem::path& output_path,
        std::atomic_bool* stop_requested = nullptr) const;

private:
    PolicyConfig::CaptureOptions config_;
};

}  // namespace pcap_constrictor_winpacket
