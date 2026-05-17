#pragma once

#include <span>
#include <string>
#include <vector>

namespace pcap_constrictor_winpacket {

struct NpcapInterfaceInfo {
    std::string name;
    std::string description;
    std::vector<std::string> addresses;
    bool is_loopback{false};
    bool is_up{false};
    bool is_running{false};
    bool is_wireless{false};
};

struct NpcapInterfaceListResult {
    std::vector<NpcapInterfaceInfo> interfaces;
    std::string error;

    [[nodiscard]] bool ok() const noexcept {
        return error.empty();
    }

    explicit operator bool() const noexcept {
        return ok();
    }
};

[[nodiscard]] bool HasNpcapInterfaceListingSupport() noexcept;
[[nodiscard]] NpcapInterfaceListResult ListNpcapInterfaces();
[[nodiscard]] std::string FormatNpcapInterfaceList(
    std::span<const NpcapInterfaceInfo> interfaces);

}  // namespace pcap_constrictor_winpacket
