#pragma once

#include <string>
#include <string_view>

namespace pcap_constrictor_winpacket {

struct NpcapRuntimeCheck {
    bool available{false};
    std::string message;
};

[[nodiscard]] std::string FormatNpcapRuntimeMissingMessage(std::string_view detail);
[[nodiscard]] NpcapRuntimeCheck CheckNpcapRuntimeAvailable();

}  // namespace pcap_constrictor_winpacket
