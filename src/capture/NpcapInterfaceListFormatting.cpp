#include "capture/NpcapInterfaceList.hpp"

#include <sstream>
#include <vector>

namespace pcap_constrictor_winpacket {
namespace {

std::string JoinStrings(const std::vector<std::string>& parts) {
    std::ostringstream output;
    for (std::size_t index = 0; index < parts.size(); ++index) {
        if (index != 0U) {
            output << ", ";
        }
        output << parts[index];
    }
    return output.str();
}

std::vector<std::string> CollectFlags(const NpcapInterfaceInfo& info) {
    std::vector<std::string> flags;
    if (info.is_loopback) {
        flags.emplace_back("loopback");
    }
    if (info.is_up) {
        flags.emplace_back("up");
    }
    if (info.is_running) {
        flags.emplace_back("running");
    }
    if (info.is_wireless) {
        flags.emplace_back("wireless");
    }
    return flags;
}

}  // namespace

std::string FormatNpcapInterfaceList(std::span<const NpcapInterfaceInfo> interfaces) {
    std::ostringstream output;

    for (std::size_t index = 0; index < interfaces.size(); ++index) {
        const NpcapInterfaceInfo& info = interfaces[index];
        output << '[' << index << "]\n"
               << "  name: " << info.name << '\n';

        if (!info.description.empty()) {
            output << "  description: " << info.description << '\n';
        }

        if (!info.addresses.empty()) {
            output << "  addresses: " << JoinStrings(info.addresses) << '\n';
        }

        const std::vector<std::string> flags = CollectFlags(info);
        if (!flags.empty()) {
            output << "  flags: " << JoinStrings(flags) << '\n';
        }

        if (index + 1U != interfaces.size()) {
            output << '\n';
        }
    }

    return output.str();
}

}  // namespace pcap_constrictor_winpacket
