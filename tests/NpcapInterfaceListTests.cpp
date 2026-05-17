#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "capture/NpcapInterfaceList.hpp"

namespace {

int Fail(std::string_view message) {
    std::cerr << "[NpcapInterfaceListTests] " << message << '\n';
    return 1;
}

}  // namespace

int RunNpcapInterfaceListTests() {
    using namespace pcap_constrictor_winpacket;

    {
        const std::string formatted =
            FormatNpcapInterfaceList(std::span<const NpcapInterfaceInfo>{});
        if (!formatted.empty()) {
            return Fail("empty interface list should format to an empty string");
        }
    }

    {
        const std::vector<NpcapInterfaceInfo> interfaces{
            NpcapInterfaceInfo{
                .name = R"(\Device\NPF_{AAAA-BBBB})",
                .description = "Ethernet",
                .addresses = {"192.168.1.10", "fe80::1234"},
                .is_loopback = false,
                .is_up = true,
                .is_running = true,
                .is_wireless = false,
            },
            NpcapInterfaceInfo{
                .name = R"(\Device\NPF_{CCCC-DDDD})",
                .description = "",
                .addresses = {},
                .is_loopback = true,
                .is_up = false,
                .is_running = false,
                .is_wireless = false,
            },
        };

        const std::string formatted = FormatNpcapInterfaceList(interfaces);
        const std::string expected =
            "[0]\n"
            "  name: \\Device\\NPF_{AAAA-BBBB}\n"
            "  description: Ethernet\n"
            "  addresses: 192.168.1.10, fe80::1234\n"
            "  flags: up, running\n"
            "\n"
            "[1]\n"
            "  name: \\Device\\NPF_{CCCC-DDDD}\n"
            "  flags: loopback\n";

        if (formatted != expected) {
            return Fail("formatted interface listing mismatch");
        }
    }

    return 0;
}
