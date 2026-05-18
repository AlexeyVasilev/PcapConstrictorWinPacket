#pragma once

#include <cstdint>

namespace pcap_constrictor_winpacket {

struct NpcapDriverStats {
    std::uint32_t received_by_driver{0};
    std::uint32_t dropped_by_driver_or_os{0};
    std::uint32_t dropped_by_interface{0};
    bool available{false};
};

}  // namespace pcap_constrictor_winpacket
