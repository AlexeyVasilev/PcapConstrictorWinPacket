#pragma once

#include <cstdint>

namespace pcap_constrictor_winpacket {

enum class PcapLinkType : std::uint32_t {
    Null = 0,
    Ethernet = 1,
};

}  // namespace pcap_constrictor_winpacket
