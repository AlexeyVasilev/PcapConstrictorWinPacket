#include "capture/NpcapInterfaceList.hpp"

#include <sstream>
#include <utility>
#include <vector>

#if PCAP_CONSTRICTOR_WINPACKET_HAS_NPCAP
#include <winsock2.h>
#include <ws2tcpip.h>

#include <pcap.h>
#endif

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

#if PCAP_CONSTRICTOR_WINPACKET_HAS_NPCAP
int SockaddrLength(const sockaddr* address) {
    if (address == nullptr) {
        return 0;
    }

    switch (address->sa_family) {
        case AF_INET:
            return static_cast<int>(sizeof(sockaddr_in));
        case AF_INET6:
            return static_cast<int>(sizeof(sockaddr_in6));
        default:
            return 0;
    }
}

std::string SockaddrToNumericString(const sockaddr* address) {
    const int address_length = SockaddrLength(address);
    if (address_length == 0) {
        return {};
    }

    char host[NI_MAXHOST] = {};
    const int result = getnameinfo(address,
                                   address_length,
                                   host,
                                   static_cast<DWORD>(sizeof(host)),
                                   nullptr,
                                   0,
                                   NI_NUMERICHOST);
    if (result != 0) {
        return {};
    }

    return std::string(host);
}
#endif

}  // namespace

bool HasNpcapInterfaceListingSupport() noexcept {
#if PCAP_CONSTRICTOR_WINPACKET_HAS_NPCAP
    return true;
#else
    return false;
#endif
}

NpcapInterfaceListResult ListNpcapInterfaces() {
    NpcapInterfaceListResult result;

#if PCAP_CONSTRICTOR_WINPACKET_HAS_NPCAP
    char error_buffer[PCAP_ERRBUF_SIZE] = {};
    pcap_if_t* devices = nullptr;
    if (pcap_findalldevs(&devices, error_buffer) != 0) {
        result.error = error_buffer[0] != '\0'
                           ? std::string(error_buffer)
                           : "pcap_findalldevs failed with no error details";
        return result;
    }

    for (pcap_if_t* device = devices; device != nullptr; device = device->next) {
        NpcapInterfaceInfo info;
        info.name = device->name != nullptr ? device->name : "";
        info.description = device->description != nullptr ? device->description : "";
        info.is_loopback = (device->flags & PCAP_IF_LOOPBACK) != 0;
#ifdef PCAP_IF_UP
        info.is_up = (device->flags & PCAP_IF_UP) != 0;
#endif
#ifdef PCAP_IF_RUNNING
        info.is_running = (device->flags & PCAP_IF_RUNNING) != 0;
#endif
#ifdef PCAP_IF_WIRELESS
        info.is_wireless = (device->flags & PCAP_IF_WIRELESS) != 0;
#endif

        for (pcap_addr_t* address = device->addresses; address != nullptr; address = address->next) {
            const std::string numeric_address = SockaddrToNumericString(address->addr);
            if (!numeric_address.empty()) {
                info.addresses.push_back(numeric_address);
            }
        }

        result.interfaces.push_back(std::move(info));
    }

    if (devices != nullptr) {
        pcap_freealldevs(devices);
    }
    return result;
#else
    result.error =
        "Npcap interface listing is not enabled in this build. Configure with NPCAP_SDK_DIR "
        "or disable PCAP_CONSTRICTOR_WINPACKET_ENABLE_NPCAP_INTERFACE_LISTING for offline-only builds.";
    return result;
#endif
}

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
