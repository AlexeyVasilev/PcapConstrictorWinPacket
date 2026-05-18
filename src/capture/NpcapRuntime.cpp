#include "capture/NpcapRuntime.hpp"

#include <utility>

#ifdef _WIN32
#include <windows.h>
#endif

namespace pcap_constrictor_winpacket {
namespace {

#ifdef _WIN32
std::string FormatLoadFailureDetail(std::string_view dll_name, const DWORD error_code) {
    std::string detail = "failed to load ";
    detail += dll_name;
    detail += " (GetLastError=";
    detail += std::to_string(static_cast<unsigned long>(error_code));
    detail += ")";
    return detail;
}
#endif

}  // namespace

std::string FormatNpcapRuntimeMissingMessage(const std::string_view detail) {
    std::string message =
        "Npcap runtime was not found.\n"
        "\n"
        "PcapConstrictorWinPacket was built with Npcap support, but wpcap.dll/Packet.dll\n"
        "could not be loaded.\n"
        "\n"
        "Install the Npcap runtime, then run this command again.\n"
        "The Npcap SDK is only required when building from source.";

    if (!detail.empty()) {
        message += "\n";
        message += "Details: ";
        message += detail;
    }

    return message;
}

NpcapRuntimeCheck CheckNpcapRuntimeAvailable() {
#ifdef _WIN32
    HMODULE wpcap_module = LoadLibraryA("wpcap.dll");
    if (wpcap_module == nullptr) {
        return NpcapRuntimeCheck{
            .available = false,
            .message = FormatNpcapRuntimeMissingMessage(
                FormatLoadFailureDetail("wpcap.dll", GetLastError())),
        };
    }

    HMODULE packet_module = LoadLibraryA("Packet.dll");
    if (packet_module == nullptr) {
        const DWORD error_code = GetLastError();
        FreeLibrary(wpcap_module);
        return NpcapRuntimeCheck{
            .available = false,
            .message = FormatNpcapRuntimeMissingMessage(
                FormatLoadFailureDetail("Packet.dll", error_code)),
        };
    }

    FreeLibrary(packet_module);
    FreeLibrary(wpcap_module);
#endif

    return NpcapRuntimeCheck{.available = true, .message = {}};
}

}  // namespace pcap_constrictor_winpacket
