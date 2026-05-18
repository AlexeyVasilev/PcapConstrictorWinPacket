#include <iostream>
#include <string>
#include <string_view>

#include "capture/NpcapRuntime.hpp"

namespace {

int Fail(std::string_view message) {
    std::cerr << "[NpcapRuntimeTests] " << message << '\n';
    return 1;
}

bool ContainsAll(const std::string& haystack,
                 std::string_view first,
                 std::string_view second,
                 std::string_view third,
                 std::string_view fourth) {
    return haystack.find(first) != std::string::npos &&
           haystack.find(second) != std::string::npos &&
           haystack.find(third) != std::string::npos &&
           haystack.find(fourth) != std::string::npos;
}

}  // namespace

int RunNpcapRuntimeTests() {
    using namespace pcap_constrictor_winpacket;

    {
        const std::string message =
            FormatNpcapRuntimeMissingMessage("failed to load wpcap.dll (GetLastError=126)");

        if (!ContainsAll(message,
                         "Npcap runtime was not found.",
                         "wpcap.dll/Packet.dll",
                         "Install the Npcap runtime, then run this command again.",
                         "The Npcap SDK is only required when building from source.")) {
            return Fail("missing-runtime message should explain runtime installation and SDK scope");
        }

        if (message.find("Details: failed to load wpcap.dll (GetLastError=126)") ==
            std::string::npos) {
            return Fail("missing-runtime message should include failure details when provided");
        }
    }

    {
        const std::string message = FormatNpcapRuntimeMissingMessage({});
        if (message.find("Details:") != std::string::npos) {
            return Fail("missing-runtime message should omit details when none are provided");
        }
    }

    return 0;
}
