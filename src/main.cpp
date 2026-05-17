#include <filesystem>
#include <iostream>
#include <string_view>

#include "config/ConfigLoader.hpp"
#include "offline/OfflinePacketFeed.hpp"
#include "stats/CaptureStats.hpp"

namespace pcap_constrictor_winpacket {
namespace {

void PrintUsage(std::ostream& output) {
    output << "Usage:\n"
           << "  PcapConstrictorWinPacket --config <config.ini>\n"
           << "  PcapConstrictorWinPacket --config <config.ini> --offline-input <input.pcap>\n"
           << "  PcapConstrictorWinPacket --help\n";
}

void PrintCaptureStats(std::ostream& output, const CaptureStats& stats) {
    output << "packets_total: " << stats.packets_total << '\n'
           << "packets_written: " << stats.packets_written << '\n'
           << "bytes_input: " << stats.bytes_input << '\n'
           << "bytes_output: " << stats.bytes_output << '\n'
           << "bytes_saved: " << stats.bytes_saved << '\n'
           << "receive_errors: " << stats.receive_errors << '\n'
           << "tls_appdata_constricted: " << stats.tls_appdata_constricted << '\n'
           << "tls_fallback: " << stats.tls_fallback << '\n'
           << "quic_long_header: " << stats.quic_long_header << '\n'
           << "quic_short_matched: " << stats.quic_short_matched << '\n'
           << "quic_short_constricted: " << stats.quic_short_constricted << '\n'
           << "quic_fallback: " << stats.quic_fallback << '\n';
}

int RunOfflinePipeline(const std::filesystem::path& input_path,
                       const PolicyConfig& config) {
    const std::filesystem::path output_path = config.capture.output;
    const OfflinePacketFeedResult feed_result =
        OfflinePacketFeed::Run(input_path, output_path, config);
    if (!feed_result) {
        std::cerr << "Offline feed error: " << feed_result.error << '\n';
        return 1;
    }

    std::cout << "Offline feed completed.\n"
              << "input: " << input_path.string() << '\n'
              << "output: " << output_path.string() << '\n';

    if (config.stats.enabled) {
        PrintCaptureStats(std::cout, feed_result.stats);
    }

    return 0;
}

int RunPlannedLiveCaptureMessage(const PolicyConfig&) {
    std::cerr
        << "Npcap live capture is not implemented yet in this milestone.\n"
        << "Use --offline-input <input.pcap> to run the deterministic offline pipeline.\n";
    return 1;
}

}  // namespace
}  // namespace pcap_constrictor_winpacket

int main(int argc, char* argv[]) {
    using namespace pcap_constrictor_winpacket;

    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        PrintUsage(std::cout);
        return 0;
    }

    const bool config_only =
        argc == 3 && std::string_view(argv[1]) == "--config";
    const bool offline_mode =
        argc == 5 &&
        std::string_view(argv[1]) == "--config" &&
        std::string_view(argv[3]) == "--offline-input";

    if (!config_only && !offline_mode) {
        PrintUsage(std::cerr);
        return 1;
    }

    const ConfigLoadResult result = ConfigLoader::LoadFromFile(argv[2]);
    if (!result) {
        std::cerr << "Configuration error: " << result.error << '\n';
        return 1;
    }

    if (offline_mode) {
        return RunOfflinePipeline(argv[4], result.config);
    }

    return RunPlannedLiveCaptureMessage(result.config);
}
