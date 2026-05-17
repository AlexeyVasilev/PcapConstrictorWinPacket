#include <atomic>
#include <filesystem>
#include <iostream>
#include <string_view>

#include "capture/LiveCaptureReporting.hpp"
#include "capture/NpcapCapture.hpp"
#include "capture/NpcapInterfaceList.hpp"
#include "config/ConfigLoader.hpp"
#include "offline/OfflinePacketFeed.hpp"
#include "stats/CaptureStats.hpp"

#ifdef _WIN32
#include <windows.h>

#ifdef interface
#undef interface
#endif
#else
#include <csignal>
#endif

namespace pcap_constrictor_winpacket {
namespace {

std::atomic_bool g_stop_requested{false};

#ifdef _WIN32
BOOL WINAPI HandleConsoleCtrl(DWORD control_type) {
    if (control_type == CTRL_C_EVENT || control_type == CTRL_BREAK_EVENT) {
        g_stop_requested.store(true, std::memory_order_relaxed);
        return TRUE;
    }

    return FALSE;
}
#else
void HandleStopSignal(int) {
    g_stop_requested.store(true, std::memory_order_relaxed);
}
#endif

void InstallStopHandlers() {
#ifdef _WIN32
    SetConsoleCtrlHandler(HandleConsoleCtrl, TRUE);
#else
    std::signal(SIGINT, HandleStopSignal);
#ifdef SIGTERM
    std::signal(SIGTERM, HandleStopSignal);
#endif
#endif
}

void PrintUsage(std::ostream& output) {
    output << "Usage:\n"
           << "  PcapConstrictorWinPacket --list-interfaces\n"
           << "  PcapConstrictorWinPacket --config <config.ini>\n"
           << "  PcapConstrictorWinPacket --config <config.ini> --offline-input <input.pcap>\n"
           << "  PcapConstrictorWinPacket --help\n";
}

void PrintOfflineStats(std::ostream& output, const CaptureStats& stats) {
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
        PrintOfflineStats(std::cout, feed_result.stats);
    }

    return 0;
}

int RunUnavailableLiveCaptureMessage() {
    std::cerr
        << "Npcap live capture is unavailable in this build.\n"
        << "Reconfigure with NPCAP_SDK_DIR to enable live capture and --list-interfaces.\n";
    return 1;
}

int RunListInterfaces() {
    const NpcapInterfaceListResult result = ListNpcapInterfaces();
    if (!result) {
        std::cerr << "Npcap interface listing error: " << result.error << '\n';
        return 1;
    }

    if (result.interfaces.empty()) {
        std::cout << "Npcap reported no capture interfaces.\n";
        return 0;
    }

    std::cout << FormatNpcapInterfaceList(result.interfaces) << '\n';
    return 0;
}

int RunLiveCapture(const PolicyConfig& config) {
    if (!NpcapCapture::HasSupport()) {
        return RunUnavailableLiveCaptureMessage();
    }

    if (config.capture.interface.empty()) {
        std::cerr
            << "Configuration error: capture.interface is required for live capture.\n"
            << "Run PcapConstrictorWinPacket --list-interfaces and copy a name into config.ini.\n";
        return 1;
    }

    g_stop_requested.store(false, std::memory_order_relaxed);
    InstallStopHandlers();

    std::cout << "Starting live capture.\n"
              << "backend: npcap\n"
              << "interface: " << config.capture.interface << '\n'
              << "output: " << config.capture.output.string() << '\n'
              << "promiscuous: " << (config.capture.promiscuous ? "true" : "false") << '\n'
              << "default_snaplen: " << config.capture.default_snaplen << '\n'
              << "max_capture_len: " << config.capture.max_capture_len << '\n'
              << "read_timeout_ms: " << config.capture.read_timeout_ms << '\n';
    if (config.capture.max_packets != 0U) {
        std::cout << "max_packets: " << config.capture.max_packets << '\n';
    }
    if (config.capture.duration_sec != 0U) {
        std::cout << "duration_sec: " << config.capture.duration_sec << '\n';
    }
    std::cout << "Press Ctrl+C to stop.\n";

    NpcapCapture capture(config.capture);
    const NpcapCaptureRunResult result =
        capture.Run(config, config.capture.output, &g_stop_requested);

    if (!result.warning.empty()) {
        std::cerr << "Npcap warning: " << result.warning << '\n';
    }

    if (result.termination_reason == LiveCaptureTerminationReason::Interrupted) {
        std::cout << "Capture interrupted, finalizing output...\n";
    }

    const std::string summary = FormatLiveCaptureSummary(
        result.termination_reason,
        result.stats,
        result.elapsed_seconds,
        config.capture.output);

    if (!result) {
        std::cerr << "Live capture error: " << result.error << '\n';
        std::cerr << summary;
        return 1;
    }

    std::cout << summary;

    return LiveCaptureTerminationIsSuccess(result.termination_reason) ? 0 : 1;
}

}  // namespace
}  // namespace pcap_constrictor_winpacket

int main(int argc, char* argv[]) {
    using namespace pcap_constrictor_winpacket;

    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        PrintUsage(std::cout);
        return 0;
    }
    if (argc == 2 && std::string_view(argv[1]) == "--list-interfaces") {
        return RunListInterfaces();
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

    return RunLiveCapture(result.config);
}
