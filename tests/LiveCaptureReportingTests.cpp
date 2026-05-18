#include <iostream>
#include <string>
#include <string_view>

#include "capture/LiveCaptureReporting.hpp"

namespace {

int Fail(std::string_view message) {
    std::cerr << "[LiveCaptureReportingTests] " << message << '\n';
    return 1;
}

}  // namespace

int RunLiveCaptureReportingTests() {
    using namespace pcap_constrictor_winpacket;

    if (LiveCaptureTerminationReasonString(LiveCaptureTerminationReason::Interrupted) !=
        "interrupted") {
        return Fail("interrupted termination reason string mismatch");
    }

    if (LiveCaptureTerminationIsSuccess(LiveCaptureTerminationReason::Interrupted) != true) {
        return Fail("interrupted termination should be considered successful");
    }

    if (LiveCaptureTerminationIsSuccess(LiveCaptureTerminationReason::Error) != false) {
        return Fail("error termination should not be considered successful");
    }

    CaptureStats stats;
    stats.packets_total = 100U;
    stats.packets_written = 100U;
    stats.bytes_input = 12000U;
    stats.bytes_output = 4500U;
    stats.bytes_saved = 7500U;
    stats.receive_errors = 2U;
    stats.tls_appdata_constricted = 8U;
    stats.quic_short_constricted = 3U;

    NpcapDriverStats driver_stats;
    driver_stats.available = true;
    driver_stats.received_by_driver = 12345U;
    driver_stats.dropped_by_driver_or_os = 4U;
    driver_stats.dropped_by_interface = 1U;

    const std::string summary = FormatLiveCaptureSummary(
        LiveCaptureTerminationReason::MaxPacketsReached,
        stats,
        driver_stats,
        1.25,
        "live-test.pcap",
        false);

    const std::string startup = FormatLiveCaptureStartupSummary(
        "\\Device\\NPF_Loopback",
        "live-test.pcap",
        4096U,
        100U,
        true,
        PcapLinkType::Null,
        100U,
        10U);

    if (summary.find("termination: max_packets limit reached") == std::string::npos) {
        return Fail("summary should include termination reason");
    }
    if (summary.find("output: live-test.pcap") == std::string::npos) {
        return Fail("summary should include output path");
    }
    if (summary.find("promiscuous: disabled") == std::string::npos) {
        return Fail("summary should include promiscuous mode");
    }
    if (summary.find("packets_seen: 100") == std::string::npos) {
        return Fail("summary should include packets_seen");
    }
    if (summary.find("bytes_written: 4500") == std::string::npos) {
        return Fail("summary should include bytes_written");
    }
    if (summary.find("tls_appdata_constricted: 8") == std::string::npos) {
        return Fail("summary should include tls counter");
    }
    if (summary.find("quic_short_constricted: 3") == std::string::npos) {
        return Fail("summary should include quic counter");
    }
    if (summary.find("Npcap/libpcap stats:\n  ps_recv: 12345\n  ps_drop: 4\n  ps_ifdrop: 1") ==
        std::string::npos) {
        return Fail("summary should include Npcap/libpcap stats separately");
    }
    if (startup.find("promiscuous: enabled") == std::string::npos) {
        return Fail("startup summary should include promiscuous mode");
    }
    if (startup.find("linktype: DLT_NULL") == std::string::npos) {
        return Fail("startup summary should include linktype");
    }
    if (startup.find("max_packets: 100") == std::string::npos ||
        startup.find("duration_sec: 10") == std::string::npos) {
        return Fail("startup summary should include configured limits");
    }

    const std::string unavailable_summary = FormatLiveCaptureSummary(
        LiveCaptureTerminationReason::Interrupted,
        stats,
        NpcapDriverStats{},
        2.5,
        "loopback-test.pcap",
        true);
    if (unavailable_summary.find("Npcap/libpcap stats: unavailable") == std::string::npos) {
        return Fail("summary should report unavailable Npcap/libpcap stats");
    }
    if (unavailable_summary.find("packets_seen: 100") == std::string::npos ||
        unavailable_summary.find("ps_recv:") != std::string::npos) {
        return Fail("application counters and unavailable Npcap stats should stay separate");
    }

    return 0;
}
