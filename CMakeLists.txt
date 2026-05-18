cmake_minimum_required(VERSION 3.20)

project(PcapConstrictorWinPacket VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)

set(PCAP_CONSTRICTOR_WINPACKET_ENABLE_NPCAP_INTERFACE_LISTING_DEFAULT OFF)
if(WIN32 AND NPCAP_SDK_DIR)
    set(PCAP_CONSTRICTOR_WINPACKET_ENABLE_NPCAP_INTERFACE_LISTING_DEFAULT ON)
endif()

option(PCAP_CONSTRICTOR_WINPACKET_ENABLE_NPCAP_INTERFACE_LISTING
    "Enable Npcap/libpcap-backed interface discovery and basic live capture"
    ${PCAP_CONSTRICTOR_WINPACKET_ENABLE_NPCAP_INTERFACE_LISTING_DEFAULT})

set(PCAP_CONSTRICTOR_WINPACKET_HAS_NPCAP 0)
if(PCAP_CONSTRICTOR_WINPACKET_ENABLE_NPCAP_INTERFACE_LISTING)
    if(NOT WIN32)
        message(FATAL_ERROR
            "Npcap interface listing is only supported on Windows. "
            "Set PCAP_CONSTRICTOR_WINPACKET_ENABLE_NPCAP_INTERFACE_LISTING=OFF for offline-only builds.")
    endif()

    if(NOT NPCAP_SDK_DIR)
        message(WARNING
            "NPCAP_SDK_DIR is not set, so Npcap interface listing will be disabled for this build. "
            "Provide -DNPCAP_SDK_DIR=... to enable --list-interfaces and live capture.")
        set(PCAP_CONSTRICTOR_WINPACKET_ENABLE_NPCAP_INTERFACE_LISTING OFF CACHE BOOL
            "Enable Npcap/libpcap-backed interface discovery and basic live capture" FORCE)
    endif()
endif()

if(PCAP_CONSTRICTOR_WINPACKET_ENABLE_NPCAP_INTERFACE_LISTING)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib/x64")
    else()
        set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib")
    endif()

    set(NPCAP_INCLUDE_DIR "${NPCAP_SDK_DIR}/Include")
    set(NPCAP_WPCAP_LIB "${NPCAP_LIB_DIR}/wpcap.lib")
    set(NPCAP_PACKET_LIB "${NPCAP_LIB_DIR}/Packet.lib")

    if(NOT EXISTS "${NPCAP_INCLUDE_DIR}/pcap.h")
        message(FATAL_ERROR "Npcap header not found: ${NPCAP_INCLUDE_DIR}/pcap.h")
    endif()
    if(NOT EXISTS "${NPCAP_WPCAP_LIB}")
        message(FATAL_ERROR "Npcap library not found: ${NPCAP_WPCAP_LIB}")
    endif()
    if(NOT EXISTS "${NPCAP_PACKET_LIB}")
        message(FATAL_ERROR "Npcap library not found: ${NPCAP_PACKET_LIB}")
    endif()

    set(PCAP_CONSTRICTOR_WINPACKET_HAS_NPCAP 1)
endif()

add_library(PcapConstrictorWinPacketCore STATIC
    src/capture/LiveCaptureReporting.cpp
    src/capture/NpcapInterfaceListFormatting.cpp
    src/capture/NpcapRuntime.cpp
    src/config/ConfigLoader.cpp
    src/decode/PacketDecode.cpp
    src/offline/OfflinePacketFeed.cpp
    src/offline/PcapReader.cpp
    src/policy/LiveCapturePolicy.cpp
    src/policy/QuicConstrictor.cpp
    src/policy/TlsConstrictor.cpp
    src/writer/PcapWriter.cpp
)

target_include_directories(PcapConstrictorWinPacketCore
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_features(PcapConstrictorWinPacketCore PUBLIC cxx_std_20)
target_compile_definitions(PcapConstrictorWinPacketCore
    PUBLIC
        PCAP_CONSTRICTOR_WINPACKET_HAS_NPCAP=${PCAP_CONSTRICTOR_WINPACKET_HAS_NPCAP}
)

add_executable(PcapConstrictorWinPacket
    src/main.cpp
    src/capture/NpcapCapture.cpp
    src/capture/NpcapInterfaceList.cpp
)

target_compile_definitions(PcapConstrictorWinPacket
    PRIVATE
        PCAP_CONSTRICTOR_WINPACKET_HAS_NPCAP=${PCAP_CONSTRICTOR_WINPACKET_HAS_NPCAP}
)

if(PCAP_CONSTRICTOR_WINPACKET_ENABLE_NPCAP_INTERFACE_LISTING)
    target_include_directories(PcapConstrictorWinPacket
        PRIVATE
            ${NPCAP_INCLUDE_DIR}
    )
    target_link_libraries(PcapConstrictorWinPacket
        PRIVATE
            ${NPCAP_WPCAP_LIB}
            ${NPCAP_PACKET_LIB}
            Ws2_32
    )

    if(MSVC)
        target_link_options(PcapConstrictorWinPacket PRIVATE
            "/DELAYLOAD:wpcap.dll"
            "/DELAYLOAD:Packet.dll"
        )
        target_link_libraries(PcapConstrictorWinPacket PRIVATE delayimp)
    elseif(WIN32)
        message(WARNING
            "Npcap support is enabled for a non-MSVC Windows build. "
            "Graceful missing-Npcap runtime diagnostics are not guaranteed in this configuration "
            "because delay-load for wpcap.dll/Packet.dll is only configured for MSVC in v0.1.0. "
            "If the DLLs are unavailable in the Windows DLL search path, the process may fail before main().")
        # TODO: Add an equivalent lazy Npcap runtime loading strategy for non-MSVC
        # Windows toolchains. v0.1.0 release hardening currently relies on MSVC
        # delay-load support so the executable can reach main() before touching
        # wpcap.dll/Packet.dll.
    endif()
endif()

target_link_libraries(PcapConstrictorWinPacket
    PRIVATE
        PcapConstrictorWinPacketCore
)

add_executable(PcapConstrictorWinPacketTests
    tests/TestMain.cpp
    tests/ConfigLoaderTests.cpp
    tests/GoldenOfflineWorkflowTests.cpp
    tests/LivePolicyClassificationTests.cpp
    tests/LiveCaptureReportingTests.cpp
    tests/LivePolicyQuicTests.cpp
    tests/LivePolicySmokeTests.cpp
    tests/NpcapInterfaceListTests.cpp
    tests/NpcapRuntimeTests.cpp
    tests/OfflinePacketFeedTests.cpp
    tests/PacketDecodeTests.cpp
    tests/PcapReaderTests.cpp
    tests/PcapWriterTests.cpp
    tests/QuicConstrictorTests.cpp
    tests/TlsConstrictorTests.cpp
)

target_link_libraries(PcapConstrictorWinPacketTests
    PRIVATE
        PcapConstrictorWinPacketCore
)

target_compile_definitions(PcapConstrictorWinPacketTests
    PRIVATE
        PCAP_CONSTRICTOR_WINPACKET_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
        PCAP_CONSTRICTOR_WINPACKET_BINARY_DIR="${CMAKE_CURRENT_BINARY_DIR}"
)

if(BUILD_TESTING)
    add_test(NAME PcapConstrictorWinPacketTests COMMAND PcapConstrictorWinPacketTests)
endif()
