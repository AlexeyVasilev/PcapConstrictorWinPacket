cmake_minimum_required(VERSION 3.20)

project(PcapConstrictorWinPacket VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)

add_library(PcapConstrictorWinPacketCore STATIC
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

add_executable(PcapConstrictorWinPacket
    src/main.cpp
)

target_link_libraries(PcapConstrictorWinPacket
    PRIVATE
        PcapConstrictorWinPacketCore
)

add_executable(PcapConstrictorWinPacketTests
    tests/TestMain.cpp
    tests/ConfigLoaderTests.cpp
    tests/GoldenOfflineWorkflowTests.cpp
    tests/LivePolicyClassificationTests.cpp
    tests/LivePolicyQuicTests.cpp
    tests/LivePolicySmokeTests.cpp
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
