# Minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Project name and language
project(cufh_attacker C)

# Set build type to Release for optimizations (-O3)
set(CMAKE_BUILD_TYPE Release)

# Define the executable name
set(PRJ dos-attacker)

# Set the source files
set(SOURCES
    src/main.c
    src/cpus.c
    src/dpdk.c
    src/pcap.c
    src/utils.c
)


# Automatically find PCAP_DIR (libpcap) if not set
if(NOT DEFINED ENV{PCAP_DIR})
    message(FATAL_ERROR "libpcap not found. Please set PCAP_DIR environment variable or install libpcap.")
else()
    set(PCAP_DIR $ENV{PCAP_DIR})
endif()


include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${PCAP_DIR})

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -g -O3 -std=gnu11")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lm -lnuma")

SET(DPDK_LIBS "-Wl,--whole-archive -ldpdk -Wl,--no-whole-archive")

# Add PCAP include directory and link PCAP library

# Add executable target
add_executable(${PRJ} ${SOURCES})

target_link_libraries(${PRJ} ${DPDK_LIBS})
target_link_libraries(${PRJ} pthread dl rt m numa)
target_link_libraries(${PRJ} ${PCAP_LIBRARY})
