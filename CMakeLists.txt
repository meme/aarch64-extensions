cmake_minimum_required(VERSION 3.1)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "-Werror -Wall -Wextra -Wno-parentheses -Wno-unused-function")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)

find_library(BINJA_CORE_LIBRARY
        NAMES binaryninjacore libbinaryninjacore.so.1
        PATHS /opt/binaryninja)

add_subdirectory(binaryninja-api)

# This is a bad joke, right? Right?
set(CAPSTONE_ARM64_SUPPORT ON)
option(CAPSTONE_ARM_SUPPORT OFF)
option(CAPSTONE_M68K_SUPPORT OFF)
option(CAPSTONE_MIPS_SUPPORT OFF)
option(CAPSTONE_PPC_SUPPORT OFF)
option(CAPSTONE_SPARC_SUPPORT OFF)
option(CAPSTONE_SYSZ_SUPPORT OFF)
option(CAPSTONE_XCORE_SUPPORT OFF)
option(CAPSTONE_X86_SUPPORT OFF)
option(CAPSTONE_TMS320C64X_SUPPORT OFF)
option(CAPSTONE_M680X_SUPPORT OFF)
option(CAPSTONE_EVM_SUPPORT OFF)

option(CAPSTONE_BUILD_TESTS OFF)
option(CAPSTONE_BUILD_CSTOOL OFF)

include_directories(capstone/include)

add_subdirectory(capstone)

add_library(aarch64_extension SHARED A64.cpp A64.h LiftDT.cpp LiftDT.h LiftFP.cpp LiftFP.h LiftGR.cpp LiftGR.h LiftVT.cpp LiftVT.h)
target_link_libraries(aarch64_extension binaryninjaapi capstone-static)
