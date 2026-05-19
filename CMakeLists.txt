cmake_minimum_required(VERSION 3.10)
project(FileSigner C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
if(MSVC)
    add_compile_options(/W3 /utf-8 $<$<CONFIG:Release>:/O2>)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -Wall -Wextra")
    else()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall")
    endif()
endif()

# Find OpenSSL (3.x required — 1.x is EOL with known CVEs)
find_package(OpenSSL 3.0 REQUIRED)
if(NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL 3.x not found. Install via: vcpkg install openssl:x64-windows")
endif()
message(STATUS "Found OpenSSL: ${OPENSSL_VERSION} at ${OPENSSL_INCLUDE_DIR}")

# Include directories
include_directories(
    src/include
    res
    ${OPENSSL_INCLUDE_DIR}
)

# Core source files
set(CORE_SOURCES
    src/core/pe_file.c
    src/core/authenticode.c
    src/core/cert_gen.c
    src/core/timestamp.c
    src/core/batch_signer.c
)

# Utility source files
set(UTIL_SOURCES
    src/utils/file_utils.c
)

# Main source files
set(MAIN_SOURCES
    src/main/main.c
    src/main/cli.c
    src/gui/gui_main.c
)

# Resource file (icon + version info)
set(RESOURCE_FILES
    res/resource.rc
)

# Single executable: double-click = GUI, command-line args = CLI
add_executable(filesigner
    ${MAIN_SOURCES}
    ${CORE_SOURCES}
    ${UTIL_SOURCES}
    ${RESOURCE_FILES}
)

if(MSVC)
    set_target_properties(filesigner PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:WINDOWS /STACK:8388608"
    )
endif()

target_link_libraries(filesigner
    OpenSSL::Crypto
    winhttp
    crypt32
    comctl32
    ole32
)

# Install
install(TARGETS filesigner
    DESTINATION bin
)
