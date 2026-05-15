cmake_minimum_required(VERSION 3.10)
project(FileSigner C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
if(MSVC)
    add_compile_options(/W3 /O2)
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

# CLI executable
add_executable(filesigner_cli
    src/main/cli.c
    ${CORE_SOURCES}
    ${UTIL_SOURCES}
)
set_target_properties(filesigner_cli PROPERTIES OUTPUT_NAME "filesigner")
target_link_libraries(filesigner_cli OpenSSL::Crypto)

if(WIN32)
    target_link_libraries(filesigner_cli winhttp crypt32)
endif()

# GUI executable (Windows only)
if(WIN32)
    add_executable(filesigner_gui
        src/gui/gui_main.c
        ${CORE_SOURCES}
        ${UTIL_SOURCES}
    )
    set_target_properties(filesigner_gui PROPERTIES
        OUTPUT_NAME "filesigner_gui"
        WIN32_EXECUTABLE TRUE
    )
    target_link_libraries(filesigner_gui OpenSSL::Crypto winhttp comctl32 ole32)
endif()

# Install
install(TARGETS filesigner_cli
    DESTINATION bin
)
if(WIN32)
    install(TARGETS filesigner_gui
        DESTINATION bin
    )
endif()
