cmake_minimum_required(VERSION 3.10)
project(FileSigner C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
if(MSVC)
    add_compile_options(/W3 /utf-8 $<$<CONFIG:Release>:/O2>)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    # Ensure C11 mode for Sciter SDK headers that use 'inline'
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /std:c11")
else()
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -Wall -Wextra")
    else()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall")
    endif()
endif()

# Sciter SDK path — set SCITER_SDK_DIR or put SDK in third_party/sciter/
if(NOT SCITER_SDK_DIR)
    set(SCITER_SDK_DIR "${CMAKE_SOURCE_DIR}/third_party/sciter")
endif()

if(EXISTS "${SCITER_SDK_DIR}/include/sciter-x.h")
    message(STATUS "Found Sciter SDK: ${SCITER_SDK_DIR}")
    set(HAVE_SCITER TRUE)
    add_definitions(-DHAVE_SCITER -DSKIP_MAIN)
    set(SCITER_INCLUDE_DIR "${SCITER_SDK_DIR}/include")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(SCITER_LIB_DIR "${SCITER_SDK_DIR}/bin.win/x64")
    else()
        set(SCITER_LIB_DIR "${SCITER_SDK_DIR}/bin.win/x32")
    endif()
else()
    message(WARNING "Sciter SDK not found at ${SCITER_SDK_DIR}. "
                    "GUI will not be built. Download from: "
                    "https://github.com/c-smile/sciter-sdk")
    set(HAVE_SCITER FALSE)
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
    ${SCITER_INCLUDE_DIR}
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
)

# GUI source — only if Sciter SDK is available
if(HAVE_SCITER)
    list(APPEND MAIN_SOURCES
        src/gui/gui_main.c
    )
endif()

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
)

# Sciter uses LoadLibrary/GetProcAddress at runtime — no import lib needed.
# The DLL must be next to the executable.

if(WIN32)
    target_link_libraries(filesigner
        winhttp
        crypt32
        comctl32
        ole32
    )
endif()

# Copy sciter.dll next to the executable
if(HAVE_SCITER AND WIN32)
    add_custom_command(TARGET filesigner POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${SCITER_LIB_DIR}/sciter.dll"
            "$<TARGET_FILE_DIR:filesigner>/sciter.dll"
        COMMENT "Copying sciter.dll"
    )
endif()

# Install
install(TARGETS filesigner
    DESTINATION bin
)

if(HAVE_SCITER AND WIN32)
    install(FILES "${SCITER_LIB_DIR}/sciter.dll"
        DESTINATION bin
    )
endif()
