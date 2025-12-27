cmake_minimum_required(VERSION 3.10)
project(FileSigner C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 设置编译选项
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -Wall -Wextra")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall")
endif()

# 查找 OpenSSL
find_package(OpenSSL REQUIRED)

if(NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found")
endif()

message(STATUS "Found OpenSSL: ${OPENSSL_INCLUDE_DIR}")

# 包含目录
include_directories(
    src/include
    ${OPENSSL_INCLUDE_DIR}
)

# 源代码文件
set(SOURCE_FILES
    src/main/file_signer.c
    src/main/verify_sig.c
    src/utils/file_utils.c
    src/utils/crypto_utils.c
)

# 主可执行文件：file_signer
add_executable(file_signer
    src/main/file_signer.c
    src/utils/file_utils.c
    src/utils/crypto_utils.c
 "src/include/signature_format.h" "src/utils/signature_utils.c")

target_link_libraries(file_signer OpenSSL::Crypto)

# 验证工具可执行文件：verify_sig
add_executable(verify_sig
    src/main/verify_sig.c
    src/utils/file_utils.c
    src/utils/crypto_utils.c
 "src/include/signature_format.h" "src/utils/signature_utils.c")

target_link_libraries(verify_sig OpenSSL::Crypto)

# 安装目标
install(TARGETS file_signer verify_sig
    DESTINATION bin
)

# 可选：静态链接版本
if(BUILD_STATIC)
    add_executable(file_signer_static
        src/main/file_signer.c
        src/utils/file_utils.c
        src/utils/crypto_utils.c
    )
    
    target_link_libraries(file_signer_static OpenSSL::Crypto)
    set_target_properties(file_signer_static PROPERTIES
        LINK_FLAGS "-static"
    )
endif()

# 测试目标
if(BUILD_TESTS)
    enable_testing()
    
    add_executable(test_filesigner
        test/test_main.c
        src/utils/file_utils.c
        src/utils/crypto_utils.c
    )
    
    target_link_libraries(test_filesigner OpenSSL::Crypto)
    
    add_test(NAME test_filesigner COMMAND test_filesigner)
endif()