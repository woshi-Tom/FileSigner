#ifndef SIGNATURE_FORMAT_H
#define SIGNATURE_FORMAT_H

#include <stdint.h>

#define SIGNATURE_MAGIC "FILESIG1"
#define SIGNATURE_VERSION 1

// 哈希算法标识
typedef enum {
    HASH_SHA256 = 1,
    HASH_SHA384 = 2,
    HASH_SHA512 = 3
} HashAlgorithm;

// 签名文件头部
typedef struct {
    char magic[8];           // 魔数："FILESIG1"
    uint32_t version;        // 格式版本：1
    uint32_t hash_algo;      // 哈希算法标识
    uint64_t orig_size;      // 原始文件大小（字节）
    uint64_t orig_mtime;     // 原始文件修改时间（Unix时间戳）
    uint64_t sig_time;       // 签名时间（Unix时间戳）
    uint32_t sig_length;     // 签名数据长度（字节）
    // 注意：签名数据紧随头部之后
} SignatureHeader;

// 验证头部有效性
int validate_signature_header(const SignatureHeader* header);

// 读取签名文件
int read_signature_file(const char* filename,
    SignatureHeader* header,
    unsigned char** signature);

// 写入签名文件
int write_signature_file(const char* filename,
    const SignatureHeader* header,
    const unsigned char* signature);

// 计算头部大小
size_t get_signature_header_size(void);

#endif // SIGNATURE_FORMAT_H