#include "signature_format.h"
#include "crypto_utils.h"
#include "file_utils.h"
#include <string.h>
#include <time.h>
#include <sys/stat.h>

// 创建签名文件
int create_signature(const char* original_file,
    EVP_PKEY* private_key,
    X509* certificate,
    const char* output_sig_file) {
    // 1. 计算文件哈希
    unsigned char hash[EVP_MAX_MD_SIZE];
    size_t hash_len;

    if (!calculate_file_hash(original_file, hash, &hash_len, EVP_sha256())) {
        return 0;
    }

    // 2. 签名哈希
    unsigned char* signature = NULL;
    size_t sig_len;

    if (!sign_data(private_key, hash, hash_len, &signature, &sig_len, EVP_sha256())) {
        return 0;
    }

    // 3. 获取文件信息
    struct stat st;
    if (stat(original_file, &st) != 0) {
        free(signature);
        return 0;
    }

    // 4. 创建签名头
    SignatureHeader header;
    memcpy(header.magic, SIGNATURE_MAGIC, 8);
    header.version = SIGNATURE_VERSION;
    header.hash_algo = HASH_SHA256;
    header.orig_size = st.st_size;
    header.orig_mtime = st.st_mtime;
    header.sig_time = time(NULL);
    header.sig_length = sig_len;

    // 5. 写入签名文件
    int result = write_signature_file(output_sig_file, &header, signature);

    free(signature);
    return result;
}

// 验证签名文件
int verify_signature(const char* original_file,
    const char* sig_file,
    EVP_PKEY* public_key) {
    // 1. 读取签名文件
    SignatureHeader header;
    unsigned char* signature = NULL;

    if (!read_signature_file(sig_file, &header, &signature)) {
        return 0;
    }

    // 2. 验证头部
    if (!validate_signature_header(&header)) {
        free(signature);
        return 0;
    }

    // 3. 获取哈希算法
    const EVP_MD* md = NULL;
    switch (header.hash_algo) {
    case HASH_SHA256: md = EVP_sha256(); break;
    case HASH_SHA384: md = EVP_sha384(); break;
    case HASH_SHA512: md = EVP_sha512(); break;
    default:
        free(signature);
        return 0;
    }

    // 4. 计算原始文件哈希
    unsigned char hash[EVP_MAX_MD_SIZE];
    size_t hash_len;

    if (!calculate_file_hash(original_file, hash, &hash_len, md)) {
        free(signature);
        return 0;
    }

    // 5. 验证签名
    int result = verify_signature(public_key, hash, hash_len,
        signature, header.sig_length, md);

    free(signature);
    return result;
}