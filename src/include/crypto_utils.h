#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <openssl/evp.h>
#include <openssl/x509.h>

// OpenSSL 初始化
int crypto_init(void);
void crypto_cleanup(void);

// 证书和密钥管理
EVP_PKEY* load_private_key(const char* key_path);
X509* load_certificate(const char* cert_path);
void free_certificate(X509* cert);
void free_private_key(EVP_PKEY* key);
EVP_PKEY* get_public_key_from_cert(X509* cert);

// 哈希计算
int calculate_file_hash(const char* filepath,
    unsigned char* hash,
    size_t* hash_len,
    const EVP_MD* md);

int calculate_data_hash(const unsigned char* data,
    size_t data_len,
    unsigned char* hash,
    size_t* hash_len,
    const EVP_MD* md);

// 签名和验证
int sign_data(EVP_PKEY* private_key,
    const unsigned char* data,
    size_t data_len,
    unsigned char** signature,
    size_t* sig_len,
    const EVP_MD* md);

int verify_signature(EVP_PKEY* public_key,
    const unsigned char* data,
    size_t data_len,
    const unsigned char* signature,
    size_t sig_len,
    const EVP_MD* md);

// 工具函数
int generate_random_bytes(unsigned char* buffer, size_t length);
char* bin2hex(const unsigned char* data, size_t len);
unsigned char* hex2bin(const char* hex, size_t* out_len);

// 常用哈希算法宏
#define HASH_SHA256 EVP_sha256()
#define HASH_SHA384 EVP_sha384()
#define HASH_SHA512 EVP_sha512()

#endif // CRYPTO_UTILS_H