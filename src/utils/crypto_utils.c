#include "crypto_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// 初始化 OpenSSL
int crypto_init(void) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    return 1;
}

// 清理 OpenSSL
void crypto_cleanup(void) {
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

// 加载私钥
EVP_PKEY* load_private_key(const char* key_path) {
    FILE* fp = fopen(key_path, "rb");
    if (!fp) {
        fprintf(stderr, "无法打开私钥文件: %s\n", key_path);
        return NULL;
    }

    EVP_PKEY* key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!key) {
        fprintf(stderr, "无法解析私钥文件: %s\n", key_path);
        unsigned long err = ERR_get_error();
        if (err != 0) {
            fprintf(stderr, "OpenSSL错误: %s\n", ERR_error_string(err, NULL));
        }
    }

    return key;
}

// 加载证书
X509* load_certificate(const char* cert_path) {
    FILE* fp = fopen(cert_path, "rb");
    if (!fp) {
        fprintf(stderr, "无法打开证书文件: %s\n", cert_path);
        return NULL;
    }

    X509* cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!cert) {
        fprintf(stderr, "无法解析证书文件: %s\n", cert_path);
        unsigned long err = ERR_get_error();
        if (err != 0) {
            fprintf(stderr, "OpenSSL错误: %s\n", ERR_error_string(err, NULL));
        }
    }

    return cert;
}

// 释放证书
void free_certificate(X509* cert) {
    if (cert) {
        X509_free(cert);
    }
}

// 释放私钥
void free_private_key(EVP_PKEY* key) {
    if (key) {
        EVP_PKEY_free(key);
    }
}

// 计算文件哈希
int calculate_file_hash(const char* filepath,
    unsigned char* hash,
    size_t* hash_len,
    const EVP_MD* md) {
    FILE* file = fopen(filepath, "rb");
    if (!file) {
        fprintf(stderr, "无法打开文件: %s\n", filepath);
        return 0;
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        fclose(file);
        return 0;
    }

    if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
        EVP_MD_CTX_free(md_ctx);
        fclose(file);
        return 0;
    }

    unsigned char buffer[8192];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (!EVP_DigestUpdate(md_ctx, buffer, bytes_read)) {
            EVP_MD_CTX_free(md_ctx);
            fclose(file);
            return 0;
        }
    }

    if (ferror(file)) {
        EVP_MD_CTX_free(md_ctx);
        fclose(file);
        return 0;
    }

    fclose(file);

    unsigned int len;
    if (!EVP_DigestFinal_ex(md_ctx, hash, &len)) {
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    if (hash_len) {
        *hash_len = len;
    }

    EVP_MD_CTX_free(md_ctx);
    return 1;
}

// 计算内存数据哈希
int calculate_data_hash(const unsigned char* data,
    size_t data_len,
    unsigned char* hash,
    size_t* hash_len,
    const EVP_MD* md) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return 0;
    }

    if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    if (!EVP_DigestUpdate(md_ctx, data, data_len)) {
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    unsigned int len;
    if (!EVP_DigestFinal_ex(md_ctx, hash, &len)) {
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    if (hash_len) {
        *hash_len = len;
    }

    EVP_MD_CTX_free(md_ctx);
    return 1;
}

// 使用私钥签名数据
int sign_data(EVP_PKEY* private_key,
    const unsigned char* data,
    size_t data_len,
    unsigned char** signature,
    size_t* sig_len,
    const EVP_MD* md) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx) {
        return 0;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    // 获取签名长度
    size_t sig_length;
    if (EVP_PKEY_sign(ctx, NULL, &sig_length, data, data_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    // 分配内存并签名
    unsigned char* sig = (unsigned char*)malloc(sig_length);
    if (!sig) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_sign(ctx, sig, &sig_length, data, data_len) <= 0) {
        free(sig);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);

    *signature = sig;
    *sig_len = sig_length;
    return 1;
}

// 使用公钥验证签名
int verify_signature(EVP_PKEY* public_key,
    const unsigned char* data,
    size_t data_len,
    const unsigned char* signature,
    size_t sig_len,
    const EVP_MD* md) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (!ctx) {
        return 0;
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    int result = EVP_PKEY_verify(ctx, signature, sig_len, data, data_len);

    EVP_PKEY_CTX_free(ctx);
    return result == 1;
}

// 从证书获取公钥
EVP_PKEY* get_public_key_from_cert(X509* cert) {
    if (!cert) {
        return NULL;
    }

    EVP_PKEY* public_key = X509_get_pubkey(cert);
    if (!public_key) {
        fprintf(stderr, "无法从证书提取公钥\n");
    }

    return public_key;
}

// 生成随机数（用于签名盐值）
int generate_random_bytes(unsigned char* buffer, size_t length) {
    if (!buffer || length == 0) {
        return 0;
    }

    FILE* urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        // 回退到伪随机数
        for (size_t i = 0; i < length; i++) {
            buffer[i] = rand() % 256;
        }
        return 1;
    }

    size_t bytes_read = fread(buffer, 1, length, urandom);
    fclose(urandom);

    return bytes_read == length;
}

// 将二进制数据转换为十六进制字符串
char* bin2hex(const unsigned char* data, size_t len) {
    if (!data || len == 0) {
        return NULL;
    }

    char* hex = (char*)malloc(len * 2 + 1);
    if (!hex) {
        return NULL;
    }

    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", data[i]);
    }

    hex[len * 2] = '\0';
    return hex;
}

// 将十六进制字符串转换为二进制数据
unsigned char* hex2bin(const char* hex, size_t* out_len) {
    if (!hex) {
        return NULL;
    }

    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        return NULL;
    }

    size_t bin_len = hex_len / 2;
    unsigned char* bin = (unsigned char*)malloc(bin_len);
    if (!bin) {
        return NULL;
    }

    for (size_t i = 0; i < bin_len; i++) {
        sscanf(hex + (i * 2), "%2hhx", &bin[i]);
    }

    if (out_len) {
        *out_len = bin_len;
    }

    return bin;
}