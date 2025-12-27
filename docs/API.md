# FileSigner API 文档

## 概述
FileSigner 提供了一组 C API 用于文件签名和验证操作。

## 核心数据结构

### SignerConfig
签名配置结构体，包含所有签名操作的配置参数。

```c
typedef struct {
    char *cert_path;      // CA 证书路径
    char *key_path;       // 私钥路径
    char *input_dir;      // 输入目录
    char *output_dir;     // 输出目录
    int force_resign;     // 强制重新签名
    int thread_count;     // 线程数
    int verbose;          // 详细输出
    int verify_only;      // 仅验证模式
} SignerConfig;
```

FileList
文件列表结构体，用于管理文件路径。

c
typedef struct {
    char **files;        // 文件路径数组
    size_t count;        // 文件数量
    size_t capacity;     // 数组容量
} FileList;
核心函数
初始化函数
c
// 初始化签名器（调用 OpenSSL 初始化）
int signer_init(void);

// 清理签名器资源
void signer_cleanup(void);
配置管理
c
// 创建配置结构体
SignerConfig* signer_config_create(void);

// 释放配置结构体
void signer_config_free(SignerConfig *config);
证书管理
c
// 加载私钥
EVP_PKEY* load_private_key(const char *key_path);

// 加载证书
X509* load_certificate(const char *cert_path);

// 释放证书
void free_certificate(X509 *cert);

// 释放私钥
void free_private_key(EVP_PKEY *key);

// 从证书获取公钥
EVP_PKEY* get_public_key_from_cert(X509 *cert);
文件签名
c
// 处理目录中的所有文件
int process_directory(SignerConfig *config, EVP_PKEY *key, X509 *cert);

// 签名单个文件
int sign_file(const char *filepath, const char *output_dir, 
              EVP_PKEY *private_key, X509 *cert);
签名验证
c
// 验证文件签名
int verify_file_signature(const char *cert_path, 
                         const char *sig_file_path,
                         const char *original_file_path);

// 检查文件是否已签名
int is_file_signed(const char *filepath);
文件工具函数
c
// 检查文件是否存在
int file_exists(const char *path);

// 检查目录是否存在
int directory_exists(const char *path);

// 创建目录（包括父目录）
int create_directory(const char *path);

// 获取目录中的文件列表
FileList* get_files_in_directory(const char *directory, 
                                const char *extension_filter);

// 释放文件列表
void free_file_list(FileList *list);
加密工具函数
c
// 计算文件哈希
int calculate_file_hash(const char *filepath, 
                       unsigned char *hash, 
                       size_t *hash_len,
                       const EVP_MD *md);

// 计算数据哈希
int calculate_data_hash(const unsigned char *data, 
                       size_t data_len,
                       unsigned char *hash, 
                       size_t *hash_len,
                       const EVP_MD *md);

// 签名数据
int sign_data(EVP_PKEY *private_key,
              const unsigned char *data,
              size_t data_len,
              unsigned char **signature,
              size_t *sig_len,
              const EVP_MD *md);

// 验证签名
int verify_signature(EVP_PKEY *public_key,
                    const unsigned char *data,
                    size_t data_len,
                    const unsigned char *signature,
                    size_t sig_len,
                    const EVP_MD *md);
使用示例
示例 1：批量签名
c
#include "signer.h"
#include "crypto_utils.h"

int main() {
    // 初始化
    crypto_init();
    
    // 创建配置
    SignerConfig *config = signer_config_create();
    config->cert_path = "ca_cert.pem";
    config->key_path = "ca_key.pem";
    config->input_dir = "./documents";
    config->output_dir = "./signed";
    config->thread_count = 4;
    
    // 加载证书和密钥
    X509 *cert = load_certificate(config->cert_path);
    EVP_PKEY *key = load_private_key(config->key_path);
    
    // 处理目录
    int count = process_directory(config, key, cert);
    printf("已签名 %d 个文件\n", count);
    
    // 清理
    free_certificate(cert);
    free_private_key(key);
    signer_config_free(config);
    crypto_cleanup();
    
    return 0;
}
示例 2：验证签名
c
#include "verifier.h"

int main() {
    int result = verify_file_signature(
        "ca_cert.pem",
        "document.pdf.sig",
        "document.pdf"
    );
    
    if (result) {
        printf("签名验证成功\n");
    } else {
        printf("签名验证失败\n");
    }
    
    return 0;
}
示例 3：批量验证
c
#include "verifier.h"

int main() {
    BatchVerifyResult *result = batch_verify_directory(
        "ca_cert.pem",
        "./signed_documents"
    );
    
    if (result) {
        print_verify_result(result);
        batch_verify_result_free(result);
    }
    
    return 0;
}
错误处理
所有函数返回 0 表示失败，非 0 表示成功。对于指针返回类型，NULL 表示失败。

使用 OpenSSL 错误处理：

c
unsigned long err = ERR_get_error();
if (err != 0) {
    fprintf(stderr, "OpenSSL错误: %s\n", ERR_error_string(err, NULL));
}
线程安全性
大多数函数都是线程安全的，除了以下需要注意：

crypto_init() 和 crypto_cleanup() 应在主线程调用

OpenSSL 错误队列不是线程安全的