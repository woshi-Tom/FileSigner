#ifndef SIGNER_H
#define SIGNER_H

#include <openssl/evp.h>
#include <openssl/x509.h>

// 配置结构体
typedef struct {
    char* cert_path;      // CA 证书路径
    char* key_path;       // 私钥路径
    char* input_dir;      // 输入目录
    char* output_dir;     // 输出目录
    int force_resign;     // 强制重新签名
    int thread_count;     // 线程数
    int verbose;          // 详细输出
    int verify_only;      // 仅验证模式
} SignerConfig;

// 文件信息结构体
typedef struct {
    char* filepath;       // 文件路径
    char* filename;       // 文件名
    size_t file_size;     // 文件大小
    int is_signed;        // 是否已签名
} FileInfo;

// 初始化函数
int signer_init(void);
void signer_cleanup(void);

// 配置函数
SignerConfig* signer_config_create(void);
void signer_config_free(SignerConfig* config);

// 证书加载
EVP_PKEY* load_private_key(const char* key_path);
X509* load_certificate(const char* cert_path);
void free_certificate(X509* cert);
void free_private_key(EVP_PKEY* key);

// 文件处理
int process_directory(SignerConfig* config, EVP_PKEY* key, X509* cert);
int sign_file(const char* filepath, const char* output_dir,
    EVP_PKEY* private_key, X509* cert);
int verify_file_signature(const char* cert_path,
    const char* sig_file_path,
    const char* original_file_path);

// 工具函数
int is_file_signed(const char* filepath);
char* get_output_path(const char* input_path, const char* output_dir);
int ensure_directory_exists(const char* path);

#endif // SIGNER_H