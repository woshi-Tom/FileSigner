#ifndef VERIFIER_H
#define VERIFIER_H

// 验证结果结构体
typedef struct {
    char* filename;       // 文件名
    int is_valid;         // 是否有效
    char* error_msg;      // 错误信息
    time_t verify_time;   // 验证时间
} VerifyResult;

// 批量验证结果
typedef struct {
    int total_files;      // 总文件数
    int valid_signatures; // 有效签名数
    int invalid_signatures; // 无效签名数
    VerifyResult* results; // 验证结果数组
    size_t results_count;  // 结果数量
} BatchVerifyResult;

// 验证函数
int verify_signature_file(const char* cert_path,
    const char* sig_file_path,
    const char* original_file_path,
    char** error_msg);

// 批量验证
BatchVerifyResult* batch_verify_directory(const char* cert_path,
    const char* directory);
void batch_verify_result_free(BatchVerifyResult* result);

// 结果输出
void print_verify_result(const BatchVerifyResult* result);
int save_verify_report(const BatchVerifyResult* result,
    const char* report_path);

#endif // VERIFIER_H