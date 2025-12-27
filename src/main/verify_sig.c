#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "verifier.h"
#include "crypto_utils.h"
#include "file_utils.h"

// 打印用法信息
void print_usage(const char* program_name) {
    printf("签名验证工具\n");
    printf("用法: %s <证书文件> <签名文件> <原始文件>\n", program_name);
    printf("  或: %s --batch <证书文件> <目录>\n\n", program_name);
    printf("选项:\n");
    printf("  --batch             批量验证目录中的所有签名文件\n");
    printf("  --report <文件>     生成验证报告文件\n");
    printf("  -h, --help         显示此帮助信息\n\n");
    printf("示例:\n");
    printf("  %s ca_cert.pem document.pdf.sig document.pdf\n", program_name);
    printf("  %s --batch ca_cert.pem ./signed_documents\n", program_name);
    printf("  %s --batch ca_cert.pem ./signed --report verification.txt\n", program_name);
}

// 单个文件验证
int verify_single_file(const char* cert_path,
    const char* sig_file,
    const char* original_file,
    int verbose) {
    if (!file_exists(cert_path)) {
        fprintf(stderr, "错误: 证书文件不存在: %s\n", cert_path);
        return 0;
    }

    if (!file_exists(sig_file)) {
        fprintf(stderr, "错误: 签名文件不存在: %s\n", sig_file);
        return 0;
    }

    if (!file_exists(original_file)) {
        fprintf(stderr, "错误: 原始文件不存在: %s\n", original_file);
        return 0;
    }

    char* error_msg = NULL;
    int result = verify_signature_file(cert_path, sig_file, original_file, &error_msg);

    if (verbose) {
        if (result) {
            printf("✓ 签名验证成功: %s\n", original_file);
        }
        else {
            printf("✗ 签名验证失败: %s\n", original_file);
            if (error_msg) {
                printf("  错误信息: %s\n", error_msg);
            }
        }
    }

    if (error_msg) {
        free(error_msg);
    }

    return result;
}

// 批量验证
int verify_batch(const char* cert_path,
    const char* directory,
    const char* report_file,
    int verbose) {
    if (!directory_exists(directory)) {
        fprintf(stderr, "错误: 目录不存在: %s\n", directory);
        return 0;
    }

    printf("开始批量验证目录: %s\n", directory);

    BatchVerifyResult* result = batch_verify_directory(cert_path, directory);
    if (!result) {
        fprintf(stderr, "错误: 批量验证失败\n");
        return 0;
    }

    // 打印结果
    print_verify_result(result);

    // 保存报告
    if (report_file) {
        if (save_verify_report(result, report_file)) {
            printf("验证报告已保存到: %s\n", report_file);
        }
        else {
            fprintf(stderr, "警告: 无法保存验证报告\n");
        }
    }

    // 清理
    batch_verify_result_free(result);

    return 1;
}

// 主函数
int main(int argc, char* argv[]) {
    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    // 初始化 OpenSSL
    if (!crypto_init()) {
        fprintf(stderr, "错误: OpenSSL 初始化失败\n");
        return 1;
    }

    int result = 0;

    if (strcmp(argv[1], "--batch") == 0) {
        // 批量验证模式
        if (argc < 4) {
            fprintf(stderr, "错误: 批量验证需要证书文件和目录参数\n");
            print_usage(argv[0]);
            crypto_cleanup();
            return 1;
        }

        const char* cert_path = argv[2];
        const char* directory = argv[3];
        const char* report_file = NULL;

        // 检查是否有报告文件参数
        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "--report") == 0 && i + 1 < argc) {
                report_file = argv[i + 1];
                break;
            }
        }

        result = verify_batch(cert_path, directory, report_file, 1);

    }
    else {
        // 单个文件验证模式
        if (argc < 4) {
            fprintf(stderr, "错误: 需要证书文件、签名文件和原始文件参数\n");
            print_usage(argv[0]);
            crypto_cleanup();
            return 1;
        }

        const char* cert_path = argv[1];
        const char* sig_file = argv[2];
        const char* original_file = argv[3];

        result = verify_single_file(cert_path, sig_file, original_file, 1);

        // 设置正确的退出码
        result = result ? 0 : 1;
    }

    crypto_cleanup();
    return result;
}