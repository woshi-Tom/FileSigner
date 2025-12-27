#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include "signer.h"
#include "file_utils.h"
#include "crypto_utils.h"

// 全局变量，用于信号处理
static volatile sig_atomic_t keep_running = 1;

// 信号处理函数
void signal_handler(int signum) {
    keep_running = 0;
    fprintf(stderr, "\n接收到终止信号，正在退出...\n");
}

// 打印用法信息
void print_usage(const char* program_name) {
    printf("FileSigner - 批量文件签名工具\n");
    printf("版本: 1.0.0\n\n");
    printf("用法: %s [选项]\n\n", program_name);
    printf("选项:\n");
    printf("  -c, --cert <file>        CA 证书文件路径 (必需)\n");
    printf("  -k, --key <file>         CA 私钥文件路径 (必需)\n");
    printf("  -i, --input <dir>        输入目录路径 (默认: 当前目录)\n");
    printf("  -o, --output <dir>       输出目录路径 (可选)\n");
    printf("  -f, --force              强制重新签名已签名的文件\n");
    printf("  -t, --threads <num>      使用的线程数 (默认: 1)\n");
    printf("  -v, --verbose            详细输出模式\n");
    printf("  --verify-only            仅验证，不进行签名\n");
    printf("  --version                显示版本信息\n");
    printf("  -h, --help               显示此帮助信息\n\n");
    printf("示例:\n");
    printf("  %s -c ca_cert.pem -k ca_key.pem -i ./documents\n", program_name);
    printf("  %s -c ca_cert.pem -k ca_key.pem -i ./docs -o ./signed -t 4\n", program_name);
    printf("  %s -c ca_cert.pem -k ca_key.pem -i ./signed --verify-only\n", program_name);
}

// 打印版本信息
void print_version(void) {
    printf("FileSigner 版本 1.0.0\n");
    printf("编译时间: %s %s\n", __DATE__, __TIME__);
    printf("支持平台: Windows/Linux/macOS\n");
    printf("使用 OpenSSL 库\n");
}

// 解析命令行参数
SignerConfig* parse_arguments(int argc, char* argv[]) {
    SignerConfig* config = signer_config_create();
    if (!config) {
        return NULL;
    }

    // 默认值
    config->input_dir = strdup(".");
    config->thread_count = 1;
    config->verbose = 0;
    config->force_resign = 0;
    config->verify_only = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cert") == 0) {
            if (i + 1 < argc) {
                config->cert_path = strdup(argv[++i]);
            }
            else {
                fprintf(stderr, "错误: -c 选项需要证书文件路径\n");
                signer_config_free(config);
                return NULL;
            }
        }
        else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) {
            if (i + 1 < argc) {
                config->key_path = strdup(argv[++i]);
            }
            else {
                fprintf(stderr, "错误: -k 选项需要私钥文件路径\n");
                signer_config_free(config);
                return NULL;
            }
        }
        else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--input") == 0) {
            if (i + 1 < argc) {
                free(config->input_dir);
                config->input_dir = strdup(argv[++i]);
            }
            else {
                fprintf(stderr, "错误: -i 选项需要输入目录路径\n");
                signer_config_free(config);
                return NULL;
            }
        }
        else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) {
                config->output_dir = strdup(argv[++i]);
            }
            else {
                fprintf(stderr, "错误: -o 选项需要输出目录路径\n");
                signer_config_free(config);
                return NULL;
            }
        }
        else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--force") == 0) {
            config->force_resign = 1;
        }
        else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--threads") == 0) {
            if (i + 1 < argc) {
                config->thread_count = atoi(argv[++i]);
                if (config->thread_count < 1) {
                    config->thread_count = 1;
                }
            }
            else {
                fprintf(stderr, "错误: -t 选项需要线程数\n");
                signer_config_free(config);
                return NULL;
            }
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            config->verbose = 1;
        }
        else if (strcmp(argv[i], "--verify-only") == 0) {
            config->verify_only = 1;
        }
        else if (strcmp(argv[i], "--version") == 0) {
            print_version();
            signer_config_free(config);
            exit(0);
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            signer_config_free(config);
            exit(0);
        }
        else {
            fprintf(stderr, "错误: 未知选项 '%s'\n", argv[i]);
            print_usage(argv[0]);
            signer_config_free(config);
            return NULL;
        }
    }

    // 验证必需参数
    if (!config->cert_path || !config->key_path) {
        fprintf(stderr, "错误: 必须指定证书和私钥文件路径\n");
        print_usage(argv[0]);
        signer_config_free(config);
        return NULL;
    }

    return config;
}

// 验证配置文件
int validate_config(SignerConfig* config) {
    if (!config) {
        return 0;
    }

    // 检查证书文件
    if (!file_exists(config->cert_path)) {
        fprintf(stderr, "错误: 证书文件不存在: %s\n", config->cert_path);
        return 0;
    }

    // 检查私钥文件
    if (!file_exists(config->key_path)) {
        fprintf(stderr, "错误: 私钥文件不存在: %s\n", config->key_path);
        return 0;
    }

    // 检查输入目录
    if (!directory_exists(config->input_dir)) {
        fprintf(stderr, "错误: 输入目录不存在: %s\n", config->input_dir);
        return 0;
    }

    // 检查输出目录（如果指定）
    if (config->output_dir && !directory_exists(config->output_dir)) {
        // 尝试创建输出目录
        if (!create_directory(config->output_dir)) {
            fprintf(stderr, "错误: 无法创建输出目录: %s\n", config->output_dir);
            return 0;
        }
    }

    return 1;
}

// 主函数
int main(int argc, char* argv[]) {
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 解析命令行参数
    SignerConfig* config = parse_arguments(argc, argv);
    if (!config) {
        return 1;
    }

    // 验证配置
    if (!validate_config(config)) {
        signer_config_free(config);
        return 1;
    }

    // 初始化 OpenSSL
    if (!crypto_init()) {
        fprintf(stderr, "错误: OpenSSL 初始化失败\n");
        signer_config_free(config);
        return 1;
    }

    // 打印配置信息
    printf("FileSigner 开始运行...\n");
    printf("证书文件: %s\n", config->cert_path);
    printf("私钥文件: %s\n", config->key_path);
    printf("输入目录: %s\n", config->input_dir);
    if (config->output_dir) {
        printf("输出目录: %s\n", config->output_dir);
    }
    printf("线程数: %d\n", config->thread_count);
    printf("模式: %s\n", config->verify_only ? "仅验证" : "签名");
    printf("强制模式: %s\n", config->force_resign ? "是" : "否");
    printf("\n");

    // 加载证书和私钥
    X509* cert = load_certificate(config->cert_path);
    EVP_PKEY* private_key = load_private_key(config->key_path);

    if (!cert || !private_key) {
        fprintf(stderr, "错误: 无法加载证书或私钥\n");
        if (cert) free_certificate(cert);
        if (private_key) free_private_key(private_key);
        signer_config_free(config);
        crypto_cleanup();
        return 1;
    }

    // 记录开始时间
    time_t start_time = time(NULL);

    // 处理目录
    int result = 0;
    if (config->verify_only) {
        // 验证模式
        printf("开始验证签名...\n");
        // TODO: 实现批量验证功能
        printf("验证模式暂未实现\n");
    }
    else {
        // 签名模式
        printf("开始批量签名...\n");
        result = process_directory(config, private_key, cert);
    }

    // 计算运行时间
    time_t end_time = time(NULL);
    double elapsed_time = difftime(end_time, start_time);

    // 打印结果
    printf("\n");
    printf("处理完成！\n");
    if (!config->verify_only) {
        printf("已处理文件数: %d\n", result);
    }
    printf("运行时间: %.2f 秒\n", elapsed_time);

    // 清理资源
    free_certificate(cert);
    free_private_key(private_key);
    signer_config_free(config);
    crypto_cleanup();

    return 0;
}