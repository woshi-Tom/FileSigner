#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cert_gen.h"
#include "authenticode.h"
#include "batch_signer.h"
#include "file_utils.h"

#define VERSION "4.0.2"

static void print_usage(const char *prog)
{
    printf("FileSigner v%s - Authenticode PE 签名工具\n\n", VERSION);
    printf("用法:\n");
    printf("  %s sign <文件|目录> --pfx <pfx> [选项]\n", prog);
    printf("  %s gen-cert [选项]\n", prog);
    printf("  %s verify <文件> [--ca <证书>]\n\n", prog);
    printf("证书生成:\n");
    printf("  --out-dir <目录>          输出目录 (默认: ./certs)\n");
    printf("  --ca-password <密码>       CA 密钥密码 (默认: 无)\n");
    printf("  --signer-password <密码>   PFX 密码 (默认: FileSigner)\n");
    printf("  --validity-days <天数>     签名证书有效天数 (默认: 90)\n");
    printf("  --signer-cn <名称>        签名者姓名 (CN, 默认: FileSigner Code Signing)\n");
    printf("  --signer-email <邮箱>      签名者邮箱 (SAN 扩展, 可选)\n\n");
    printf("签名:\n");
    printf("  --pfx <文件>               PFX/P12 证书文件\n");
    printf("  --password <密码>          PFX 密码\n");
    printf("  --timestamp <URL>          时间戳服务器 URL\n");
    printf("  --output <目录>            输出目录 (默认: 覆盖原文件)\n");
    printf("  --force                    强制重新签名已签名的文件\n");
    printf("  --recursive                扫描子目录\n\n");
    printf("验证:\n");
    printf("  --ca <文件>                CA 证书 (用于证书链验证)\n\n");
    printf("示例:\n");
    printf("  %s gen-cert --out-dir ./mycerts\n", prog);
    printf("  %s sign ./myapp.exe --pfx ./mycerts/FileSigner_Signer.pfx\n", prog);
    printf("  %s sign ./build --pfx cert.pfx --recursive --timestamp http://timestamp.digicert.com\n", prog);
    printf("  %s verify signed.exe --ca ./mycerts/FileSigner_RootCA.cer\n", prog);
}

int cli_main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    /* gen-cert */
    if (strcmp(argv[1], "gen-cert") == 0) {
        const char *out_dir = "./certs";
        const char *ca_pw = NULL;
        const char *signer_pw = "FileSigner";
        const char *signer_cn = NULL;
        const char *signer_email = NULL;
        int validity = CERT_SIGNER_DEFAULT_DAYS;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--out-dir") == 0 && i + 1 < argc)
                out_dir = argv[++i];
            else if (strcmp(argv[i], "--ca-password") == 0 && i + 1 < argc)
                ca_pw = argv[++i];
            else if (strcmp(argv[i], "--signer-password") == 0 && i + 1 < argc)
                signer_pw = argv[++i];
            else if (strcmp(argv[i], "--validity-days") == 0 && i + 1 < argc) {
                char *endp;
                long v = strtol(argv[++i], &endp, 10);
                if (*endp != '\0' || v < 1 || v > 3650) {
                    fprintf(stderr, "错误: --validity-days 必须是 1-3650 之间的整数\n");
                    return 1;
                }
                validity = (int)v;
            }
            else if (strcmp(argv[i], "--signer-cn") == 0 && i + 1 < argc)
                signer_cn = argv[++i];
            else if (strcmp(argv[i], "--signer-email") == 0 && i + 1 < argc)
                signer_email = argv[++i];
        }

        if (!directory_exists(out_dir)) {
            if (!create_directory(out_dir)) {
                fprintf(stderr, "错误: 无法创建输出目录: %s\n", out_dir);
                return 1;
            }
        }

        printf("正在生成证书...\n");
        printf("  CA CN: %s\n", CERT_CA_CN);
        printf("  签名者 CN: %s (有效期: %d 天)\n",
               signer_cn ? signer_cn : CERT_SIGNER_CN, validity);
        if (signer_email) printf("  签名者邮箱: %s\n", signer_email);
        printf("  输出目录: %s\n\n", out_dir);

        if (cert_generate(out_dir, ca_pw, signer_pw, validity, signer_cn, signer_email)) {
            printf("\n证书生成成功!\n");
            printf("\n下一步:\n");
            printf("  1. 将 %s/FileSigner_RootCA.cer 导入 Windows\n", out_dir);
            printf("     \"受信任的根证书颁发机构\" 存储\n");
            printf("  2. 使用 FileSigner_Signer.pfx 对你的可执行文件签名\n");
        } else {
            fprintf(stderr, "\n证书生成失败!\n");
            return 1;
        }

        return 0;
    }

    /* sign */
    if (strcmp(argv[1], "sign") == 0) {
        if (argc < 3) {
            fprintf(stderr, "错误: sign 需要指定文件或目录\n");
            print_usage(argv[0]);
            return 1;
        }

        const char *target = argv[2];
        const char *pfx_path = NULL;
        const char *pfx_pw = NULL;
        const char *ts_url = NULL;
        const char *output_dir = NULL;
        int force = 0;
        int recursive = 0;

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--pfx") == 0 && i + 1 < argc)
                pfx_path = argv[++i];
            else if (strcmp(argv[i], "--password") == 0 && i + 1 < argc)
                pfx_pw = argv[++i];
            else if (strcmp(argv[i], "--timestamp") == 0 && i + 1 < argc)
                ts_url = argv[++i];
            else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc)
                output_dir = argv[++i];
            else if (strcmp(argv[i], "--force") == 0)
                force = 1;
            else if (strcmp(argv[i], "--recursive") == 0)
                recursive = 1;
        }

        if (!pfx_path) {
            fprintf(stderr, "错误: 签名需要 --pfx 参数\n");
            return 1;
        }

        int ret;
        if (directory_exists(target)) {
            if (output_dir && !directory_exists(output_dir)) {
                if (!create_directory(output_dir)) {
                    fprintf(stderr, "错误: 无法创建输出目录: %s\n", output_dir);
                    return 1;
                }
            }
            int count = batch_sign(target, pfx_path, pfx_pw, ts_url,
                                    output_dir, force, recursive, NULL, NULL);
            printf("\n已签名 %d 个文件\n", count);
            ret = (count > 0) ? 0 : 1;
        } else if (file_exists(target)) {
            const char *out = target;
            char outbuf[4096];
            if (output_dir) {
                const char *slash = strrchr(target, '/');
                if (!slash) slash = strrchr(target, '\\');
                const char *fname = slash ? slash + 1 : target;
                snprintf(outbuf, sizeof(outbuf), "%s/%s", output_dir, fname);
                out = outbuf;
            }
            ret = authenticode_sign(target, pfx_path, pfx_pw, ts_url, out, NULL, NULL) ? 0 : 1;
        } else {
            fprintf(stderr, "错误: 目标不存在: %s\n", target);
            ret = 1;
        }

        return ret;
    }

    /* verify */
    if (strcmp(argv[1], "verify") == 0) {
        if (argc < 3) {
            fprintf(stderr, "错误: verify 需要指定文件\n");
            print_usage(argv[0]);
            return 1;
        }

        const char *target = argv[2];
        const char *ca_path = NULL;

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc)
                ca_path = argv[++i];
        }

        return authenticode_verify(target, ca_path) ? 0 : 1;
    }

    /* help */
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    fprintf(stderr, "未知命令: %s\n", argv[1]);
    print_usage(argv[0]);
    return 1;
}
