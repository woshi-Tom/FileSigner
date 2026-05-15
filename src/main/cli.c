#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cert_gen.h"
#include "authenticode.h"
#include "batch_signer.h"
#include "file_utils.h"

#define VERSION "2.0.0"

static void print_usage(const char *prog)
{
    printf("FileSigner v%s - Authenticode PE Signing Tool\n\n", VERSION);
    printf("Usage:\n");
    printf("  %s --generate-cert [options]\n", prog);
    printf("  %s --sign <file|dir> --pfx <pfx> [options]\n", prog);
    printf("  %s --verify <file> [--ca <cert>]\n", prog);
    printf("  %s --gui        (use filesigner_gui.exe for GUI)\n\n", prog);
    printf("Certificate Generation:\n");
    printf("  --out-dir <dir>          Output directory (default: ./certs)\n");
    printf("  --ca-password <pw>       CA key password (default: none)\n");
    printf("  --signer-password <pw>   PFX password (default: FileSigner)\n");
    printf("  --validity-days <n>      Signer cert validity in days (default: 90)\n\n");
    printf("Signing:\n");
    printf("  --pfx <file>             PFX/P12 certificate file\n");
    printf("  --password <pw>          PFX password\n");
    printf("  --timestamp <url>        Timestamp server URL\n");
    printf("  --output <dir>           Output directory (default: overwrite)\n");
    printf("  --force                  Re-sign already-signed files\n");
    printf("  --recursive              Scan subdirectories\n\n");
    printf("Verification:\n");
    printf("  --ca <file>              CA certificate for chain verification\n\n");
    printf("Examples:\n");
    printf("  %s --generate-cert --out-dir ./mycerts\n", prog);
    printf("  %s --sign ./myapp.exe --pfx ./mycerts/FileSigner_Signer.pfx\n", prog);
    printf("  %s --sign ./build --pfx cert.pfx --recursive --timestamp http://timestamp.digicert.com\n", prog);
    printf("  %s --verify signed.exe --ca ./mycerts/FileSigner_RootCA.cer\n", prog);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    /* --generate-cert */
    if (strcmp(argv[1], "--generate-cert") == 0) {
        const char *out_dir = "./certs";
        const char *ca_pw = NULL;
        const char *signer_pw = "FileSigner";
        int validity = CERT_SIGNER_DEFAULT_DAYS;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--out-dir") == 0 && i + 1 < argc)
                out_dir = argv[++i];
            else if (strcmp(argv[i], "--ca-password") == 0 && i + 1 < argc)
                ca_pw = argv[++i];
            else if (strcmp(argv[i], "--signer-password") == 0 && i + 1 < argc)
                signer_pw = argv[++i];
            else if (strcmp(argv[i], "--validity-days") == 0 && i + 1 < argc)
                validity = atoi(argv[++i]);
        }

        if (!directory_exists(out_dir)) {
            if (!create_directory(out_dir)) {
                fprintf(stderr, "Error: Cannot create output directory: %s\n", out_dir);
                return 1;
            }
        }

        printf("Generating certificates...\n");
        printf("  CA CN: %s\n", CERT_CA_CN);
        printf("  Signer CN: %s (validity: %d days)\n", CERT_SIGNER_CN, validity);
        printf("  Output: %s\n\n", out_dir);

        if (cert_generate(out_dir, ca_pw, signer_pw, validity)) {
            printf("\nCertificate generation successful!\n");
            printf("\nNext steps:\n");
            printf("  1. Import %s/FileSigner_RootCA.cer into Windows\n", out_dir);
            printf("     'Trusted Root Certification Authorities' store\n");
            printf("  2. Use FileSigner_Signer.pfx to sign your executables\n");
        } else {
            fprintf(stderr, "\nCertificate generation failed!\n");
            return 1;
        }

        return 0;
    }

    /* --sign */
    if (strcmp(argv[1], "--sign") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: --sign requires a file or directory argument\n");
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
            fprintf(stderr, "Error: --pfx is required for signing\n");
            return 1;
        }

        int ret;
        if (directory_exists(target)) {
            /* Batch sign */
            if (output_dir && !directory_exists(output_dir)) {
                create_directory(output_dir);
            }
            int count = batch_sign(target, pfx_path, pfx_pw, ts_url,
                                    output_dir, force, recursive, NULL, NULL);
            printf("\nSigned %d file(s)\n", count);
            ret = (count > 0) ? 0 : 1;
        } else if (file_exists(target)) {
            /* Single file sign */
            const char *out = target;
            char outbuf[4096];
            if (output_dir) {
                const char *slash = strrchr(target, '/');
                if (!slash) slash = strrchr(target, '\\');
                const char *fname = slash ? slash + 1 : target;
                snprintf(outbuf, sizeof(outbuf), "%s/%s", output_dir, fname);
                out = outbuf;
            }
            ret = authenticode_sign(target, pfx_path, pfx_pw, ts_url, out) ? 0 : 1;
        } else {
            fprintf(stderr, "Error: Target not found: %s\n", target);
            ret = 1;
        }

        return ret;
    }

    /* --verify */
    if (strcmp(argv[1], "--verify") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: --verify requires a file argument\n");
            print_usage(argv[0]);
            return 1;
        }

        const char *target = argv[2];
        const char *ca_path = NULL;

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc)
                ca_path = argv[++i];
        }

        int ret = authenticode_verify(target, ca_path) ? 0 : 1;

        return ret;
    }

    /* Unknown command */
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    print_usage(argv[0]);
    return 1;
}
