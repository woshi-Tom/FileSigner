#include "cert_gen.h"
#include "file_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

/* Helper: add an X509 extension */
static int add_ext(X509 *cert, int nid, const char *value)
{
    X509V3_CTX ctx;
    X509_EXTENSION *ex;

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
    if (!ex)
        return 0;

    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}

/* Helper: add extension signed by issuer */
static int add_ext_issuer(X509 *cert, X509 *issuer, int nid, const char *value)
{
    X509V3_CTX ctx;
    X509_EXTENSION *ex;

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);

    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
    if (!ex)
        return 0;

    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}

/* Generate RSA key pair */
static EVP_PKEY* generate_rsa_key(int bits)
{
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) return NULL;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) { EVP_PKEY_free(pkey); return NULL; }

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Write PEM private key to file */
static int write_key_pem(const char *path, EVP_PKEY *key, const char *password)
{
    FILE *fp = fopen_utf8(path, "wb");
    if (!fp) return 0;

    int ret;
    if (password && password[0]) {
        ret = PEM_write_PrivateKey(fp, key, EVP_aes_256_cbc(),
                                   (unsigned char *)password,
                                   (int)strlen(password), NULL, NULL);
    } else {
        ret = PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
    }

    fclose(fp);
    return ret;
}

/* Write PEM certificate to file */
static int write_cert_pem(const char *path, X509 *cert)
{
    FILE *fp = fopen_utf8(path, "wb");
    if (!fp) return 0;

    int ret = PEM_write_X509(fp, cert);
    fclose(fp);
    return ret;
}

/* Create the Root CA certificate (self-signed) */
static X509* create_ca_cert(EVP_PKEY *pkey)
{
    X509 *cert = X509_new();
    if (!cert) return NULL;

    /* Version 3 (0-indexed = 2) */
    X509_set_version(cert, 2);

    /* Serial number */
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    /* Validity */
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), (long)CERT_CA_DEFAULT_DAYS * 86400);

    /* Public key */
    X509_set_pubkey(cert, pkey);

    /* Subject name */
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                (unsigned char *)CERT_CA_CN, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                (unsigned char *)"FileSigner", -1, -1, 0);

    /* Issuer = Subject (self-signed) */
    X509_set_issuer_name(cert, name);

    /* Extensions */
    add_ext(cert, NID_basic_constraints, "critical,CA:TRUE");
    add_ext(cert, NID_key_usage, "critical,keyCertSign,cRLSign");
    add_ext(cert, NID_subject_key_identifier, "hash");

    /* Sign with own key */
    if (!X509_sign(cert, pkey, EVP_sha256())) {
        X509_free(cert);
        return NULL;
    }

    return cert;
}

/* Create code signing certificate signed by the CA */
static X509* create_signer_cert(EVP_PKEY *signer_key, X509 *ca_cert,
                                 EVP_PKEY *ca_key, int validity_days,
                                 const char *signer_cn, const char *signer_email)
{
    X509 *cert = X509_new();
    if (!cert) return NULL;

    X509_set_version(cert, 2);

    /* Serial number (random) */
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    BIGNUM *bn = BN_new();
    BN_rand(bn, 64, 0, 0);
    BN_to_ASN1_INTEGER(bn, serial);
    BN_free(bn);

    /* Validity */
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    int days = validity_days > 0 ? validity_days : CERT_SIGNER_DEFAULT_DAYS;
    X509_gmtime_adj(X509_get_notAfter(cert), (long)days * 86400);

    /* Public key */
    X509_set_pubkey(cert, signer_key);

    /* Subject name */
    const char *cn = (signer_cn && signer_cn[0]) ? signer_cn : CERT_SIGNER_CN;
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                (unsigned char *)cn, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                (unsigned char *)"FileSigner", -1, -1, 0);

    /* Issuer = CA subject */
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    /* Extensions */
    add_ext_issuer(cert, ca_cert, NID_basic_constraints, "CA:FALSE");
    add_ext_issuer(cert, ca_cert, NID_key_usage, "critical,digitalSignature");
    add_ext_issuer(cert, ca_cert, NID_ext_key_usage, "codeSigning");
    add_ext_issuer(cert, ca_cert, NID_subject_key_identifier, "hash");
    add_ext_issuer(cert, ca_cert, NID_authority_key_identifier, "keyid:always");

    /* SubjectAlternativeName with email (if provided) */
    if (signer_email && signer_email[0]) {
        char san_buf[512];
        snprintf(san_buf, sizeof(san_buf), "email:%s", signer_email);
        add_ext_issuer(cert, ca_cert, NID_subject_alt_name, san_buf);
    }

    /* Sign with CA key */
    if (!X509_sign(cert, ca_key, EVP_sha256())) {
        X509_free(cert);
        return NULL;
    }

    return cert;
}

/* Export PFX (PKCS#12) containing signer cert + key + CA chain */
static int write_pfx(const char *path, EVP_PKEY *key, X509 *cert,
                      X509 *ca_cert, const char *password)
{
    PKCS12 *p12;
    FILE *fp;
    int ret;
    STACK_OF(X509) *extra = NULL;

    if (ca_cert) {
        extra = sk_X509_new_null();
        if (extra) sk_X509_push(extra, ca_cert);
    }

    p12 = PKCS12_create(
        (char *)password,           /* export password */
        CERT_SIGNER_CN,             /* friendly name */
        key,                        /* private key */
        cert,                       /* signer certificate */
        extra,                      /* extra certs (CA chain) */
        0, 0, 0, 0, 0
    );

    if (extra) sk_X509_free(extra);
    if (!p12) return 0;

    fp = fopen_utf8(path, "wb");
    if (!fp) { PKCS12_free(p12); return 0; }

    ret = i2d_PKCS12_fp(fp, p12);
    fclose(fp);
    PKCS12_free(p12);

    return ret > 0;
}

/* ------------------------------------------------------------------ */

int cert_generate(const char *output_dir,
                  const char *ca_password,
                  const char *signer_password,
                  int validity_days,
                  const char *signer_cn,
                  const char *signer_email)
{
    EVP_PKEY *ca_key = NULL, *signer_key = NULL;
    X509 *ca_cert = NULL, *signer_cert = NULL;
    int ret = 0;
    char path[1024];

    /* Generate CA key pair (4096-bit RSA) */
    ca_key = generate_rsa_key(4096);
    if (!ca_key) {
        fprintf(stderr, "Failed to generate CA key pair\n");
        goto cleanup;
    }

    /* Generate signer key pair (2048-bit RSA) */
    signer_key = generate_rsa_key(2048);
    if (!signer_key) {
        fprintf(stderr, "Failed to generate signer key pair\n");
        goto cleanup;
    }

    /* Create CA certificate */
    ca_cert = create_ca_cert(ca_key);
    if (!ca_cert) {
        fprintf(stderr, "Failed to create CA certificate\n");
        goto cleanup;
    }

    /* Create signer certificate */
    signer_cert = create_signer_cert(signer_key, ca_cert, ca_key, validity_days,
                                      signer_cn, signer_email);
    if (!signer_cert) {
        fprintf(stderr, "Failed to create signer certificate\n");
        goto cleanup;
    }

    /* Write files */
    snprintf(path, sizeof(path), "%s/FileSigner_RootCA.cer", output_dir);
    if (!write_cert_pem(path, ca_cert)) {
        fprintf(stderr, "Failed to write CA certificate\n"); goto cleanup;
    }
    printf("  Created: %s\n", path);

    snprintf(path, sizeof(path), "%s/FileSigner_RootCA.key", output_dir);
    if (!write_key_pem(path, ca_key, ca_password)) {
        fprintf(stderr, "Failed to write CA key\n"); goto cleanup;
    }
    printf("  Created: %s\n", path);

    snprintf(path, sizeof(path), "%s/FileSigner_Signer.cer", output_dir);
    if (!write_cert_pem(path, signer_cert)) {
        fprintf(stderr, "Failed to write signer certificate\n"); goto cleanup;
    }
    printf("  Created: %s\n", path);

    snprintf(path, sizeof(path), "%s/FileSigner_Signer.key", output_dir);
    if (!write_key_pem(path, signer_key, NULL)) {
        fprintf(stderr, "Failed to write signer key\n"); goto cleanup;
    }
    printf("  Created: %s\n", path);

    snprintf(path, sizeof(path), "%s/FileSigner_Signer.pfx", output_dir);
    {
        const char *friendly = (signer_cn && signer_cn[0]) ? signer_cn : CERT_SIGNER_CN;
        PKCS12 *p12_tmp = NULL;
        /* write_pfx uses CERT_SIGNER_CN as friendly name; override via re-implementation */
        STACK_OF(X509) *extra = sk_X509_new_null();
        if (extra) sk_X509_push(extra, ca_cert);
        p12_tmp = PKCS12_create((char *)signer_password, friendly,
                                signer_key, signer_cert, extra, 0, 0, 0, 0, 0);
        if (extra) sk_X509_free(extra);
        if (!p12_tmp) {
            fprintf(stderr, "Failed to write PFX file\n"); goto cleanup;
        }
        FILE *pfx_fp = fopen_utf8(path, "wb");
        if (!pfx_fp) { PKCS12_free(p12_tmp); goto cleanup; }
        if (!i2d_PKCS12_fp(pfx_fp, p12_tmp)) {
            fclose(pfx_fp);
            PKCS12_free(p12_tmp);
            fprintf(stderr, "Failed to write PFX file\n");
            goto cleanup;
        }
        fclose(pfx_fp);
        PKCS12_free(p12_tmp);
    }
    printf("  Created: %s\n", path);

    ret = 1;

cleanup:
    if (ca_key)      EVP_PKEY_free(ca_key);
    if (signer_key)  EVP_PKEY_free(signer_key);
    if (ca_cert)     X509_free(ca_cert);
    if (signer_cert) X509_free(signer_cert);

    return ret;
}
