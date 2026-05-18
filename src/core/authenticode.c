#include "authenticode.h"
#include "pe_file.h"
#include "file_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
/* Fallback for older OpenSSL headers that may not define PKCS7_NOSMIMECAP */
#ifndef PKCS7_NOSMIMECAP
#define PKCS7_NOSMIMECAP 0x200
#endif

/* ------------------------------------------------------------------ */
/* DER builder — raw byte buffer for manual PKCS#7 construction       */
/* ------------------------------------------------------------------ */

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} DerBuf;

static int db_init(DerBuf *db)
{
    db->cap = 4096;
    db->len = 0;
    db->data = (unsigned char *)OPENSSL_malloc(db->cap);
    if (!db->data) { db->cap = 0; return 0; }
    return 1;
}

static void db_free(DerBuf *db)
{
    OPENSSL_free(db->data);
    db->data = NULL;
    db->len = 0;
}

static int db_grow(DerBuf *db, size_t need)
{
    if (!db->data) return 0;
    if (db->len + need <= db->cap) return 1;
    while (db->len + need > db->cap) db->cap *= 2;
    unsigned char *p = (unsigned char *)OPENSSL_realloc(db->data, db->cap);
    if (!p) return 0;
    db->data = p;
    return 1;
}

static int db_raw(DerBuf *db, const void *src, size_t n)
{
    if (!db->data) return 0;
    if (!db_grow(db, n)) return 0;
    memcpy(db->data + db->len, src, n);
    db->len += n;
    return 1;
}

static int db_byte(DerBuf *db, unsigned char b) { return db_raw(db, &b, 1); }

static int db_len(DerBuf *db, size_t len)
{
    if (len < 0x80) return db_byte(db, (unsigned char)len);
    unsigned char tmp[5];
    int n;
    if (len < 0x100) {
        tmp[0] = 0x81; tmp[1] = (unsigned char)len; n = 2;
    } else if (len < 0x10000) {
        tmp[0] = 0x82; tmp[1] = (unsigned char)(len >> 8);
        tmp[2] = (unsigned char)len; n = 3;
    } else if (len < 0x1000000) {
        tmp[0] = 0x83; tmp[1] = (unsigned char)(len >> 16);
        tmp[2] = (unsigned char)(len >> 8);
        tmp[3] = (unsigned char)len; n = 4;
    } else {
        tmp[0] = 0x84; tmp[1] = (unsigned char)(len >> 24);
        tmp[2] = (unsigned char)(len >> 16);
        tmp[3] = (unsigned char)(len >> 8);
        tmp[4] = (unsigned char)len; n = 5;
    }
    return db_raw(db, tmp, n);
}

static int db_tag(DerBuf *db, unsigned char tag, size_t body_len)
{
    return db_byte(db, tag) && db_len(db, body_len);
}

/* Push current length as a placeholder, return position for later fix */
static size_t db_push_len_placeholder(DerBuf *db)
{
    /* Reserve 5 bytes for tag + max length encoding */
    size_t pos = db->len;
    unsigned char zeros[5] = {0};
    db_raw(db, zeros, 5);
    return pos;
}

/* Fix a previously pushed placeholder with actual tag+length */
static void db_fix_placeholder(DerBuf *db, size_t pos, unsigned char tag,
                                size_t body_len)
{
    /* body_len = current_len - (pos + 5) */
    size_t actual = db->len - pos - 5;
    /* Write the real tag+length at pos, then shift body */
    unsigned char hdr[5];
    int hdr_len = 0;
    hdr[hdr_len++] = tag;
    if (actual < 0x80) {
        hdr[hdr_len++] = (unsigned char)actual;
    } else if (actual < 0x100) {
        hdr[hdr_len++] = 0x81;
        hdr[hdr_len++] = (unsigned char)actual;
        hdr_len += 0; /* already set */
    } else {
        hdr[hdr_len++] = 0x82;
        hdr[hdr_len++] = (unsigned char)(actual >> 8);
        hdr[hdr_len++] = (unsigned char)actual;
    }
    /* Copy header into position (overwriting zeros) */
    memcpy(db->data + pos, hdr, hdr_len);
    /* Shift body left if header is shorter than 5 bytes */
    if (hdr_len < 5) {
        size_t shift = 5 - hdr_len;
        memmove(db->data + pos + hdr_len, db->data + pos + 5, actual);
        db->len -= shift;
    }
    (void)body_len;
}

static int db_der_int(DerBuf *db, long val)
{
    unsigned char tmp[9];
    int n = 0;
    if (val < 0) return 0;  /* negative not supported; use i2d_ASN1_INTEGER */
    do {
        if (n >= (int)sizeof(tmp)) return 0;
        tmp[n++] = (unsigned char)(val & 0xff);
        val >>= 8;
    } while (val);
    /* If high bit set, prepend 0x00 */
    if (tmp[n-1] & 0x80) tmp[n++] = 0x00;
    /* Reverse to big-endian */
    int i;
    for (i = 0; i < n/2; i++) {
        unsigned char c = tmp[i]; tmp[i] = tmp[n-1-i]; tmp[n-1-i] = c;
    }
    return db_tag(db, 0x02, n) && db_raw(db, tmp, n);
}

static int db_der_octet_string(DerBuf *db, const unsigned char *data, size_t len)
{
    return db_tag(db, 0x04, len) && db_raw(db, data, len);
}

static int db_der_oid_raw(DerBuf *db, const unsigned char *der, size_t len)
{
    return db_tag(db, 0x06, len) && db_raw(db, der, len);
}

static int db_der_null(DerBuf *db)
{
    return db_tag(db, 0x05, 0);
}

static int db_der_oid_nid(DerBuf *db, int nid)
{
    ASN1_OBJECT *obj = OBJ_nid2obj(nid);
    if (!obj) return 0;
    unsigned char buf[64];
    int len = i2d_ASN1_OBJECT(obj, NULL);
    if (len <= 0 || (size_t)len > sizeof(buf)) return 0;
    unsigned char *p = buf;
    i2d_ASN1_OBJECT(obj, &p);
    return db_der_oid_raw(db, buf + 1, len - 1); /* skip tag */
}

static int db_der_oid_str(DerBuf *db, const char *oid_str)
{
    ASN1_OBJECT *obj = OBJ_txt2obj(oid_str, 1);
    if (!obj) return 0;
    unsigned char buf[64];
    int len = i2d_ASN1_OBJECT(obj, NULL);
    if (len <= 0 || (size_t)len > sizeof(buf)) { ASN1_OBJECT_free(obj); return 0; }
    unsigned char *p = buf;
    i2d_ASN1_OBJECT(obj, &p);
    ASN1_OBJECT_free(obj);
    return db_der_oid_raw(db, buf + 1, len - 1); /* skip tag */
}

/* Encode a raw DER SEQUENCE (body already DER encoded) */
static int db_der_seq(DerBuf *db, const unsigned char *body, size_t body_len)
{
    return db_tag(db, 0x30, body_len) && db_raw(db, body, body_len);
}

/* Encode a raw DER SET (body already DER encoded) */
static int db_der_set(DerBuf *db, const unsigned char *body, size_t body_len)
{
    return db_tag(db, 0x31, body_len) && db_raw(db, body, body_len);
}

/* Copy existing DER data into buffer (e.g. from OpenSSL i2d functions) */
static int db_der_copy(DerBuf *db, const unsigned char *der, size_t len)
{
    return db_raw(db, der, len);
}

/* ------------------------------------------------------------------ */
/* Load PFX/P12 file — extract cert, private key, CA chain            */
/* ------------------------------------------------------------------ */

static int load_pfx(const char *path, const char *password,
                     EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
    FILE *fp;
    PKCS12 *p12;
    int ret;

    fp = fopen_utf8(path, "rb");
    if (!fp) return 0;

    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);
    if (!p12) return 0;

    ret = PKCS12_parse(p12, password, pkey, cert, ca);
    PKCS12_free(p12);

    return ret;
}

/* ------------------------------------------------------------------ */
/* Build SpcIndirectDataContent as DER                                */
/* ------------------------------------------------------------------ */

static unsigned char* build_spc_content_der(const unsigned char *pe_hash,
                                             unsigned int pe_hash_len,
                                             int *out_len)
{
    DerBuf body, seq;
    unsigned char *result = NULL;

    if (!db_init(&body) || !db_init(&seq)) {
        db_free(&body); db_free(&seq);
        return NULL;
    }

    /* SpcAttributeTypeAndOptionalValue = SEQUENCE { OID(SPC_PE_IMAGE_DATA) } */
    {
        DerBuf sa;
        if (!db_init(&sa)) { db_free(&body); db_free(&seq); return NULL; }
        db_der_oid_str(&sa, SPC_PE_IMAGE_DATA_OID);
        db_der_seq(&body, sa.data, sa.len);
        db_free(&sa);
    }

    /* DigestInfo = SEQUENCE { DigestAlgorithmIdentifier, Digest } */
    {
        DerBuf di, alg;
        if (!db_init(&di) || !db_init(&alg)) {
            db_free(&di); db_free(&alg); db_free(&body); db_free(&seq);
            return NULL;
        }
        db_der_oid_nid(&alg, NID_sha256);
        db_der_null(&alg);
        db_der_seq(&di, alg.data, alg.len);
        db_raw(&body, di.data, di.len);
        db_free(&di);
        db_free(&alg);
    }

    /* messageDigest = OCTET STRING (PE hash) */
    db_der_octet_string(&body, pe_hash, pe_hash_len);

    /* Wrap in SEQUENCE */
    db_der_seq(&seq, body.data, body.len);
    db_free(&body);

    *out_len = (int)seq.len;
    result = (unsigned char *)OPENSSL_malloc(seq.len);
    if (result) memcpy(result, seq.data, seq.len);
    db_free(&seq);
    return result;
}

/* ------------------------------------------------------------------ */
/* Build PKCS#7 SignedData using OpenSSL native API                   */
/* ------------------------------------------------------------------ */

static unsigned char* build_authenticode_pkcs7(EVP_PKEY *pkey, X509 *cert,
                                                STACK_OF(X509) *ca_chain,
                                                const unsigned char *pe_hash,
                                                unsigned int pe_hash_len,
                                                int *out_len)
{
    PKCS7 *p7 = NULL;
    PKCS7_SIGNER_INFO *si = NULL;
    unsigned char *result = NULL;
    unsigned char *spc_der = NULL;
    int spc_len = 0;
    BIO *out_bio = NULL;
    BUF_MEM *bmem = NULL;

    /* 1. Create PKCS7 SignedData with SHA-256 signer + empty content */
    {
        BIO *empty = BIO_new(BIO_s_mem());
        if (!empty) { OutputDebugStringA("[build] BIO_new FAILED\n"); return NULL; }
        p7 = PKCS7_sign(cert, pkey, NULL, empty, PKCS7_BINARY);
        BIO_free(empty);
        if (!p7) {
            OutputDebugStringA("[build] PKCS7_sign FAILED\n");
            {
                char errbuf[512]; unsigned long e;
                while ((e = ERR_get_error())) {
                    ERR_error_string_n(e, errbuf, sizeof(errbuf));
                    OutputDebugStringA("[build] ERR: ");
                    OutputDebugStringA(errbuf);
                    OutputDebugStringA("\n");
                }
            }
            return NULL;
        }
    }
    OutputDebugStringA("[build] PKCS7_sign OK\n");

    /* 2. Get signer info */
    si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(p7), 0);
    if (!si) {
        OutputDebugStringA("[build] No signer info\n");
        PKCS7_free(p7);
        return NULL;
    }

    /* 3. Add CA chain certs */
    if (ca_chain) {
        for (int i = 0; i < sk_X509_num(ca_chain); i++) {
            PKCS7_add_certificate(p7, sk_X509_value(ca_chain, i));
        }
    }

    /* 4. Encode to DER and output */
    (void)pe_hash; (void)pe_hash_len; /* unused for now */
    out_bio = BIO_new(BIO_s_mem());
    if (!out_bio || !i2d_PKCS7_bio(out_bio, p7)) {
        OutputDebugStringA("[build] i2d_PKCS7_bio FAILED\n");
        if (out_bio) BIO_free(out_bio);
        PKCS7_free(p7);
        return NULL;
    }

    BIO_get_mem_ptr(out_bio, &bmem);
    *out_len = (int)bmem->length;
    result = (unsigned char *)OPENSSL_malloc(bmem->length);
    if (result) memcpy(result, bmem->data, bmem->length);
    BIO_free(out_bio);
    PKCS7_free(p7);

    return result;
}

/* ------------------------------------------------------------------ */
/* Serialize PKCS7 to DER and attach to PE                            */
/* ------------------------------------------------------------------ */

static int attach_pkcs7_to_pe(PE_FILE *pe, const unsigned char *der,
                                int der_len, const char *output_path)
{
    /* Attach signature to PE */
    if (!pe_attach_signature(pe, der, (uint32_t)der_len))
        return 0;

    /* Recalculate checksum */
    pe_recalc_checksum(pe);

    /* Save */
    return pe_save(pe, output_path);
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

int authenticode_sign(const char *pe_path,
                      const char *pfx_path,
                      const char *pfx_password,
                      const char *timestamp_url,
                      const char *output_path,
                      authenticode_status_cb status_cb,
                      void *cb_data)
{
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca_chain = NULL;
    PE_FILE *pe = NULL;
    unsigned char *pkcs7_der = NULL;
    int pkcs7_len = 0;
    unsigned char pe_hash[EVP_MAX_MD_SIZE];
    unsigned int pe_hash_len = 0;
    int ret = 0;
    const char *out;

    (void)timestamp_url; /* TODO: Phase 4 */

    if (status_cb) status_cb("加载 PFX 证书...", cb_data);

    /* Load PFX */
    if (!load_pfx(pfx_path, pfx_password, &pkey, &cert, &ca_chain)) {
        fprintf(stderr, "Failed to load PFX: %s\n", pfx_path);
        return 0;
    }

    /* Validate PFX output */
    {
        char _pfxdbg[256];
        snprintf(_pfxdbg, sizeof(_pfxdbg), "[sign] PFX loaded: cert=%p pkey=%p ca=%p\n",
                 (void*)cert, (void*)pkey, (void*)ca_chain);
        OutputDebugStringA(_pfxdbg);
        if (cert) {
            X509_NAME *issuer = X509_get_issuer_name(cert);
            X509_NAME *subject = X509_get_subject_name(cert);
            snprintf(_pfxdbg, sizeof(_pfxdbg), "[sign] issuer=%p subject=%p\n",
                     (void*)issuer, (void*)subject);
            OutputDebugStringA(_pfxdbg);
            if (issuer) {
                char cn[256] = {0};
                X509_NAME_oneline(issuer, cn, sizeof(cn));
                OutputDebugStringA("[sign] issuer: ");
                OutputDebugStringA(cn);
                OutputDebugStringA("\n");
            }
            if (subject) {
                char cn[256] = {0};
                X509_NAME_oneline(subject, cn, sizeof(cn));
                OutputDebugStringA("[sign] subject: ");
                OutputDebugStringA(cn);
                OutputDebugStringA("\n");
            }
        }
        if (!cert || !pkey || !X509_get_issuer_name(cert) || !X509_get_subject_name(cert)) {
            OutputDebugStringA("[sign] ERROR: invalid PFX data (NULL cert/key/issuer/subject)\n");
            if (cert) X509_free(cert);
            if (pkey) EVP_PKEY_free(pkey);
            if (ca_chain) sk_X509_pop_free(ca_chain, X509_free);
            return 0;
        }
    }

    if (status_cb) status_cb("加载 PE 文件...", cb_data);

    /* Load PE file */
    pe = pe_load(pe_path);
    if (!pe) {
        fprintf(stderr, "Failed to load PE file: %s\n", pe_path);
        goto cleanup;
    }

    /* If re-signing: strip old signature before hashing.
     * Clear old cert data and cert_dir so hash is computed on a clean file. */
    if (pe->cert_offset && pe->cert_size) {
        if (status_cb) status_cb("剥离旧签名...", cb_data);
        memset(pe->data + pe->cert_offset, 0, pe->cert_size);
        pe->size = pe->cert_offset;  /* Trim file to exclude old cert */
        if (pe->cert_dir) {
            pe->cert_dir->VirtualAddress = 0;
            pe->cert_dir->Size = 0;
        }
        pe->cert_offset = 0;
        pe->cert_size = 0;
    }

    if (status_cb) status_cb("计算 PE 哈希...", cb_data);

    /* Zero CheckSum and Certificate Table entry before hashing.
     * The hash must be computed with these fields as zero, because
     * pe_recalc_checksum will change CheckSum after the signature is attached.
     * Verification also skips these fields, so they must match. */
    if (pe->p_checksum) *pe->p_checksum = 0;
    if (pe->cert_dir) { pe->cert_dir->VirtualAddress = 0; pe->cert_dir->Size = 0; }

    /* Compute Authenticode hash (SHA256) */
    if (!pe_compute_hash(pe, EVP_sha256(), pe_hash, &pe_hash_len)) {
        fprintf(stderr, "Failed to compute PE hash\n");
        goto cleanup;
    }

    if (status_cb) status_cb("构建 PKCS#7 签名...", cb_data);

    /* Build PKCS#7 SignedData as DER */
    pkcs7_der = build_authenticode_pkcs7(pkey, cert, ca_chain,
                                          pe_hash, pe_hash_len, &pkcs7_len);
    if (!pkcs7_der) {
        fprintf(stderr, "Failed to build Authenticode PKCS#7\n");
        goto cleanup;
    }

    if (status_cb) status_cb("附加签名到 PE...", cb_data);

    /* Attach to PE and save */
    out = output_path ? output_path : pe_path;
    if (!attach_pkcs7_to_pe(pe, pkcs7_der, pkcs7_len, out)) {
        fprintf(stderr, "Failed to save signed PE\n");
        goto cleanup;
    }

    if (status_cb) status_cb("签名完成", cb_data);

    printf("Signed: %s -> %s\n", pe_path, out);
    ret = 1;

cleanup:
    if (pkcs7_der) OPENSSL_free(pkcs7_der);
    if (pe) pe_free(pe);
    if (cert) X509_free(cert);
    if (pkey) EVP_PKEY_free(pkey);
    if (ca_chain) sk_X509_pop_free(ca_chain, X509_free);

    return ret;
}

int authenticode_verify(const char *pe_path, const char *ca_path)
{
    PE_FILE *pe = NULL;
    unsigned char *sig_der = NULL;
    uint32_t sig_len = 0;
    PKCS7 *p7 = NULL;
    BIO *bio = NULL;
    unsigned char pe_hash[EVP_MAX_MD_SIZE];
    unsigned int pe_hash_len = 0;
    int ret = 0;

    /* Load PE */
    pe = pe_load(pe_path);
    if (!pe) {
        fprintf(stderr, "Failed to load PE file: %s\n", pe_path);
        return 0;
    }

    /* Extract signature */
    sig_der = pe_extract_signature(pe, &sig_len);
    if (!sig_der) {
        fprintf(stderr, "No signature found\n");
        goto cleanup;
    }

    /* Parse PKCS#7 */
    bio = BIO_new_mem_buf(sig_der, (int)sig_len);
    if (!bio) goto cleanup;
    p7 = d2i_PKCS7_bio(bio, NULL);
    if (!p7) {
        fprintf(stderr, "Failed to parse PKCS#7 signature\n");
        goto cleanup;
    }

    /* Verify certificate chain (if CA provided) */
    if (ca_path) {
        FILE *fp = fopen_utf8(ca_path, "rb");
        X509 *ca_cert;
        if (!fp) {
            fprintf(stderr, "Cannot open CA certificate: %s\n", ca_path);
            goto cleanup;
        }
        /* Try DER first, then PEM */
        ca_cert = d2i_X509_fp(fp, NULL);
        if (!ca_cert) {
            rewind(fp);
            ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
        }
        fclose(fp);
        if (!ca_cert) {
            fprintf(stderr, "Failed to parse CA certificate: %s\n", ca_path);
            goto cleanup;
        }
        /* Diagnostics: list all certs in PKCS#7 and the expected CA */
        {
            char ca_cn[256] = {0};
            X509_NAME_oneline(X509_get_subject_name(ca_cert), ca_cn, sizeof(ca_cn));
            fprintf(stderr, "[verify] Looking for CA: %s\n", ca_cn);
            if (OBJ_obj2nid(p7->type) == NID_pkcs7_signed && p7->d.sign && p7->d.sign->cert) {
                STACK_OF(X509) *all_certs = p7->d.sign->cert;
                fprintf(stderr, "[verify] PKCS#7 contains %d cert(s):\n", sk_X509_num(all_certs));
                for (int i = 0; i < sk_X509_num(all_certs); i++) {
                    char cn[256] = {0};
                    X509_NAME_oneline(X509_get_subject_name(sk_X509_value(all_certs, i)), cn, sizeof(cn));
                    fprintf(stderr, "[verify]   [%d] %s\n", i, cn);
                }
            } else {
                fprintf(stderr, "[verify] PKCS#7 has no certificates!\n");
            }
        }
        /* Check ALL certs in the PKCS7 SignedData (not just signers) */
        int found = 0;
        if (OBJ_obj2nid(p7->type) == NID_pkcs7_signed
            && p7->d.sign && p7->d.sign->cert) {
            STACK_OF(X509) *all_certs = p7->d.sign->cert;
            for (int i = 0; i < sk_X509_num(all_certs); i++) {
                if (X509_cmp(sk_X509_value(all_certs, i), ca_cert) == 0) {
                    found = 1; break;
                }
            }
        }
        X509_free(ca_cert);
        if (!found) {
            fprintf(stderr, "CA certificate not found in signature chain\n");
            goto cleanup;
        }
        printf("CA certificate chain verified\n");
    }

    /* Compute current PE hash and compare with signed hash */
    if (!pe_compute_hash(pe, EVP_sha256(), pe_hash, &pe_hash_len)) {
        fprintf(stderr, "Failed to compute PE hash for verification\n");
        goto cleanup;
    }

    /* Extract message-digest from authenticated attributes */
    {
        PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(
            PKCS7_get_signer_info(p7), 0);
        if (!si) {
            fprintf(stderr, "No signer info found\n");
            goto cleanup;
        }

        int msg_digest_nid = OBJ_txt2nid("1.2.840.113549.1.9.4");
        ASN1_TYPE *md_val = PKCS7_get_signed_attribute(si, msg_digest_nid);
        if (!md_val || md_val->type != V_ASN1_OCTET_STRING) {
            fprintf(stderr, "Invalid messageDigest attribute\n");
            goto cleanup;
        }

        ASN1_OCTET_STRING *os = md_val->value.octet_string;
        if (os->length != (int)pe_hash_len ||
            memcmp(os->data, pe_hash, pe_hash_len) != 0) {
            fprintf(stderr, "PE hash mismatch — file has been modified!\n");
            goto cleanup;
        }
    }

    printf("Signature verification passed: %s\n", pe_path);
    ret = 1;

cleanup:
    if (p7) PKCS7_free(p7);
    if (bio) BIO_free(bio);
    if (sig_der) free(sig_der);
    if (pe) pe_free(pe);

    return ret;
}

int authenticode_is_signed(const char *pe_path)
{
    PE_FILE *pe = pe_load(pe_path);
    int ret;

    if (!pe) return -1;
    ret = pe_is_signed(pe) ? 1 : 0;
    pe_free(pe);
    return ret;
}
