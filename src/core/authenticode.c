#include "authenticode.h"
#include "pe_file.h"
#include "file_utils.h"
#include "timestamp.h"
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
    while (db->len + need > db->cap) {
        if (db->cap > (size_t)-1 / 2) return 0; /* overflow */
        db->cap *= 2;
    }
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
    /* Reserve 6 bytes for tag + max length encoding (tag + 0x84 + 4 bytes) */
    size_t pos = db->len;
    unsigned char zeros[6] = {0};
    db_raw(db, zeros, 6);
    return pos;
}

/* Fix a previously pushed placeholder with actual tag+length */
static void db_fix_placeholder(DerBuf *db, size_t pos, unsigned char tag,
                                size_t body_len)
{
    /* body_len = current_len - (pos + 6) */
    size_t actual = db->len - pos - 6;
    /* Write the real tag+length at pos, then shift body */
    unsigned char hdr[6];
    int hdr_len = 0;
    hdr[hdr_len++] = tag;
    if (actual < 0x80) {
        hdr[hdr_len++] = (unsigned char)actual;
    } else if (actual < 0x100) {
        hdr[hdr_len++] = 0x81;
        hdr[hdr_len++] = (unsigned char)actual;
    } else if (actual < 0x10000) {
        hdr[hdr_len++] = 0x82;
        hdr[hdr_len++] = (unsigned char)(actual >> 8);
        hdr[hdr_len++] = (unsigned char)actual;
    } else if (actual < 0x1000000) {
        hdr[hdr_len++] = 0x83;
        hdr[hdr_len++] = (unsigned char)(actual >> 16);
        hdr[hdr_len++] = (unsigned char)(actual >> 8);
        hdr[hdr_len++] = (unsigned char)actual;
    } else {
        hdr[hdr_len++] = 0x84;
        hdr[hdr_len++] = (unsigned char)(actual >> 24);
        hdr[hdr_len++] = (unsigned char)(actual >> 16);
        hdr[hdr_len++] = (unsigned char)(actual >> 8);
        hdr[hdr_len++] = (unsigned char)actual;
    }
    /* Copy header into position (overwriting zeros) */
    memcpy(db->data + pos, hdr, hdr_len);
    /* Shift body left if header is shorter than 6 bytes */
    if (hdr_len < 6) {
        size_t shift = 6 - hdr_len;
        memmove(db->data + pos + hdr_len, db->data + pos + 6, actual);
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
    DerBuf body = {0}, seq = {0};
    unsigned char *result = NULL;

    if (!db_init(&body) || !db_init(&seq)) {
        db_free(&body); db_free(&seq);
        return NULL;
    }

    /* SpcAttributeTypeAndOptionalValue = SEQUENCE { OID(SPC_PE_IMAGE_DATA) } */
    {
        DerBuf sa;
        if (!db_init(&sa)) { db_free(&body); db_free(&seq); return NULL; }
        if (!db_der_oid_str(&sa, SPC_PE_IMAGE_DATA_OID)) {
            db_free(&sa); db_free(&body); db_free(&seq); return NULL;
        }
        db_der_seq(&body, sa.data, sa.len);
        db_free(&sa);
    }

    /* DigestInfo = SEQUENCE { AlgorithmIdentifier { OID, NULL }, OCTET STRING(hash) }
     * The outer DigestInfo SEQUENCE directly contains: OID, NULL, OCTET STRING. */
    {
        DerBuf di = {0}, alg = {0}, hash_os = {0};
        if (!db_init(&di) || !db_init(&alg) || !db_init(&hash_os)) {
            db_free(&di); db_free(&alg); db_free(&hash_os);
            db_free(&body); db_free(&seq);
            return NULL;
        }
        if (!db_der_oid_nid(&alg, NID_sha256) ||
            !db_der_null(&alg) ||
            !db_der_octet_string(&hash_os, pe_hash, pe_hash_len) ||
            !db_raw(&di, alg.data, alg.len) ||
            !db_raw(&di, hash_os.data, hash_os.len)) {
            db_free(&di); db_free(&alg); db_free(&hash_os);
            db_free(&body); db_free(&seq);
            return NULL;
        }
        db_free(&alg);
        db_free(&hash_os);
        if (!db_der_seq(&body, di.data, di.len)) {
            db_free(&di); db_free(&body); db_free(&seq);
            return NULL;
        }
        db_free(&di);
    }

    /* Wrap in SEQUENCE */
    if (!db_der_seq(&seq, body.data, body.len)) {
        db_free(&body); db_free(&seq);
        return NULL;
    }
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
                                                const char *timestamp_url,
                                                authenticode_status_cb status_cb,
                                                void *cb_data,
                                                int *out_len)
{
    PKCS7 *p7 = NULL;
    PKCS7_SIGNER_INFO *si = NULL;
    unsigned char *result = NULL;
    BIO *out_bio = NULL;
    BIO *content_bio = NULL;
    BUF_MEM *bmem = NULL;
    unsigned char *spc_der = NULL;
    int spc_len = 0;

    /* 1. Create PKCS7 SignedData (PARTIAL = don't finalize) */
    p7 = PKCS7_sign(cert, pkey, NULL, NULL,
                    PKCS7_BINARY | PKCS7_PARTIAL);
    if (!p7) return NULL;

    /* 2. Get signer info for adding attributes */
    si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(p7), 0);
    if (!si) { PKCS7_free(p7); return NULL; }

    /* 3. Build SpcIndirectDataContent — this becomes the PKCS7 content */
    spc_der = build_spc_content_der(pe_hash, pe_hash_len, &spc_len);
    if (!spc_der) { PKCS7_free(p7); return NULL; }

    /* 4. Compute messageDigest = SHA256(SpcIndirectDataContent DER) */
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { OPENSSL_free(spc_der); PKCS7_free(p7); return NULL; }
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, spc_der, spc_len) != 1 ||
        EVP_DigestFinal_ex(mdctx, md_value, &md_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        OPENSSL_free(spc_der);
        PKCS7_free(p7);
        return NULL;
    }
    EVP_MD_CTX_free(mdctx);

    /* 5. Add authenticated attributes for Authenticode */
    {
        ASN1_OBJECT *obj;

        /* contentType = SPC_PE_IMAGE_DATA */
        obj = OBJ_txt2obj(SPC_PE_IMAGE_DATA_OID, 1);
        if (obj) {
            if (!PKCS7_add_signed_attribute(si, NID_pkcs9_contentType,
                                             V_ASN1_OBJECT, obj))
                ASN1_OBJECT_free(obj);
        }

        /* messageDigest = SHA256(SpcIndirectDataContent DER) */
        ASN1_OCTET_STRING *md = ASN1_OCTET_STRING_new();
        if (md) {
            ASN1_OCTET_STRING_set(md, md_value, md_len);
            if (!PKCS7_add_signed_attribute(si, NID_pkcs9_messageDigest,
                                             V_ASN1_OCTET_STRING, md))
                ASN1_OCTET_STRING_free(md);
        }

        /* signingTime = current system time (local timestamp)
         * Build as raw DER to avoid OpenSSL type conversion issues */
        {
            ASN1_UTCTIME *utc = ASN1_UTCTIME_adj(NULL, time(NULL), 0, 0);
            if (utc) {
                unsigned char time_der[64];
                int td = 0;
                /* Attribute ::= SEQUENCE { OID, SET { UTCTime } } */
                /* OID: pkcs9-signingTime = 1.2.840.113549.1.9.5 */
                unsigned char oid_bytes[] = {
                    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05
                };
                /* Encode UTCTime */
                unsigned char utc_der[32];
                int ud = 0;
                utc_der[ud++] = 0x17; /* UTCTime tag */
                utc_der[ud++] = (unsigned char)utc->length;
                memcpy(utc_der + ud, utc->data, utc->length);
                ud += utc->length;
                ASN1_UTCTIME_free(utc);

                /* SET { UTCTime } */
                unsigned char set_der[40];
                int sd = 0;
                set_der[sd++] = 0x31;
                set_der[sd++] = (unsigned char)ud;
                memcpy(set_der + sd, utc_der, ud); sd += ud;

                /* SEQUENCE { OID, SET } */
                int attr_body = (int)sizeof(oid_bytes) + sd;
                time_der[td++] = 0x30;
                time_der[td++] = (unsigned char)attr_body;
                memcpy(time_der + td, oid_bytes, sizeof(oid_bytes)); td += sizeof(oid_bytes);
                memcpy(time_der + td, set_der, sd); td += sd;

                const unsigned char *tp = time_der;
                X509_ATTRIBUTE *ts_attr = d2i_X509_ATTRIBUTE(NULL, &tp, td);
                if (ts_attr) {
                    /* Add to authenticated attributes */
                    if (!si->auth_attr)
                        si->auth_attr = sk_X509_ATTRIBUTE_new_null();
                    if (si->auth_attr) {
                        sk_X509_ATTRIBUTE_push(si->auth_attr, ts_attr);
                    } else {
                        X509_ATTRIBUTE_free(ts_attr);
                    }
                }
            }
        }
    }

    /* 6. Add CA chain certs */
    if (ca_chain) {
        for (int i = 0; i < sk_X509_num(ca_chain); i++) {
            PKCS7_add_certificate(p7, sk_X509_value(ca_chain, i));
        }
    }

    /* 7. Finalize: sign authenticated attributes.
     *    Pass SpcIndirectDataContent as content so PKCS7_final
     *    can verify the messageDigest matches. */
    content_bio = BIO_new_mem_buf(spc_der, spc_len);
    if (!content_bio) { OPENSSL_free(spc_der); PKCS7_free(p7); return NULL; }

    if (!PKCS7_final(p7, content_bio, PKCS7_BINARY)) {
        unsigned long err = ERR_get_error();
        char errbuf[256];
        ERR_error_string_n(err, errbuf, sizeof(errbuf));
        fprintf(stderr, "PKCS7_final failed: %s\n", errbuf);
        BIO_free(content_bio);
        /* Detach content before freeing spc_der to avoid double-free:
           PKCS7_final may have set contents->d.data to reference spc_der. */
        if (p7->d.sign && p7->d.sign->contents)
            p7->d.sign->contents->d.data = NULL;
        PKCS7_free(p7);
        OPENSSL_free(spc_der);
        return NULL;
    }
    BIO_free(content_bio);

    /* Ensure eContent is set in the ContentInfo.
     * Some OpenSSL 3.x builds don't populate contents->d.data from
     * the BIO passed to PKCS7_final, leaving it NULL. i2d_PKCS7_bio
     * then hits an internal assertion when encoding a SignedData with
     * missing eContent. We explicitly set it here. */
    if (p7->d.sign && p7->d.sign->contents
        && !p7->d.sign->contents->d.data) {
        ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
        if (os && ASN1_OCTET_STRING_set(os, spc_der, spc_len)) {
            p7->d.sign->contents->d.data = os;
        } else {
            if (os) ASN1_OCTET_STRING_free(os);
            fprintf(stderr, "Failed to set PKCS7 content\n");
            OPENSSL_free(spc_der);
            PKCS7_free(p7);
            return NULL;
        }
    }
    OPENSSL_free(spc_der);

    /* 8. Timestamp (RFC 3161 counter-signature via TSA server) */
    if (timestamp_url && timestamp_url[0]) {
        if (status_cb) status_cb("请求时间戳...", cb_data);
        PKCS7_SIGNER_INFO *ts_si = sk_PKCS7_SIGNER_INFO_value(
            PKCS7_get_signer_info(p7), 0);
        if (ts_si && ts_si->enc_digest && ts_si->enc_digest->length > 0) {
            /* RFC 3161 messageImprint requires a fixed-length hash,
             * not the raw RSA signature bytes. Hash the encrypted
             * digest with SHA-256 to get a 32-byte imprint. */
            unsigned char sig_hash[EVP_MAX_MD_SIZE];
            unsigned int sig_hash_len = 0;
            EVP_MD_CTX *sigctx = EVP_MD_CTX_new();
            if (sigctx) {
                EVP_DigestInit_ex(sigctx, EVP_sha256(), NULL);
                EVP_DigestUpdate(sigctx, ts_si->enc_digest->data,
                                  ts_si->enc_digest->length);
                EVP_DigestFinal_ex(sigctx, sig_hash, &sig_hash_len);
                EVP_MD_CTX_free(sigctx);
            }
            if (sig_hash_len > 0) {
                unsigned char *ts_token = NULL;
                size_t ts_token_len = 0;
                if (timestamp_request(sig_hash, sig_hash_len,
                                      NID_sha256, timestamp_url,
                                      &ts_token, &ts_token_len)) {
                    if (!timestamp_attach_to_signer(ts_si, ts_token, ts_token_len)) {
                        fprintf(stderr, "[timestamp] ERROR: failed to attach timestamp token\n");
                        free(ts_token);
                        PKCS7_free(p7);
                        return NULL;
                    }
                    free(ts_token);
                } else {
                    fprintf(stderr, "[timestamp] ERROR: timestamp server %s unreachable "
                                    "or returned invalid response\n", timestamp_url);
                    if (status_cb) status_cb("时间戳服务器连接失败", cb_data);
                    PKCS7_free(p7);
                    return NULL;
                }
            } else {
                fprintf(stderr, "[timestamp] ERROR: failed to compute hash for timestamp request\n");
                if (status_cb) status_cb("时间戳哈希计算失败", cb_data);
                PKCS7_free(p7);
                return NULL;
            }
        } else {
            fprintf(stderr, "[timestamp] ERROR: PKCS7 signer info or encrypted digest unavailable\n");
            if (status_cb) status_cb("时间戳: 签名者信息无效", cb_data);
            PKCS7_free(p7);
            return NULL;
        }
    }

    /* 9. Encode to DER */
    out_bio = BIO_new(BIO_s_mem());
    if (!out_bio) {
        PKCS7_free(p7);
        return NULL;
    }
    if (!i2d_PKCS7_bio(out_bio, p7)) {
        unsigned long err = ERR_get_error();
        char errbuf[256];
        ERR_error_string_n(err, errbuf, sizeof(errbuf));
        fprintf(stderr, "i2d_PKCS7_bio failed: %s\n", errbuf);
        BIO_free(out_bio);
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

    if (status_cb) status_cb("加载 PFX 证书...", cb_data);

    /* Load PFX */
    if (!load_pfx(pfx_path, pfx_password, &pkey, &cert, &ca_chain)) {
        fprintf(stderr, "Failed to load PFX: %s\n", pfx_path);
        if (cert) X509_free(cert);
        if (pkey) EVP_PKEY_free(pkey);
        if (ca_chain) sk_X509_pop_free(ca_chain, X509_free);
        return 0;
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
    if (pe->cert_offset && pe->cert_size &&
        pe->cert_offset + pe->cert_size <= pe->size) {
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
                                          pe_hash, pe_hash_len,
                                          timestamp_url,
                                          status_cb, cb_data,
                                          &pkcs7_len);
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

    /* Verify it's a SignedData */
    if (OBJ_obj2nid(p7->type) != NID_pkcs7_signed || !p7->d.sign) {
        fprintf(stderr, "Not a PKCS#7 SignedData\n");
        goto cleanup;
    }

    /* Verify cryptographic signature.
     * Authenticode uses SPC_PE_IMAGE_DATA as content-type OID, which
     * PKCS7_verify doesn't understand. We temporarily override it to
     * NID_pkcs7_data so OpenSSL can verify the signature, then restore. */
    {
        int sig_ok = 0;
        if (p7->d.sign->contents && p7->d.sign->contents->d.data &&
            p7->d.sign->contents->d.data->data &&
            p7->d.sign->contents->d.data->length > 0) {

            ASN1_OBJECT *saved_type = p7->d.sign->contents->type;
            ASN1_OBJECT *data_obj = OBJ_nid2obj(NID_pkcs7_data);
            if (data_obj) {
                p7->d.sign->contents->type = data_obj;

                BIO *cont = BIO_new_mem_buf(
                    p7->d.sign->contents->d.data->data,
                    p7->d.sign->contents->d.data->length);
                if (cont) {
                    if (PKCS7_verify(p7, NULL, NULL, cont, NULL,
                                     PKCS7_NOVERIFY) == 1) {
                        sig_ok = 1;
                    } else {
                        unsigned long err = ERR_get_error();
                        char errbuf[256];
                        ERR_error_string_n(err, errbuf, sizeof(errbuf));
                        fprintf(stderr, "[verify] crypto sig error: %s\n", errbuf);
                    }
                    BIO_free(cont);
                }
                /* Restore original type — PKCS7_free frees saved_type */
                p7->d.sign->contents->type = saved_type;
            }
        }
        if (!sig_ok) {
            fprintf(stderr, "Cryptographic signature verification FAILED — "
                            "file may have been tampered with\n");
            goto cleanup;
        }
        fprintf(stderr, "[verify] Cryptographic signature OK\n");
    }

    /* Verify certificate chain (if CA provided) */
    if (ca_path) {
        FILE *fp = fopen_utf8(ca_path, "rb");
        X509 *ca_cert;
        int found = 0;

        if (!fp) {
            fprintf(stderr, "Cannot open CA certificate: %s\n", ca_path);
            goto cleanup;
        }
        ca_cert = d2i_X509_fp(fp, NULL);
        if (!ca_cert) { rewind(fp); ca_cert = PEM_read_X509(fp, NULL, NULL, NULL); }
        fclose(fp);
        if (!ca_cert) {
            fprintf(stderr, "Failed to parse CA certificate: %s\n", ca_path);
            goto cleanup;
        }

        /* Verify that the signer certificate was actually issued/signed
         * by the CA's private key.  A simple X509_cmp match is insufficient
         * — an attacker could embed the target CA cert in the PKCS#7 list
         * without it ever signing the signer. */
        {
            STACK_OF(X509) *signers = PKCS7_get0_signers(p7, NULL, 0);
            if (signers) {
                for (int i = 0; i < sk_X509_num(signers); i++) {
                    X509 *signer = sk_X509_value(signers, i);
                    /* Name check: signer's issuer must match CA's subject */
                    if (X509_check_issued(ca_cert, signer) != X509_V_OK)
                        continue;
                    /* Cryptographic check: signer's signature must be
                     * verifiable with the CA's public key */
                    EVP_PKEY *ca_pkey = X509_get_pubkey(ca_cert);
                    if (ca_pkey) {
                        found = (X509_verify(signer, ca_pkey) == 1);
                        EVP_PKEY_free(ca_pkey);
                    }
                    if (found) break;
                }
                sk_X509_free(signers);
            }
        }
        X509_free(ca_cert);
        if (!found) {
            fprintf(stderr, "CA certificate did not issue/sign the signer certificate\n");
            goto cleanup;
        }
        printf("CA certificate chain verified\n");
    }

    /* Verify messageDigest and PE hash if authenticated attributes are present.
     *
     * Authenticode structure:
     *   PKCS#7 content = DER(SpcIndirectDataContent) which contains:
     *     SpcAttributeTypeAndOptionalValue { OID(SPC_PE_IMAGE_DATA) }
     *     DigestInfo { AlgorithmIdentifier { OID, NULL }, OCTET STRING(PE hash) }
     *
     *   Authenticated attribute messageDigest = SHA256(DER(SpcIndirectDataContent))
     *
     * So we must:
     *   1. Verify messageDigest == SHA256(PKCS#7 content bytes)
     *   2. Extract the PE hash from inside the SpcIndirectDataContent
     *   3. Compare extracted PE hash with hash computed from the actual PE file
     */
    {
        PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(
            PKCS7_get_signer_info(p7), 0);
        if (si) {
            int md_nid = OBJ_txt2nid("1.2.840.113549.1.9.4");
            ASN1_TYPE *md_val = (md_nid != NID_undef)
                ? PKCS7_get_signed_attribute(si, md_nid) : NULL;
            if (md_val && md_val->type == V_ASN1_OCTET_STRING) {
                ASN1_OCTET_STRING *md_attr = md_val->value.octet_string;

                /* Step 1: Verify messageDigest = SHA256(PKCS#7 content) */
                if (p7->d.sign && p7->d.sign->contents
                    && p7->d.sign->contents->d.data) {
                    ASN1_OCTET_STRING *content_os =
                        (ASN1_OCTET_STRING *)p7->d.sign->contents->d.data;
                    if (content_os->data && content_os->length > 0) {
                        unsigned char content_hash[EVP_MAX_MD_SIZE];
                        unsigned int content_hash_len = 0;
                        EVP_MD_CTX *vctx = EVP_MD_CTX_new();
                        if (vctx) {
                            EVP_DigestInit_ex(vctx, EVP_sha256(), NULL);
                            EVP_DigestUpdate(vctx, content_os->data,
                                             content_os->length);
                            EVP_DigestFinal_ex(vctx, content_hash,
                                               &content_hash_len);
                            EVP_MD_CTX_free(vctx);
                        }
                        if (content_hash_len == 0 ||
                            md_attr->length != (int)content_hash_len ||
                            memcmp(md_attr->data, content_hash,
                                   content_hash_len) != 0) {
                            fprintf(stderr, "messageDigest verification FAILED\n");
                            goto cleanup;
                        }

                        /* Step 2: Extract PE hash from SpcIndirectDataContent DER.
                         * Structure: SEQUENCE { SEQUENCE{OID}, DigestInfo }
                         * DigestInfo: SEQUENCE { OID, NULL, OCTET STRING(pe_hash) } */
                        {
                            const unsigned char *p = content_os->data;
                            const unsigned char *end = p + content_os->length;
                            unsigned char *stored_pe_hash = NULL;
                            long stored_pe_hash_len = 0;

                            /* Outer SEQUENCE */
                            if (p < end && *p == 0x30) {
                                p++;
                                if (p < end && *p < 0x80) p += 1;
                                else if (p + 1 < end && *p == 0x81) p += 2;
                                else if (p + 2 < end && *p == 0x82) p += 3;
                                else p = end;

                                /* Skip first inner SEQUENCE (SpcAttributeTypeAndOptionalValue) */
                                if (p < end && *p == 0x30) {
                                    p++;
                                    long inner = 0;
                                    if (p < end && *p < 0x80) { inner = *p++; }
                                    else if (p < end && *p == 0x81 && p+1 < end) { inner = p[1]; p += 2; }
                                    else if (p < end && *p == 0x82 && p+2 < end) { inner = (p[1]<<8)|p[2]; p += 3; }
                                    else p = end;
                                    if (p + inner <= end) p += inner;
                                }

                                /* Second inner SEQUENCE = DigestInfo */
                                if (p < end && *p == 0x30) {
                                    p++;
                                    long inner = 0;
                                    if (p < end && *p < 0x80) { inner = *p++; }
                                    else if (p < end && *p == 0x81 && p+1 < end) { inner = p[1]; p += 2; }
                                    else if (p < end && *p == 0x82 && p+2 < end) { inner = (p[1]<<8)|p[2]; p += 3; }
                                    else p = end;
                                    const unsigned char *di_end = p + inner;
                                    if (di_end > end) di_end = end;

                                    /* Skip AlgorithmIdentifier: OID + NULL */
                                    if (p + 2 <= di_end && *p == 0x06) {
                                        p++;
                                        long oid_len = 0;
                                        if (p < di_end && *p < 0x80) { oid_len = *p++; }
                                        else if (p+1 < di_end && *p == 0x81) { oid_len = p[1]; p += 2; }
                                        else p = di_end;
                                        if (p + oid_len <= di_end) p += oid_len;
                                        if (p + 2 <= di_end && *p == 0x05 && p[1] == 0x00)
                                            p += 2;
                                    }

                                    /* Read OCTET STRING containing PE hash */
                                    if (p + 2 <= di_end && *p == 0x04) {
                                        p++;
                                        if (p < di_end && *p < 0x80) {
                                            stored_pe_hash_len = *p++;
                                            if (p + stored_pe_hash_len <= di_end)
                                                stored_pe_hash = (unsigned char *)p;
                                        } else if (p+1 < di_end && *p == 0x81) {
                                            stored_pe_hash_len = p[1]; p += 2;
                                            if (p + stored_pe_hash_len <= di_end)
                                                stored_pe_hash = (unsigned char *)p;
                                        }
                                    }
                                }
                            }

                            /* Step 3: Compare stored PE hash with computed PE hash */
                            if (!stored_pe_hash || stored_pe_hash_len <= 0) {
                                fprintf(stderr, "Could not extract PE hash from signature\n");
                                goto cleanup;
                            }

                            {
                                unsigned char pe_hash[EVP_MAX_MD_SIZE];
                                unsigned int pe_hash_len = 0;
                                if (!pe_compute_hash(pe, EVP_sha256(),
                                                     pe_hash, &pe_hash_len)) {
                                    fprintf(stderr, "Failed to compute PE hash\n");
                                    goto cleanup;
                                }
                                if ((int)pe_hash_len != stored_pe_hash_len ||
                                    memcmp(pe_hash, stored_pe_hash,
                                           pe_hash_len) != 0) {
                                    fprintf(stderr, "PE hash mismatch — "
                                            "file has been modified!\n");
                                    goto cleanup;
                                }
                            }
                        }
                    }
                }
            }
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
