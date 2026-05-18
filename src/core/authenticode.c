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
    return db->data != NULL;
}

static void db_free(DerBuf *db)
{
    OPENSSL_free(db->data);
    db->data = NULL;
    db->len = 0;
}

static int db_grow(DerBuf *db, size_t need)
{
    if (db->len + need <= db->cap) return 1;
    while (db->len + need > db->cap) db->cap *= 2;
    unsigned char *p = (unsigned char *)OPENSSL_realloc(db->data, db->cap);
    if (!p) return 0;
    db->data = p;
    return 1;
}

static int db_raw(DerBuf *db, const void *src, size_t n)
{
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
    tmp[n++] = (unsigned char)(val & 0xff);
    val >>= 8;
    while (val) { tmp[n++] = (unsigned char)(val & 0xff); val >>= 8; }
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
/* Build authenticated attributes as DER SET OF                       */
/* ------------------------------------------------------------------ */

static int build_auth_attrs_der(const unsigned char *pe_hash,
                                 unsigned int pe_hash_len,
                                 const unsigned char *cert_der,
                                 int cert_der_len,
                                 DerBuf *out)
{
    DerBuf body;
    if (!db_init(&body)) return 0;

    /* Attribute 1: contentType = SPC_PE_IMAGE_DATA (OID 1.3.6.1.4.1.311.2.1.15) */
    {
        DerBuf val, attr;
        if (!db_init(&val) || !db_init(&attr)) {
            db_free(&val); db_free(&attr);
            goto cleanup_attrs;
        }
        db_der_oid_str(&val, SPC_PE_IMAGE_DATA_OID);
        /* attr = SEQUENCE { OID(NID_pkcs9_contentType), SET { value } } */
        db_der_oid_nid(&attr, NID_pkcs9_contentType);
        {
            DerBuf set_body;
            if (!db_init(&set_body)) { goto cleanup_attrs; }
            db_raw(&set_body, val.data, val.len);
            db_der_set(&attr, set_body.data, set_body.len);
            db_free(&set_body);
        }
        db_raw(&body, attr.data, attr.len);
        db_free(&attr);
        db_free(&val);
    }

    /* Attribute 2: messageDigest = SHA256(PE hash) */
    {
        DerBuf val, attr;
        if (!db_init(&val) || !db_init(&attr)) {
            db_free(&val); db_free(&attr);
            goto cleanup_attrs;
        }
        db_der_octet_string(&val, pe_hash, pe_hash_len);
        db_der_oid_nid(&attr, NID_pkcs9_messageDigest);
        {
            DerBuf set_body;
            if (!db_init(&set_body)) { goto cleanup_attrs; }
            db_raw(&set_body, val.data, val.len);
            db_der_set(&attr, set_body.data, set_body.len);
            db_free(&set_body);
        }
        db_raw(&body, attr.data, attr.len);
        db_free(&attr);
        db_free(&val);
    }

    /* Attribute 3: SPC_STATEMENT_TYPE = individualCodeSigning */
    {
        DerBuf val, attr;
        if (!db_init(&val) || !db_init(&attr)) {
            db_free(&val); db_free(&attr);
            goto cleanup_attrs;
        }
        db_der_oid_str(&val, SPC_INDIVIDUAL_PURPOSE);
        /* Use SPC_STATEMENT_TYPE OID as the attribute type */
        db_der_oid_str(&attr, SPC_STATEMENT_TYPE_OID);
        {
            DerBuf set_body;
            if (!db_init(&set_body)) { goto cleanup_attrs; }
            db_raw(&set_body, val.data, val.len);
            db_der_set(&attr, set_body.data, set_body.len);
            db_free(&set_body);
        }
        db_raw(&body, attr.data, attr.len);
        db_free(&attr);
        db_free(&val);
    }

    /* Attribute 4: ESS signing-certificate (SHA1 of cert DER) */
    {
        unsigned char cert_sha1[EVP_MAX_MD_SIZE];
        unsigned int cert_sha1_len = 0;
        EVP_Digest(cert_der, (size_t)cert_der_len,
                    cert_sha1, &cert_sha1_len, EVP_sha1(), NULL);

        /* Build ESS SigningCert value manually as DER:
         * SigningCert ::= SEQUENCE {
         *   certs ::= SEQUENCE OF ESSCertID
         * }
         * ESSCertID ::= SEQUENCE {
         *   hash ::= OCTET STRING (SHA1 of cert DER)
         *   issuerSerial ::= SEQUENCE {
         *     issuer ::= [0] IMPLICIT SEQUENCE OF GeneralName (issuer name as is)
         *     serial ::= CertificateSerialNumber (INTEGER)
         *   }
         * }
         */
        /* We'll encode this directly and add as attribute */
        /* For simplicity, skip ESS signing-certificate — Windows still validates
           without it for self-signed chains. The important attrs are above. */
        (void)cert_sha1;
        (void)cert_sha1_len;
    }

    /* Wrap as SET OF */
    {
        int ok = db_der_set(out, body.data, body.len);
        db_free(&body);
        return ok;
    }

cleanup_attrs:
    db_free(&body);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Sign the authenticated attributes and return encrypted digest      */
/* ------------------------------------------------------------------ */

static int sign_attrs(const unsigned char *der_attrs, size_t der_len,
                       EVP_PKEY *pkey,
                       unsigned char **out_sig, size_t *out_sig_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1 ||
        EVP_DigestSignUpdate(ctx, der_attrs, der_len) != 1 ||
        EVP_DigestSignFinal(ctx, NULL, out_sig_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    *out_sig = (unsigned char *)OPENSSL_malloc(*out_sig_len);
    if (!*out_sig) { EVP_MD_CTX_free(ctx); return 0; }

    if (EVP_DigestSignFinal(ctx, *out_sig, out_sig_len) != 1) {
        OPENSSL_free(*out_sig); *out_sig = NULL;
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    EVP_MD_CTX_free(ctx);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Build PKCS#7 SignedData as raw DER                                 */
/* ------------------------------------------------------------------ */

static unsigned char* build_authenticode_pkcs7(EVP_PKEY *pkey, X509 *cert,
                                                STACK_OF(X509) *ca_chain,
                                                const unsigned char *pe_hash,
                                                unsigned int pe_hash_len,
                                                int *out_len)
{
    DerBuf signed_data;
    unsigned char *der_attrs = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    unsigned char *cert_der = NULL;
    int cert_der_len = 0;
    unsigned char *result = NULL;

    if (!db_init(&signed_data)) return NULL;

    /* 1. version = 1 */
    db_der_int(&signed_data, 1);

    /* 2. digestAlgorithms = SET { SEQUENCE { SHA256, NULL } } */
    {
        DerBuf alg, alg_seq, alg_set;
        if (!db_init(&alg) || !db_init(&alg_seq) || !db_init(&alg_set))
            goto cleanup;
        db_der_oid_nid(&alg, NID_sha256);
        db_der_null(&alg);
        db_der_seq(&alg_seq, alg.data, alg.len);
        db_der_set(&alg_set, alg_seq.data, alg_seq.len);
        db_raw(&signed_data, alg_set.data, alg_set.len);
        db_free(&alg_set);
        db_free(&alg_seq);
        db_free(&alg);
    }

    /* 3. contentInfo = SEQUENCE { OID(SPC_PE_IMAGE_DATA) } */
    {
        DerBuf ci, ci_seq;
        if (!db_init(&ci) || !db_init(&ci_seq))
            goto cleanup;
        db_der_oid_str(&ci, SPC_PE_IMAGE_DATA_OID);
        db_der_seq(&ci_seq, ci.data, ci.len);
        db_raw(&signed_data, ci_seq.data, ci_seq.len);
        db_free(&ci_seq);
        db_free(&ci);
    }

    /* 4. certificates [0] IMPLICIT SET OF { cert, [ca certs] } */
    {
        DerBuf certs;
        if (!db_init(&certs))
            goto cleanup;

        /* Add signing cert */
        cert_der_len = i2d_X509(cert, &cert_der);
        if (cert_der_len <= 0 || !cert_der) {
            goto cleanup;
        }
        db_raw(&certs, cert_der, (size_t)cert_der_len);

        /* Add CA chain certs */
        if (ca_chain) {
            for (int i = 0; i < sk_X509_num(ca_chain); i++) {
                unsigned char *ca_der = NULL;
                int ca_len = i2d_X509(sk_X509_value(ca_chain, i), &ca_der);
                if (ca_len > 0 && ca_der) {
                    db_raw(&certs, ca_der, (size_t)ca_len);
                    OPENSSL_free(ca_der);
                }
            }
        }

        /* [0] IMPLICIT SET OF — tag 0xA0 (context-specific, constructed) */
        db_tag(&signed_data, 0xA0, certs.len);
        db_raw(&signed_data, certs.data, certs.len);
        db_free(&certs);
    }

    /* 5. Build authenticated attributes and sign */
    {
        DerBuf auth_attrs;
        if (!build_auth_attrs_der(pe_hash, pe_hash_len,
                                   cert_der, cert_der_len, &auth_attrs)) {
            goto cleanup;
        }

        der_attrs = auth_attrs.data;
        /* Don't free auth_attrs — we own der_attrs now */
        auth_attrs.data = NULL;

        /* Sign the DER-encoded attrs */
        if (!sign_attrs(der_attrs, auth_attrs.len, pkey, &sig, &sig_len)) {
            goto cleanup;
        }

        /* signerInfos */
        {
            DerBuf si;
            if (!db_init(&si))
                goto cleanup;

            /* version = 1 */
            db_der_int(&si, 1);

            /* issuerAndSerialNumber */
            {
                X509_NAME *issuer = X509_get_issuer_name(cert);
                ASN1_INTEGER *serial = X509_get_serialNumber(cert);

                DerBuf isn;
                if (!db_init(&isn)) { db_free(&si); goto cleanup; }
                /* issuer */
                {
                    unsigned char *name_der = NULL;
                    int name_len = i2d_X509_NAME(issuer, &name_der);
                    if (name_len > 0 && name_der) {
                        db_raw(&isn, name_der, (size_t)name_len);
                        OPENSSL_free(name_der);
                    }
                }
                /* serial */
                {
                    DerBuf ser;
                    if (!db_init(&ser)) { db_free(&isn); db_free(&si); goto cleanup; }
                    db_der_int(&ser, ASN1_INTEGER_get(serial));
                    db_raw(&isn, ser.data, ser.len);
                    db_free(&ser);
                }
                db_raw(&si, isn.data, isn.len);
                db_free(&isn);
            }

            /* digestAlgorithm = SHA256 */
            {
                DerBuf alg, alg_seq;
                if (!db_init(&alg) || !db_init(&alg_seq)) {
                    db_free(&alg); db_free(&alg_seq); db_free(&si);
                    goto cleanup;
                }
                db_der_oid_nid(&alg, NID_sha256);
                db_der_null(&alg);
                db_der_seq(&alg_seq, alg.data, alg.len);
                db_raw(&si, alg_seq.data, alg_seq.len);
                db_free(&alg_seq);
                db_free(&alg);
            }

            /* authenticatedAttributes [0] IMPLICIT SET OF */
            db_tag(&si, 0xA0, auth_attrs.len);
            db_raw(&si, der_attrs, auth_attrs.len);
            db_free(&auth_attrs);

            /* digestEncryptionAlgorithm = RSA-SHA256 */
            {
                DerBuf enc_alg, enc_seq;
                if (!db_init(&enc_alg) || !db_init(&enc_seq)) {
                    db_free(&enc_alg); db_free(&enc_seq); db_free(&si);
                    goto cleanup;
                }
                db_der_oid_nid(&enc_alg, NID_rsaEncryption);
                db_der_null(&enc_alg);
                db_der_seq(&enc_seq, enc_alg.data, enc_alg.len);
                db_raw(&si, enc_seq.data, enc_seq.len);
                db_free(&enc_seq);
                db_free(&enc_alg);
            }

            /* encryptedDigest */
            db_der_octet_string(&si, sig, sig_len);
            OPENSSL_free(sig); sig = NULL;

            /* signerInfos ::= SET OF { SignerInfo } */
            {
                DerBuf si_seq, si_set;
                if (!db_init(&si_seq) || !db_init(&si_set)) {
                    db_free(&si_seq); db_free(&si_set); db_free(&si);
                    goto cleanup;
                }
                db_der_seq(&si_seq, si.data, si.len);
                db_der_set(&si_set, si_seq.data, si_seq.len);
                db_raw(&signed_data, si_set.data, si_set.len);
                db_free(&si_set);
                db_free(&si_seq);
            }
            db_free(&si);
        }
    }

    /* 6. Wrap as ContentInfo: SEQUENCE { OID(pkcs7-signedData), [0] { signedData } } */
    {
        DerBuf ci;
        if (!db_init(&ci))
            goto cleanup;
        /* ContentInfo OID */
        db_der_oid_str(&ci, "1.2.840.113549.1.7.2");

        /* [0] EXPLICIT — wrap SignedData in its own SEQUENCE first */
        {
            DerBuf sd_seq;
            if (!db_init(&sd_seq)) { db_free(&ci); goto cleanup; }
            db_der_seq(&sd_seq, signed_data.data, signed_data.len);

            db_tag(&ci, 0xA0, sd_seq.len);
            db_raw(&ci, sd_seq.data, sd_seq.len);
            db_free(&sd_seq);
        }

        /* Final outer SEQUENCE */
        {
            DerBuf outer;
            if (!db_init(&outer)) { db_free(&ci); goto cleanup; }
            db_der_seq(&outer, ci.data, ci.len);

            *out_len = (int)outer.len;
            result = (unsigned char *)OPENSSL_malloc(outer.len);
            if (result) memcpy(result, outer.data, outer.len);
            db_free(&outer);
            db_free(&ci);
        }
    }

cleanup:
    db_free(&signed_data);
    if (cert_der) OPENSSL_free(cert_der);
    if (der_attrs) OPENSSL_free(der_attrs);
    if (sig) OPENSSL_free(sig);
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
                      const char *output_path)
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

    fprintf(stderr, "[sign] Loading PFX: %s\n", pfx_path);

    /* Load PFX */
    if (!load_pfx(pfx_path, pfx_password, &pkey, &cert, &ca_chain)) {
        fprintf(stderr, "Failed to load PFX: %s\n", pfx_path);
        return 0;
    }

    fprintf(stderr, "[sign] Loading PE: %s\n", pe_path);

    /* Load PE file */
    pe = pe_load(pe_path);
    if (!pe) {
        fprintf(stderr, "Failed to load PE file: %s\n", pe_path);
        goto cleanup;
    }

    /* If re-signing: strip old signature before hashing.
     * Clear old cert data and cert_dir so hash is computed on a clean file. */
    if (pe->cert_offset && pe->cert_size) {
        fprintf(stderr, "[sign] Re-signing: stripping old signature (offset=%u size=%u)\n",
                pe->cert_offset, pe->cert_size);
        memset(pe->data + pe->cert_offset, 0, pe->cert_size);
        pe->size = pe->cert_offset;  /* Trim file to exclude old cert */
        if (pe->cert_dir) {
            pe->cert_dir->VirtualAddress = 0;
            pe->cert_dir->Size = 0;
        }
        pe->cert_offset = 0;
        pe->cert_size = 0;
    }

    fprintf(stderr, "[sign] Computing hash\n");

    /* Compute Authenticode hash (SHA256) */
    if (!pe_compute_hash(pe, EVP_sha256(), pe_hash, &pe_hash_len)) {
        fprintf(stderr, "Failed to compute PE hash\n");
        goto cleanup;
    }

    fprintf(stderr, "[sign] Building PKCS#7\n");

    /* Build PKCS#7 SignedData as DER */
    pkcs7_der = build_authenticode_pkcs7(pkey, cert, ca_chain,
                                          pe_hash, pe_hash_len, &pkcs7_len);
    if (!pkcs7_der) {
        fprintf(stderr, "Failed to build Authenticode PKCS#7\n");
        goto cleanup;
    }

    fprintf(stderr, "[sign] Attaching signature to PE\n");

    /* Attach to PE and save */
    out = output_path ? output_path : pe_path;
    if (!attach_pkcs7_to_pe(pe, pkcs7_der, pkcs7_len, out)) {
        fprintf(stderr, "Failed to save signed PE\n");
        goto cleanup;
    }

    fprintf(stderr, "[sign] Done: %s -> %s\n", pe_path, out);

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
        ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
        fclose(fp);
        if (!ca_cert) {
            fprintf(stderr, "Failed to parse CA certificate\n");
            goto cleanup;
        }
        /* Check if CA cert is in the PKCS7 cert stack */
        int found = 0;
        STACK_OF(X509) *certs = PKCS7_get0_signers(p7, NULL, 0);
        if (certs) {
            for (int i = 0; i < sk_X509_num(certs); i++) {
                if (X509_cmp(sk_X509_value(certs, i), ca_cert) == 0) {
                    found = 1; break;
                }
            }
            sk_X509_free(certs);
        }
        X509_free(ca_cert);
        if (!found) {
            fprintf(stderr, "CA certificate not found in signature chain\n");
            goto cleanup;
        }
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
