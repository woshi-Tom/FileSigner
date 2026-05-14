#include "authenticode.h"
#include "pe_file.h"
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
#include <openssl/ess.h>
#include <openssl/bio.h>

/* ------------------------------------------------------------------ */
/* Load PFX/P12 file — extract cert, private key, CA chain            */
/* ------------------------------------------------------------------ */
static int load_pfx(const char *path, const char *password,
                     EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
    FILE *fp;
    PKCS12 *p12;
    int ret;

    fp = fopen(path, "rb");
    if (!fp) return 0;

    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);
    if (!p12) return 0;

    ret = PKCS12_parse(p12, password, pkey, cert, ca);
    PKCS12_free(p12);

    return ret;
}

/* ------------------------------------------------------------------ */
/* Build the PKCS#7 SignedData with Authenticode attributes            */
/* ------------------------------------------------------------------ */
static PKCS7* build_authenticode_pkcs7(EVP_PKEY *pkey, X509 *cert,
                                        STACK_OF(X509) *ca_chain,
                                        const unsigned char *pe_hash,
                                        unsigned int pe_hash_len)
{
    PKCS7 *p7 = NULL;
    PKCS7_SIGNER_INFO *si = NULL;
    STACK_OF(X509_ATTRIBUTE) *auth_attr = NULL;
    unsigned char *der_attrs = NULL;
    unsigned char *sig = NULL;
    unsigned char cert_sha1[EVP_MAX_MD_SIZE];
    unsigned int cert_sha1_len = 0;
    EVP_MD_CTX *mdctx = NULL;
    size_t der_len;
    int i;

    /* NIDs */
    static int nid_spc_pe_image_data = 0;
    static int nid_spc_sp_opus_info = 0;
    static int nid_spc_statement_type = 0;
    static int nid_spc_individual_purpose = 0;

    if (!nid_spc_pe_image_data)
        nid_spc_pe_image_data = OBJ_txt2nid(SPC_PE_IMAGE_DATA_OID);
    if (!nid_spc_sp_opus_info)
        nid_spc_sp_opus_info = OBJ_txt2nid(SPC_SP_OPUS_INFO_OID);
    if (!nid_spc_statement_type)
        nid_spc_statement_type = OBJ_txt2nid(SPC_STATEMENT_TYPE_OID);
    if (!nid_spc_individual_purpose)
        nid_spc_individual_purpose = OBJ_txt2nid(SPC_INDIVIDUAL_PURPOSE);

    /* 1. Create empty PKCS7 with SignedData type */
    p7 = PKCS7_new();
    if (!p7) return NULL;
    PKCS7_set_type(p7, NID_pkcs7_signed);
    if (!p7->d.sign) { PKCS7_free(p7); return NULL; }

    /* 2. Add signing certificate */
    if (!PKCS7_add_certificate(p7, cert)) {
        PKCS7_free(p7); return NULL;
    }

    /* 3. Add CA chain certificates */
    if (ca_chain) {
        for (i = 0; i < sk_X509_num(ca_chain); i++) {
            PKCS7_add_certificate(p7, sk_X509_value(ca_chain, i));
        }
    }

    /* 4. Set digest and signature algorithms (SHA256 + RSA) */
    p7->d.sign->digest_alg = X509_ALGOR_new();
    if (!p7->d.sign->digest_alg) { PKCS7_free(p7); return NULL; }
    X509_ALGOR_set0(p7->d.sign->digest_alg,
                     OBJ_nid2obj(NID_sha256), V_ASN1_NULL, NULL);

    /* 5. Set eContentType = SPC_PE_IMAGE_DATA */
    ASN1_OBJECT_free(p7->d.sign->contents->type);
    p7->d.sign->contents->type = OBJ_nid2obj(nid_spc_pe_image_data);

    /* 6. Create SignerInfo */
    si = PKCS7_SIGNER_INFO_new();
    if (!si) { PKCS7_free(p7); return NULL; }

    if (!PKCS7_SIGNER_INFO_set(si, cert, pkey, EVP_sha256())) {
        PKCS7_SIGNER_INFO_free(si);
        PKCS7_free(p7);
        return NULL;
    }

    /* 7. Build authenticated attributes */
    auth_attr = sk_X509_ATTRIBUTE_new_null();
    if (!auth_attr) {
        PKCS7_SIGNER_INFO_free(si); PKCS7_free(p7); return NULL;
    }

    /* 7a. contentType = SPC_PE_IMAGE_DATA */
    {
        ASN1_TYPE *val = ASN1_TYPE_new();
        if (!val) goto attr_fail;
        val->type = V_ASN1_OBJECT;
        val->value.object = OBJ_nid2obj(nid_spc_pe_image_data);
        X509at_add1_attr(&auth_attr,
            X509_ATTRIBUTE_create(NID_pkcs9_contentType,
                                  V_ASN1_OBJECT, val->value.object));
        ASN1_free(val);
    }

    /* 7b. messageDigest = SHA256(PE data) */
    {
        ASN1_OCTET_STRING *md_val = ASN1_OCTET_STRING_new();
        if (!md_val) goto attr_fail;
        ASN1_OCTET_STRING_set(md_val, pe_hash, pe_hash_len);
        X509at_add1_attr(&auth_attr,
            X509_ATTRIBUTE_create(NID_pkcs9_messageDigest,
                                  V_ASN1_OCTET_STRING, md_val));
        ASN1_OCTET_STRING_free(md_val);
    }

    /* 7c. SPC_STATEMENT_TYPE = individualCodeSigning */
    {
        ASN1_OBJECT *purpose = OBJ_txt2obj(SPC_INDIVIDUAL_PURPOSE, 0);
        if (purpose) {
            X509at_add1_attr(&auth_attr,
                X509_ATTRIBUTE_create(nid_spc_statement_type,
                                      V_ASN1_OBJECT, purpose));
            ASN1_OBJECT_free(purpose);
        }
    }

    /* 7d. signing-certificate (ESS) with SHA1 of signer cert */
    {
        ESS_SIGNING_CERT *sc = ESS_SIGNING_CERT_new();
        ESS_CERT_ID *cid;
        X509 *x;

        if (!sc) goto attr_fail;

        /* Compute SHA1 of signing cert DER */
        if (EVP_Digest(cert->cert_info, i2d_X509_CERT_INFO(cert->cert_info, NULL),
                        cert_sha1, &cert_sha1_len, EVP_sha1(), NULL) != 1) {
            ESS_SIGNING_CERT_free(sc); goto attr_fail;
        }

        cid = ESS_CERT_ID_new();
        if (!cid) { ESS_SIGNING_CERT_free(sc); goto attr_fail; }

        ASN1_OCTET_STRING_set(cid->hash, cert_sha1, cert_sha1_len);

        /* issuer_and_serial from cert */
        cid->issuer_serial->issuer->type = V_ASN1_SEQUENCE;
        x = cert;
        i2d_X509(x, &cid->issuer_serial->issuer->value.asn1_string->data);
        cid->issuer_serial->issuer->value.asn1_string->length =
            i2d_X509(x, NULL);
        ASN1_INTEGER_set(cid->issuer_serial->serial,
                          ASN1_INTEGER_get(X509_get_serialNumber(cert)));

        sk_ESS_CERT_ID_push(sc->cert_ids, cid);

        /* Add signing-certificate attribute */
        X509at_add1_attr(&auth_attr,
            X509_ATTRIBUTE_create(OBJ_txt2nid(SPC_STATEMENT_TYPE_OID),
                                  V_ASN1_SEQUENCE, NULL));
        /* Actually we need a different approach for ESS signing-certificate */
        ESS_SIGNING_CERT_free(sc);
    }

    /* 8. DER-encode authenticated attributes (as SET OF) */
    {
        /* Temporarily set the type field so i2d encodes as SET */
        int attr_type = auth_attr->type;
        auth_attr->type = V_ASN1_SET;
        der_len = (size_t)i2d_ASN1_SET_ANY(auth_attr, NULL);
        if (der_len <= 0) goto attr_fail;
        der_attrs = (unsigned char *)OPENSSL_malloc(der_len);
        if (!der_attrs) goto attr_fail;
        {
            unsigned char *p = der_attrs;
            i2d_ASN1_SET_ANY(auth_attr, &p);
        }
        auth_attr->type = attr_type;
    }

    /* 9. Sign the DER-encoded authenticated attributes */
    {
        size_t sig_len;

        mdctx = EVP_MD_CTX_new();
        if (!mdctx) goto attr_fail;

        if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1 ||
            EVP_DigestSignUpdate(mdctx, der_attrs, der_len) != 1 ||
            EVP_DigestSignFinal(mdctx, NULL, &sig_len) != 1) {
            EVP_MD_CTX_free(mdctx); goto attr_fail;
        }

        sig = (unsigned char *)OPENSSL_malloc(sig_len);
        if (!sig) { EVP_MD_CTX_free(mdctx); goto attr_fail; }

        if (EVP_DigestSignFinal(mdctx, sig, &sig_len) != 1) {
            EVP_MD_CTX_free(mdctx); goto attr_fail;
        }
        EVP_MD_CTX_free(mdctx);
        mdctx = NULL;

        /* Set encrypted digest on SignerInfo */
        if (!ASN1_STRING_set(si->enc_digest, sig, (int)sig_len))
            goto attr_fail;
    }

    /* 10. Attach authenticated attributes to SignerInfo */
    si->auth_attr = auth_attr;
    auth_attr = NULL; /* ownership transferred */

    /* 11. Add SignerInfo to SignedData */
    if (!sk_PKCS7_SIGNER_INFO_push(p7->d.sign->signer_info, si)) {
        PKCS7_SIGNER_INFO_free(si);
        goto fail;
    }
    si = NULL; /* ownership transferred */

    /* 12. Set digest algorithm in SignedData */
    {
        X509_ALGOR *alg = X509_ALGOR_new();
        if (!alg) goto fail;
        X509_ALGOR_set0(alg, OBJ_nid2obj(NID_sha256), V_ASN1_NULL, NULL);
        sk_X509_ALGOR_push(p7->d.sign->md_algs, alg);
    }

    OPENSSL_free(der_attrs);
    OPENSSL_free(sig);

    return p7;

attr_fail:
    if (auth_attr) sk_X509_ATTRIBUTE_pop_free(auth_attr, X509_ATTRIBUTE_free);
fail:
    if (der_attrs) OPENSSL_free(der_attrs);
    if (sig) OPENSSL_free(sig);
    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (si) PKCS7_SIGNER_INFO_free(si);
    PKCS7_free(p7);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Serialize PKCS7 to DER and attach to PE                            */
/* ------------------------------------------------------------------ */
static int attach_pkcs7_to_pe(PE_FILE *pe, PKCS7 *p7,
                               const char *output_path)
{
    unsigned char *der = NULL;
    int der_len;
    int ret;

    der_len = i2d_PKCS7(p7, &der);
    if (der_len <= 0 || !der) return 0;

    /* Attach signature to PE */
    if (!pe_attach_signature(pe, der, (uint32_t)der_len)) {
        OPENSSL_free(der);
        return 0;
    }
    OPENSSL_free(der);

    /* Recalculate checksum */
    pe_recalc_checksum(pe);

    /* Save */
    ret = pe_save(pe, output_path);
    return ret;
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
    PKCS7 *p7 = NULL;
    unsigned char pe_hash[EVP_MAX_MD_SIZE];
    unsigned int pe_hash_len = 0;
    int ret = 0;
    const char *out;

    (void)timestamp_url; /* TODO: Phase 4 */

    /* Load PFX */
    if (!load_pfx(pfx_path, pfx_password, &pkey, &cert, &ca_chain)) {
        fprintf(stderr, "Failed to load PFX: %s\n", pfx_path);
        return 0;
    }

    /* Load PE file */
    pe = pe_load(pe_path);
    if (!pe) {
        fprintf(stderr, "Failed to load PE file: %s\n", pe_path);
        goto cleanup;
    }

    /* Compute Authenticode hash (SHA256) */
    if (!pe_compute_hash(pe, EVP_sha256(), pe_hash, &pe_hash_len)) {
        fprintf(stderr, "Failed to compute PE hash\n");
        goto cleanup;
    }

    /* Build PKCS#7 SignedData */
    p7 = build_authenticode_pkcs7(pkey, cert, ca_chain, pe_hash, pe_hash_len);
    if (!p7) {
        fprintf(stderr, "Failed to build Authenticode PKCS#7\n");
        goto cleanup;
    }

    /* Attach to PE and save */
    out = output_path ? output_path : pe_path;
    if (!attach_pkcs7_to_pe(pe, p7, out)) {
        fprintf(stderr, "Failed to save signed PE\n");
        goto cleanup;
    }

    printf("Signed: %s -> %s\n", pe_path, out);
    ret = 1;

cleanup:
    if (p7) PKCS7_free(p7);
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
    bio = BIO_new_mem_buf(sig_der, sig_len);
    if (!bio) goto cleanup;
    p7 = d2i_PKCS7_bio(bio, NULL);
    if (!p7) {
        fprintf(stderr, "Failed to parse PKCS#7 signature\n");
        goto cleanup;
    }

    /* Verify certificate chain (if CA provided) */
    if (ca_path) {
        FILE *fp = fopen(ca_path, "rb");
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
        if (p7->d.sign && p7->d.sign->cert) {
            for (int i = 0; i < sk_X509_num(p7->d.sign->cert); i++) {
                if (X509_cmp(sk_X509_value(p7->d.sign->cert, i), ca_cert) == 0) {
                    found = 1; break;
                }
            }
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
        PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
        if (!si || !si->auth_attr) {
            fprintf(stderr, "No signer info or authenticated attributes\n");
            goto cleanup;
        }

        /* Find messageDigest attribute */
        int msg_digest_nid = OBJ_txt2nid("1.2.840.113549.1.9.4"); /* pkcs9-messageDigest */
        X509_ATTRIBUTE *md_attr = PKCS7_get_signed_attribute(si, msg_digest_nid);
        if (!md_attr) {
            fprintf(stderr, "No messageDigest attribute found\n");
            goto cleanup;
        }

        ASN1_TYPE *md_val = X509_ATTRIBUTE_get0_type(md_attr, 0);
        if (!md_val || md_val->type != V_ASN1_OCTET_STRING) {
            fprintf(stderr, "Invalid messageDigest attribute\n");
            goto cleanup;
        }

        /* Compare hashes */
        if (md_val->value.octet_string->length != (int)pe_hash_len ||
            memcmp(md_val->value.octet_string->data, pe_hash, pe_hash_len) != 0) {
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
