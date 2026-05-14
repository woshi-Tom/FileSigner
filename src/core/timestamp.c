#include "timestamp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

/* ------------------------------------------------------------------ */
/* DER construction helpers                                           */
/* ------------------------------------------------------------------ */

static int der_write_tag_len(unsigned char *buf, int tag, size_t len)
{
    int n = 0;
    buf[n++] = (unsigned char)tag;

    if (len < 0x80) {
        buf[n++] = (unsigned char)len;
    } else if (len < 0x100) {
        buf[n++] = 0x81;
        buf[n++] = (unsigned char)len;
    } else if (len < 0x10000) {
        buf[n++] = 0x82;
        buf[n++] = (unsigned char)(len >> 8);
        buf[n++] = (unsigned char)(len & 0xFF);
    } else {
        buf[n++] = 0x83;
        buf[n++] = (unsigned char)(len >> 16);
        buf[n++] = (unsigned char)((len >> 8) & 0xFF);
        buf[n++] = (unsigned char)(len & 0xFF);
    }
    return n;
}

static int der_write_sequence(unsigned char *buf, const unsigned char *inner, size_t inner_len)
{
    int hlen = der_write_tag_len(buf, 0x30, inner_len);
    memcpy(buf + hlen, inner, inner_len);
    return hlen + (int)inner_len;
}

static int der_write_oid(unsigned char *buf, const char *oid_str)
{
    ASN1_OBJECT *obj = OBJ_txt2obj(oid_str, 0);
    if (!obj) return 0;

    int len = i2d_ASN1_OBJECT(obj, NULL);
    if (len <= 0) { ASN1_OBJECT_free(obj); return 0; }

    unsigned char *tmp = buf;
    i2d_ASN1_OBJECT(obj, &tmp);
    ASN1_OBJECT_free(obj);
    return len;
}

static int der_write_octet_string(unsigned char *buf,
                                   const unsigned char *data, size_t len)
{
    int hlen = der_write_tag_len(buf, 0x04, len);
    memcpy(buf + hlen, data, len);
    return hlen + (int)len;
}

static int der_write_null(unsigned char *buf)
{
    buf[0] = 0x05;
    buf[1] = 0x00;
    return 2;
}

static int der_write_integer_small(unsigned char *buf, int val)
{
    if (val < 128) {
        buf[0] = 0x02;
        buf[1] = 0x01;
        buf[2] = (unsigned char)val;
        return 3;
    }
    buf[0] = 0x02;
    buf[1] = 0x02;
    buf[2] = (unsigned char)(val >> 8);
    buf[3] = (unsigned char)(val & 0xFF);
    return 4;
}

static int der_write_boolean(unsigned char *buf, int val)
{
    buf[0] = 0x01;
    buf[1] = 0x01;
    buf[2] = val ? 0xFF : 0x00;
    return 3;
}

/* ------------------------------------------------------------------ */
/* Build RFC 3161 TimeStampReq DER                                    */
/* ------------------------------------------------------------------ */

static unsigned char* build_timestamp_request(const unsigned char *digest,
                                               size_t digest_len,
                                               int algo_nid,
                                               size_t *out_len)
{
    unsigned char inner[1024];
    unsigned char msg_imprint[512];
    unsigned char hash_alg[64];
    unsigned char hash_val[256];
    int hi, ha, mi, ii;
    size_t total;

    /* HashAlgorithmIdentifier */
    ha = 0;
    ha += der_write_oid(hash_alg + ha, OBJ_nid2sn(algo_nid));
    ha += der_write_null(hash_alg + ha);

    /* Digest (OCTET STRING) */
    hi = der_write_octet_string(hash_val, digest, digest_len);

    /* MessageImprint SEQUENCE */
    mi = 0;
    memcpy(msg_imprint + mi, hash_alg, ha); mi += ha;
    memcpy(msg_imprint + mi, hash_val, hi); mi += hi;

    /* Inner content: version + MessageImprint */
    ii = 0;
    ii += der_write_integer_small(inner + ii, 1);  /* version = 1 */
    /* MessageImprint sequence */
    {
        int hlen = der_write_tag_len(inner + ii, 0x30, mi);
        memcpy(inner + ii + hlen, msg_imprint, mi);
        ii += hlen + mi;
    }

    /* Full TimeStampReq SEQUENCE */
    total = (size_t)ii + 10; /* extra for overhead */
    unsigned char *result = (unsigned char *)malloc(total);
    if (!result) return NULL;

    *out_len = (size_t)der_write_sequence(result, inner, ii);
    return result;
}

/* ------------------------------------------------------------------ */
/* HTTP POST via WinHTTP                                              */
/* ------------------------------------------------------------------ */

#ifdef _WIN32

static unsigned char* http_post(const char *url,
                                 const unsigned char *body, size_t body_len,
                                 size_t *resp_len)
{
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    URL_COMPONENTS uc;
    WCHAR host[256] = {0}, path[1024] = {0};
    unsigned char *response = NULL;
    DWORD status_code = 0, size = sizeof(DWORD);
    DWORD bytes_available = 0, total_read = 0;
    unsigned char *result = NULL;
    char *url_a;

    /* Convert URL to wide chars */
    int wlen = MultiByteToWideChar(CP_UTF8, 0, url, -1, NULL, 0);
    WCHAR *url_w = (WCHAR *)malloc(wlen * sizeof(WCHAR));
    if (!url_w) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, url, -1, url_w, wlen);

    /* Parse URL */
    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 1024;

    if (!WinHttpCrackUrl(url_w, 0, 0, &uc)) {
        free(url_w); return NULL;
    }
    free(url_w);

    /* Open session */
    hSession = WinHttpOpen(L"FileSigner/1.0",
                            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME,
                            WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return NULL;

    /* Connect */
    hConnect = WinHttpConnect(hSession, host, uc.nPort, 0);
    if (!hConnect) goto cleanup;

    /* Open request */
    hRequest = WinHttpOpenRequest(hConnect, L"POST", path,
                                   NULL, WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES,
                                   (uc.nScheme == INTERNET_SCHEME_HTTPS) ?
                                       WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) goto cleanup;

    /* Set content type header */
    WinHttpAddRequestHeaders(hRequest,
                              L"Content-Type: application/timestamp-query",
                              -1L, WINHTTP_ADDREQ_FLAG_ADD);

    /* Send request */
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                             (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0))
        goto cleanup;

    if (!WinHttpReceiveResponse(hRequest, NULL)) goto cleanup;

    /* Check status code */
    WinHttpQueryHeaders(hRequest,
                          WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                          WINHTTP_HEADER_NAME_BY_INDEX, &status_code,
                          &size, WINHTTP_NO_HEADER_INDEX);

    if (status_code != 200) {
        fprintf(stderr, "Timestamp server returned HTTP %lu\n", (unsigned long)status_code);
        goto cleanup;
    }

    /* Read response */
    result = (unsigned char *)malloc(65536);
    if (!result) goto cleanup;

    while (WinHttpQueryDataAvailable(hRequest, &bytes_available) && bytes_available > 0) {
        if (total_read + bytes_available > 65536) {
            unsigned char *tmp = (unsigned char *)realloc(result, total_read + bytes_available + 4096);
            if (!tmp) break;
            result = tmp;
        }
        DWORD read = 0;
        WinHttpReadData(hRequest, result + total_read, bytes_available, &read);
        total_read += read;
    }

    if (total_read > 0) {
        *resp_len = total_read;
    } else {
        free(result);
        result = NULL;
    }

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return result;
}

#endif /* _WIN32 */

/* ------------------------------------------------------------------ */
/* Parse TimeStampResp — extract the TSTInfo from the PKCS#7 token    */
/* We extract the raw PKCS#7 DER (the TimeStampToken) as a blob.      */
/* ------------------------------------------------------------------ */

static int parse_timestamp_response(const unsigned char *resp, size_t resp_len,
                                     unsigned char **out_token, size_t *out_token_len)
{
    /*
     * TimeStampResp ::= SEQUENCE {
     *     status          PKIStatusInfo,
     *     timeStampToken  TimeStampToken OPTIONAL  -- PKCS#7 ContentInfo
     * }
     *
     * We use a simple ASN.1 parser to find the timeStampToken field:
     * Skip the outer SEQUENCE header, parse the PKIStatusInfo (a SEQUENCE),
     * then the remaining data is the TimeStampToken (PKCS#7 ContentInfo).
     */

    const unsigned char *p = resp;
    const unsigned char *end = resp + resp_len;
    int tag;
    size_t len;
    int hlen;

    /* Outer SEQUENCE */
    if (p >= end || *p != 0x30) return 0;
    p++;
    hlen = 1;

    /* Parse length */
    if (p >= end) return 0;
    if (*p < 0x80) {
        len = *p++; hlen++;
    } else if (*p == 0x81) {
        p++; hlen++;
        if (p >= end) return 0;
        len = *p++; hlen++;
    } else if (*p == 0x82) {
        p++; hlen++;
        if (p + 1 >= end) return 0;
        len = ((size_t)p[0] << 8) | p[1];
        p += 2; hlen += 2;
    } else {
        return 0;
    }

    /* Now p points to first element: PKIStatusInfo (SEQUENCE) */
    if (p >= end || *p != 0x30) return 0;

    /* Skip PKIStatusInfo by parsing its length */
    p++;
    if (p >= end) return 0;
    if (*p < 0x80) {
        size_t inner_len = *p;
        p += 1 + inner_len;
    } else if (*p == 0x81) {
        p++;
        if (p >= end) return 0;
        size_t inner_len = *p;
        p += 1 + inner_len;
    } else if (*p == 0x82) {
        p++;
        if (p + 1 >= end) return 0;
        size_t inner_len = ((size_t)p[0] << 8) | p[1];
        p += 2 + inner_len;
    } else {
        return 0;
    }

    /* Check if there's a timeStampToken */
    if (p >= end) {
        /* No optional token */
        return 0;
    }

    /* The remaining data is the TimeStampToken (a PKCS#7 ContentInfo SEQUENCE) */
    size_t token_len = (size_t)(end - p);
    unsigned char *token = (unsigned char *)malloc(token_len);
    if (!token) return 0;

    memcpy(token, p, token_len);
    *out_token = token;
    *out_token_len = token_len;

    return 1;
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

int timestamp_request(const unsigned char *digest, size_t digest_len,
                      int algo_nid, const char *url,
                      unsigned char **out_token, size_t *out_len)
{
    unsigned char *req_der = NULL;
    size_t req_len = 0;
    unsigned char *http_resp = NULL;
    size_t resp_len = 0;
    int ret = 0;

    /* Build TimeStampReq */
    req_der = build_timestamp_request(digest, digest_len, algo_nid, &req_len);
    if (!req_der) {
        fprintf(stderr, "Failed to build timestamp request\n");
        return 0;
    }

#ifdef _WIN32
    /* Send HTTP POST */
    http_resp = http_post(url, req_der, req_len, &resp_len);
    if (!http_resp) {
        fprintf(stderr, "HTTP POST to timestamp server failed\n");
        free(req_der);
        return 0;
    }

    /* Parse response */
    if (!parse_timestamp_response(http_resp, resp_len, out_token, out_len)) {
        fprintf(stderr, "Failed to parse timestamp response\n");
        free(http_resp);
        free(req_der);
        return 0;
    }

    ret = 1;
    free(http_resp);
#else
    (void)url;
    (void)out_token;
    (void)out_len;
    fprintf(stderr, "Timestamp requests require WinHTTP (Windows only)\n");
#endif

    free(req_der);
    return ret;
}

int timestamp_attach_to_signer(void *vsi,
                                const unsigned char *token_der,
                                size_t token_len)
{
    PKCS7_SIGNER_INFO *si = (PKCS7_SIGNER_INFO *)vsi;
    ASN1_OBJECT *oid;
    ASN1_OCTET_STRING *os;
    X509_ATTRIBUTE *attr;

    if (!si || !token_der || token_len == 0)
        return 0;

    /* Create OID for timestamp token */
    oid = OBJ_txt2obj(TIMESTAMP_TOKEN_OID, 0);
    if (!oid) return 0;

    /* Create OCTET STRING wrapping the token DER */
    os = ASN1_OCTET_STRING_new();
    if (!os) { ASN1_OBJECT_free(oid); return 0; }

    if (!ASN1_OCTET_STRING_set(os, token_der, (int)token_len)) {
        ASN1_OBJECT_free(oid);
        ASN1_OCTET_STRING_free(os);
        return 0;
    }

    /* Create attribute with NID, type=OCTET_STRING, value=os */
    attr = X509_ATTRIBUTE_create(
        OBJ_txt2nid(TIMESTAMP_TOKEN_OID),
        V_ASN1_OCTET_STRING, os);

    ASN1_OBJECT_free(oid);
    ASN1_OCTET_STRING_free(os);

    if (!attr) return 0;

    /* Add to unauthenticated attributes */
    if (!si->unauth_attr)
        si->unauth_attr = sk_X509_ATTRIBUTE_new_null();

    if (!sk_X509_ATTRIBUTE_push(si->unauth_attr, attr)) {
        X509_ATTRIBUTE_free(attr);
        return 0;
    }

    return 1;
}
