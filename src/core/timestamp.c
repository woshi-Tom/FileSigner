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

    unsigned char tmp[64];
    int full_len = i2d_ASN1_OBJECT(obj, NULL);
    if (full_len <= 0 || full_len > (int)sizeof(tmp)) {
        ASN1_OBJECT_free(obj); return 0;
    }

    unsigned char *p = tmp;
    i2d_ASN1_OBJECT(obj, &p);
    ASN1_OBJECT_free(obj);

    /* Output full DER (tag + length + content) */
    memcpy(buf, tmp, full_len);
    return full_len;
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
    /*
     * TimeStampReq ::= SEQUENCE {
     *   version         INTEGER 1,
     *   messageImprint  SEQUENCE {
     *     algorithm  SEQUENCE { OID, NULL },
     *     hash       OCTET STRING
     *   }
     * }
     */

    /* 1. AlgorithmIdentifier = SEQUENCE { OID(sha256), NULL } */
    unsigned char alg_id[40];
    int alg_len = 0;
    {
        unsigned char oid[32];
        int oid_len = der_write_oid(oid, OBJ_nid2sn(algo_nid));
        /* body = full DER OID + NULL */
        unsigned char body[40];
        int blen = 0;
        memcpy(body, oid, oid_len); blen += oid_len;
        body[blen++] = 0x05; body[blen++] = 0x00;    /* NULL */
        alg_len = der_write_tag_len(alg_id, 0x30, blen);
        memcpy(alg_id + alg_len, body, blen); alg_len += blen;
    }

    /* 2. OCTET STRING header for digest */
    unsigned char hash_hdr[8];
    int hh_len = der_write_tag_len(hash_hdr, 0x04, digest_len);

    /* 3. MessageImprint body = alg_id || hash_hdr || digest */
    int mi_body = alg_len + hh_len + (int)digest_len;

    /* 4. version = INTEGER(1) */
    unsigned char ver[4];
    int vl = der_write_integer_small(ver, 1);

    /* 5. Assemble inner: version + MessageImprint SEQUENCE + certReq(TRUE) */
    unsigned char inner[1024];
    int ipos = 0;
    #define CHECK_BOUNDS(n) do { if ((int)(n) > (int)sizeof(inner) - ipos) return NULL; } while(0)
    CHECK_BOUNDS(vl);
    memcpy(inner + ipos, ver, vl); ipos += vl;
    {
        int tl = der_write_tag_len(inner + ipos, 0x30, mi_body);
        CHECK_BOUNDS(tl); ipos += tl;
    }
    CHECK_BOUNDS(alg_len);
    memcpy(inner + ipos, alg_id, alg_len); ipos += alg_len;
    CHECK_BOUNDS(hh_len);
    memcpy(inner + ipos, hash_hdr, hh_len); ipos += hh_len;
    CHECK_BOUNDS((int)digest_len);
    memcpy(inner + ipos, digest, (int)digest_len); ipos += (int)digest_len;
    /* certReq = TRUE */
    CHECK_BOUNDS(3);
    inner[ipos++] = 0x01; inner[ipos++] = 0x01; inner[ipos++] = 0xFF;
    #undef CHECK_BOUNDS

    /* 6. Outer SEQUENCE */
    unsigned char *result = (unsigned char *)malloc((size_t)ipos + 5);
    if (!result) return NULL;

    *out_len = (size_t)der_write_sequence(result, inner, ipos);
    return result;
}

/* ------------------------------------------------------------------ */
/* HTTP POST via WinHTTP                                              */
/* ------------------------------------------------------------------ */

#ifdef _WIN32

static unsigned char* http_post(const char *url,
                                 const unsigned char *body, size_t body_len,
                                 size_t *resp_len, DWORD timeout_ms)
{
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    URL_COMPONENTS uc;
    WCHAR host[256] = {0}, path[1024] = {0};
    DWORD status_code = 0, size = sizeof(DWORD);
    DWORD bytes_available = 0, total_read = 0;
    unsigned char *result = NULL;
    size_t buf_cap = 0;

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
        fprintf(stderr, "[timestamp] WinHttpCrackUrl failed: err=%lu url=%s\n",
                GetLastError(), url);
        free(url_w); return NULL;
    }
    free(url_w);

    fprintf(stderr, "[timestamp] POST %S:%lu%S (%lu bytes)\n",
            host, (unsigned long)uc.nPort, path, (unsigned long)body_len);

    /* Open session */
    hSession = WinHttpOpen(L"FileSigner/1.0",
                            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME,
                            WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        fprintf(stderr, "[timestamp] WinHttpOpen failed: err=%lu\n", GetLastError());
        return NULL;
    }

    /* Set timeouts from parameter */
    {
        DWORD t = timeout_ms > 0 ? timeout_ms : 10000;
        DWORD half = t / 2;
        WinHttpSetTimeouts(hSession, half, half, t, t);
    }

    /* Connect */
    hConnect = WinHttpConnect(hSession, host, uc.nPort, 0);
    if (!hConnect) {
        fprintf(stderr, "[timestamp] WinHttpConnect failed: err=%lu\n", GetLastError());
        goto cleanup;
    }

    /* Open request */
    hRequest = WinHttpOpenRequest(hConnect, L"POST", path,
                                   NULL, WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES,
                                   (uc.nScheme == INTERNET_SCHEME_HTTPS) ?
                                       WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        fprintf(stderr, "[timestamp] WinHttpOpenRequest failed: err=%lu\n", GetLastError());
        goto cleanup;
    }

    /* Enable automatic HTTPS redirect */
    {
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                      SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
    }

    /* Set content type header */
    WinHttpAddRequestHeaders(hRequest,
                              L"Content-Type: application/timestamp-query",
                              -1L, WINHTTP_ADDREQ_FLAG_ADD);

    /* Send request */
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                             (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0)) {
        fprintf(stderr, "[timestamp] WinHttpSendRequest failed: err=%lu\n", GetLastError());
        goto cleanup;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        fprintf(stderr, "[timestamp] WinHttpReceiveResponse failed: err=%lu\n", GetLastError());
        goto cleanup;
    }

    /* Check status code */
    WinHttpQueryHeaders(hRequest,
                          WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                          WINHTTP_HEADER_NAME_BY_INDEX, &status_code,
                          &size, WINHTTP_NO_HEADER_INDEX);

    fprintf(stderr, "[timestamp] HTTP %lu\n", (unsigned long)status_code);

    /* Read response body (both success and error) */
    buf_cap = 65536;
    result = (unsigned char *)malloc(buf_cap);
    if (!result) goto cleanup;

    while (WinHttpQueryDataAvailable(hRequest, &bytes_available) && bytes_available > 0) {
        if ((size_t)total_read + bytes_available > buf_cap) {
            buf_cap = (size_t)total_read + bytes_available + 4096;
            unsigned char *tmp = (unsigned char *)realloc(result, buf_cap);
            if (!tmp) break;
            result = tmp;
        }
        DWORD read = 0;
        WinHttpReadData(hRequest, result + total_read, bytes_available, &read);
        total_read += read;
    }

    if (total_read > 0) {
        *resp_len = total_read;
        fprintf(stderr, "[timestamp] received %lu bytes\n", (unsigned long)total_read);
        /* If non-200, dump response for debugging */
        if (status_code != 200) {
            fprintf(stderr, "[timestamp] error response (%lu bytes): ", (unsigned long)total_read);
            for (DWORD i = 0; i < total_read && i < 64; i++)
                fprintf(stderr, "%02x ", result[i]);
            fprintf(stderr, "\n");
            free(result);
            result = NULL;
        }
    } else {
        fprintf(stderr, "[timestamp] empty response\n");
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
     * Skip PKIStatusInfo, then remaining data is the TimeStampToken.
     */

    /* Diagnostic: dump first 16 bytes */
    fprintf(stderr, "[timestamp] response (%zu bytes):", resp_len);
    for (size_t i = 0; i < resp_len && i < 16; i++)
        fprintf(stderr, " %02x", resp[i]);
    fprintf(stderr, "\n");

    const unsigned char *p = resp;
    const unsigned char *end = resp + resp_len;
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
        if (p + 1 + inner_len > end) return 0;
        p += 1 + inner_len;
    } else if (*p == 0x81) {
        p++;
        if (p >= end) return 0;
        size_t inner_len = *p;
        if (p + 1 + inner_len > end) return 0;
        p += 1 + inner_len;
    } else if (*p == 0x82) {
        p++;
        if (p + 1 >= end) return 0;
        size_t inner_len = ((size_t)p[0] << 8) | p[1];
        if (p + 2 + inner_len > end) return 0;
        p += 2 + inner_len;
    } else {
        return 0;
    }

    /* Check if there's a timeStampToken */
    if (p >= end) {
        /* No optional token */
        fprintf(stderr, "[timestamp] response has no timeStampToken\n");
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

    fprintf(stderr, "[timestamp] requesting from: %s\n", url);

    /* Build TimeStampReq */
    req_der = build_timestamp_request(digest, digest_len, algo_nid, &req_len);
    if (!req_der) {
        fprintf(stderr, "[timestamp] failed to build request\n");
        return 0;
    }

    /* Debug: dump request DER */
    fprintf(stderr, "[timestamp] request DER (%zu bytes):", req_len);
    for (size_t i = 0; i < req_len; i++) fprintf(stderr, " %02x", req_der[i]);
    fprintf(stderr, "\n");

#ifdef _WIN32
    /* Send HTTP POST */
    http_resp = http_post(url, req_der, req_len, &resp_len, 10000);
    if (!http_resp) {
        fprintf(stderr, "[timestamp] HTTP POST failed\n");
        free(req_der);
        return 0;
    }

    /* Parse response */
    if (!parse_timestamp_response(http_resp, resp_len, out_token, out_len)) {
        fprintf(stderr, "[timestamp] failed to parse response (%zu bytes)\n", resp_len);
        free(http_resp);
        free(req_der);
        return 0;
    }

    fprintf(stderr, "[timestamp] token obtained: %zu bytes\n", *out_len);
    ret = 1;
    free(http_resp);
#else
    (void)url;
    (void)out_token;
    (void)out_len;
    fprintf(stderr, "[timestamp] WinHTTP required (Windows only)\n");
#endif

    free(req_der);
    return ret;
}

/* Helper: write DER tag + length header, return header length */
static int write_tl(unsigned char *out, unsigned char tag, size_t body_len)
{
    int n = 0;
    out[n++] = tag;
    if (body_len < 0x80) {
        out[n++] = (unsigned char)body_len;
    } else if (body_len < 0x100) {
        out[n++] = 0x81;
        out[n++] = (unsigned char)body_len;
    } else {
        out[n++] = 0x82;
        out[n++] = (unsigned char)(body_len >> 8);
        out[n++] = (unsigned char)(body_len & 0xFF);
    }
    return n;
}

int timestamp_attach_to_signer(void *vsi,
                                const unsigned char *token_der,
                                size_t token_len)
{
    PKCS7_SIGNER_INFO *si = (PKCS7_SIGNER_INFO *)vsi;
    X509_ATTRIBUTE *attr = NULL;
    unsigned char oid_buf[64];
    int oid_len;
    unsigned char *der, *p;
    unsigned char tl[5];
    int set_hl, seq_hl;
    size_t set_body, seq_body, total;

    if (!si || !token_der || token_len == 0) {
        fprintf(stderr, "[timestamp] attach: invalid params\n");
        return 0;
    }

    fprintf(stderr, "[timestamp] attach: token %zu bytes, first 8:", token_len);
    for (size_t i = 0; i < token_len && i < 8; i++)
        fprintf(stderr, " %02x", token_der[i]);
    fprintf(stderr, "\n");

    /* Encode OID as full DER (tag+length+value) */
    ASN1_OBJECT *obj = OBJ_txt2obj(TIMESTAMP_TOKEN_OID, 1);
    if (!obj) { fprintf(stderr, "[timestamp] attach: OID failed\n"); return 0; }
    oid_len = i2d_ASN1_OBJECT(obj, NULL);
    if (oid_len <= 0 || oid_len > (int)sizeof(oid_buf)) {
        ASN1_OBJECT_free(obj); return 0;
    }
    unsigned char *op = oid_buf;
    i2d_ASN1_OBJECT(obj, &op);
    ASN1_OBJECT_free(obj);

    /*
     * Build Attribute DER: SEQUENCE { OID, SET { token } }
     * OID goes at SEQUENCE level, BEFORE the SET.
     * Token goes directly into SET (no OCTET STRING wrapper).
     */
    set_body = token_len;
    set_hl = write_tl(tl, 0x31, set_body);  /* measure SET header */
    seq_body = (size_t)oid_len + set_hl + set_body;
    seq_hl = write_tl(tl, 0x30, seq_body);  /* measure SEQ header */
    total = (size_t)seq_hl + seq_body;

    der = (unsigned char *)malloc(total);
    if (!der) return 0;

    p = der;
    write_tl(p, 0x30, seq_body); p += seq_hl;   /* SEQUENCE */
    memcpy(p, oid_buf, oid_len);  p += oid_len; /* OID at SEQ level */
    write_tl(p, 0x31, set_body); p += set_hl;   /* SET */
    memcpy(p, token_der, token_len);              /* token inside SET */

    /* Parse DER into X509_ATTRIBUTE */
    {
        const unsigned char *tp = der;
        attr = d2i_X509_ATTRIBUTE(NULL, &tp, (int)total);
    }
    free(der);

    if (!attr) {
        fprintf(stderr, "[timestamp] attach: d2i_X509_ATTRIBUTE failed\n");
        return 0;
    }

    if (!si->unauth_attr)
        si->unauth_attr = sk_X509_ATTRIBUTE_new_null();

    if (!sk_X509_ATTRIBUTE_push(si->unauth_attr, attr)) {
        X509_ATTRIBUTE_free(attr);
        return 0;
    }

    fprintf(stderr, "[timestamp] attach: done (count=%d)\n",
            sk_X509_ATTRIBUTE_num(si->unauth_attr));
    return 1;
}

/* ------------------------------------------------------------------ */
/* Test connectivity to a TSA server                                  */
/* ------------------------------------------------------------------ */

int timestamp_test_server(const char *url)
{
    if (!url || !url[0]) {
        fprintf(stderr, "[timestamp] test: no URL provided\n");
        return 0;
    }

    fprintf(stderr, "[timestamp] test: connecting to %s ...\n", url);

#ifdef _WIN32
    /* Build a minimal RFC 3161 request using a dummy SHA-256 hash */
    unsigned char dummy_hash[32];
    unsigned char *req_der = NULL;
    size_t req_len = 0;
    unsigned char *http_resp = NULL;
    size_t resp_len = 0;
    unsigned char *token = NULL;
    size_t token_len = 0;

    /* Deterministic dummy hash for testing */
    memset(dummy_hash, 0xAB, sizeof(dummy_hash));

    req_der = build_timestamp_request(dummy_hash, sizeof(dummy_hash),
                                       NID_sha256, &req_len);
    if (!req_der) {
        fprintf(stderr, "[timestamp] test: failed to build request DER\n");
        return 0;
    }

    /* Send HTTP POST */
    http_resp = http_post(url, req_der, req_len, &resp_len, 4000);
    if (!http_resp) {
        fprintf(stderr, "[timestamp] test: HTTP POST failed — "
                        "server unreachable or connection rejected\n");
        free(req_der);
        return 0;
    }

    /* Parse response to verify it's a valid TimeStampResp */
    if (!parse_timestamp_response(http_resp, resp_len, &token, &token_len)) {
        fprintf(stderr, "[timestamp] test: server response invalid "
                        "(not a valid RFC 3161 TimeStampResp)\n");
        free(http_resp);
        free(req_der);
        return 0;
    }

    /* Success: valid timestamp token received */
    fprintf(stderr, "[timestamp] test: SUCCESS — server reachable, "
                    "valid RFC 3161 response (%zu bytes)\n", token_len);
    free(token);
    free(http_resp);
    free(req_der);
    return 1;

#else /* !_WIN32 */
    (void)url;
    fprintf(stderr, "[timestamp] test: WinHTTP required (Windows only)\n");
    return 0;
#endif
}

/* ------------------------------------------------------------------ */
/* Built-in TSA server list trusted by Windows                        */
/* ------------------------------------------------------------------ */

const TSAServer g_tsa_servers[TSA_SERVER_COUNT] = {
    { "DigiCert",     "http://timestamp.digicert.com" },
    { "Sectigo",      "http://timestamp.sectigo.com" },
    { "GlobalSign",   "http://timestamp.globalsign.com/tsa/r6advanced1" },
    { "Entrust",      "http://timestamp.entrust.net/TSS/RFC3161sha2TS" },
    { "IdenTrust",    "http://timestamp.identrust.com" },
    { "Certum",       "http://time.certum.pl" },
};

/* ------------------------------------------------------------------ */
/* Find the fastest TSA server by measuring response latency          */
/* ------------------------------------------------------------------ */

int timestamp_find_fastest(int *out_latency_ms)
{
#ifdef _WIN32
    int best_idx = -1;
    int best_latency = 0;

    fprintf(stderr, "[timestamp] latency test: checking %d servers...\n", TSA_SERVER_COUNT);

    for (int i = 0; i < TSA_SERVER_COUNT; i++) {
        fprintf(stderr, "[timestamp]   [%d/%d] %-12s ", i + 1, TSA_SERVER_COUNT,
                g_tsa_servers[i].label);

        DWORD t0 = GetTickCount();
        int ok = timestamp_test_server(g_tsa_servers[i].url);
        DWORD elapsed = GetTickCount() - t0;

        if (ok) {
            fprintf(stderr, "%lu ms OK\n", elapsed);
            if (best_idx < 0 || (int)elapsed < best_latency) {
                best_idx = i;
                best_latency = (int)elapsed;
            }
        } else {
            fprintf(stderr, "FAILED\n");
        }
    }

    if (best_idx >= 0) {
        fprintf(stderr, "[timestamp] fastest: %s (%s) at %d ms\n",
                g_tsa_servers[best_idx].label,
                g_tsa_servers[best_idx].url,
                best_latency);
        if (out_latency_ms) *out_latency_ms = best_latency;
    } else {
        fprintf(stderr, "[timestamp] all servers unreachable\n");
        if (out_latency_ms) *out_latency_ms = -1;
    }

    return best_idx;
#else
    (void)out_latency_ms;
    fprintf(stderr, "[timestamp] find_fastest: Windows only\n");
    return -1;
#endif
}
