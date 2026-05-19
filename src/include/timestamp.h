#ifndef TIMESTAMP_H
#define TIMESTAMP_H

#include <stddef.h>

/* OID for TimeStampToken attribute in PKCS#7 unauthenticated attributes */
#define TIMESTAMP_TOKEN_OID "1.2.840.113549.1.9.16.2.14"

/* Built-in TSA server list — root CAs trusted by Windows */
#define TSA_SERVER_COUNT 6

typedef struct {
    const char *label;  /* Display name */
    const char *url;    /* RFC 3161 endpoint URL */
} TSAServer;

extern const TSAServer g_tsa_servers[TSA_SERVER_COUNT];

/*
 * Request an RFC 3161 timestamp token from a TSA server.
 *
 * digest       — data to timestamp (typically the DER-encoded PKCS#7 content)
 * digest_len   — length of digest
 * algo_nid     — hash algorithm NID (e.g., NID_sha256)
 * url          — TSA server URL
 * out_token    — allocated buffer with DER-encoded TimeStampToken (caller frees)
 * out_len      — length of out_token
 *
 * Returns 1 on success, 0 on failure.
 */
int timestamp_request(const unsigned char *digest, size_t digest_len,
                      int algo_nid, const char *url,
                      unsigned char **out_token, size_t *out_len);

/*
 * Add a timestamp token to a PKCS7 signer's unauthenticated attributes.
 * Creates a shallow copy of the token data (caller must not free until PKCS7 is freed).
 *
 * si           — PKCS7 SignerInfo to modify
 * token_der    — DER-encoded TimeStampToken
 * token_len    — length of token_der
 *
 * Returns 1 on success, 0 on failure.
 */
int timestamp_attach_to_signer(void *si,  /* PKCS7_SIGNER_INFO* */
                               const unsigned char *token_der,
                               size_t token_len);

/*
 * Test connectivity to a TSA server by sending a minimal RFC 3161 request
 * and verifying a valid response is received.
 *
 * url  — TSA server URL to test
 *
 * Returns 1 if the server is reachable and responds correctly, 0 on failure.
 * Prints diagnostic messages to stderr.
 */
int timestamp_test_server(const char *url);

/*
 * Test all built-in TSA servers and return index of the fastest.
 * Sets *out_latency_ms to the latency of the fastest server.
 * Returns -1 if all servers are unreachable.
 */
int timestamp_find_fastest(int *out_latency_ms);

#endif /* TIMESTAMP_H */
