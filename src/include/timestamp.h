#ifndef TIMESTAMP_H
#define TIMESTAMP_H

#include <stddef.h>

/* OID for TimeStampToken attribute in PKCS#7 unauthenticated attributes */
#define TIMESTAMP_TOKEN_OID "1.2.840.113549.1.9.16.2.14"

/* Common timestamp server URLs */
#define TIMESTAMP_URL_DIGICERT  "http://timestamp.digicert.com"
#define TIMESTAMP_URL_COMODO    "http://timestamp.sectigo.com"
#define TIMESTAMP_URL_GLOBALSIGN "http://timestamp.globalsign.com/tsa/r6advanced"

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

#endif /* TIMESTAMP_H */
