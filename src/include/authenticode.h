#ifndef AUTHENTICODE_H
#define AUTHENTICODE_H

/*
 * Authenticode signing and verification.
 * Uses OpenSSL to build PKCS#7 SignedData conforming to the
 * Microsoft Authenticode specification, then embeds the signature
 * into the PE file's Certificate Table (WIN_CERTIFICATE).
 */

/* OID strings for Authenticode */
#define SPC_PE_IMAGE_DATA_OID    "1.3.6.1.4.1.311.2.1.15"
#define SPC_SP_OPUS_INFO_OID     "1.3.6.1.4.1.311.2.1.12"
#define SPC_STATEMENT_TYPE_OID   "1.3.6.1.4.1.311.2.1.11"
#define SPC_INDIVIDUAL_PURPOSE   "1.3.6.1.4.1.311.2.1.21"

/*
 * Status callback for progress reporting during signing.
 * Called at each major step so the caller can update UI / process messages.
 */
typedef void (*authenticode_status_cb)(const char *status, void *user_data);

/*
 * Sign a PE file with Authenticode.
 *
 * pe_path         — path to the PE (EXE/DLL) file
 * pfx_path        — path to PFX/P12 file (contains cert + key + chain)
 * pfx_password    — PFX password
 * timestamp_url   — RFC 3161 timestamp server URL (NULL to skip timestamping)
 * output_path     — output path for signed PE (NULL = overwrite original)
 * status_cb       — optional progress callback (NULL = no callback)
 * cb_data         — user data for callback
 *
 * Returns 1 on success, 0 on failure.
 */
int authenticode_sign(const char *pe_path,
                      const char *pfx_path,
                      const char *pfx_password,
                      const char *timestamp_url,
                      const char *output_path,
                      authenticode_status_cb status_cb,
                      void *cb_data);

/*
 * Verify an Authenticode-signed PE file.
 *
 * pe_path   — path to signed PE file
 * ca_path   — path to trusted CA certificate (NULL = skip chain verification)
 *
 * Returns 1 if signature is valid, 0 otherwise.
 */
int authenticode_verify(const char *pe_path, const char *ca_path);

/*
 * Verify an Authenticode-signed PE file with status callbacks.
 *
 * pe_path   — path to signed PE file
 * ca_path   — path to trusted CA certificate (NULL = skip chain verification)
 * status_cb — optional progress callback (NULL = no callback)
 * cb_data   — user data for callback
 *
 * Returns 1 if signature is valid, 0 otherwise.
 */
int authenticode_verify_ex(const char *pe_path, const char *ca_path,
                           authenticode_status_cb status_cb, void *cb_data);

/*
 * Check if a PE file has an Authenticode signature
 * (does not validate, just checks presence).
 *
 * Returns 1 if signed, 0 if not, -1 on error.
 */
int authenticode_is_signed(const char *pe_path);

#endif /* AUTHENTICODE_H */
