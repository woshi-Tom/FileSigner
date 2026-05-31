#ifndef CERT_GEN_H
#define CERT_GEN_H

/* Default validity periods (days) */
#define CERT_CA_DEFAULT_DAYS       3650   /* 10 years */
#define CERT_SIGNER_DEFAULT_DAYS   90     /* 90 days */

/* Fixed certificate subject names */
#define CERT_CA_CN      "FileSigner Root CA"
#define CERT_SIGNER_CN  "FileSigner Code Signing"

/* Status callback for progress reporting */
typedef void (*cert_status_cb)(const char *status, void *user_data);

/*
 * Generate a self-signed Root CA + code signing certificate + PFX.
 *
 * output_dir     — directory to write files into
 * ca_password    — password to encrypt CA private key (NULL = no password)
 * signer_password — password to encrypt PFX
 * validity_days  — code signing cert validity in days (0 = default 90)
 * signer_cn      — custom CN for signer cert (NULL = default "FileSigner Code Signing")
 * signer_email   — email for SubjectAlternativeName (NULL = skip)
 *
 * Writes:
 *   FileSigner_RootCA.cer
 *   FileSigner_RootCA.key
 *   FileSigner_Signer.cer
 *   FileSigner_Signer.key
 *   FileSigner_Signer.pfx
 *
 * Returns 1 on success, 0 on failure.
 */
int cert_generate(const char *output_dir,
                  const char *ca_password,
                  const char *signer_password,
                  int validity_days,
                  const char *signer_cn,
                  const char *signer_email);

/*
 * Same as cert_generate but with status callback for progress reporting.
 */
int cert_generate_ex(const char *output_dir,
                     const char *ca_password,
                     const char *signer_password,
                     int validity_days,
                     const char *signer_cn,
                     const char *signer_email,
                     cert_status_cb status_cb,
                     void *cb_data);

#endif /* CERT_GEN_H */
