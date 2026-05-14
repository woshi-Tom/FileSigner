#ifndef CERT_GEN_H
#define CERT_GEN_H

/* Default validity periods (days) */
#define CERT_CA_DEFAULT_DAYS       3650   /* 10 years */
#define CERT_SIGNER_DEFAULT_DAYS   90     /* 90 days */

/* Fixed certificate subject names */
#define CERT_CA_CN      "FileSigner Root CA"
#define CERT_SIGNER_CN  "FileSigner Code Signing"

/*
 * Generate a self-signed Root CA + code signing certificate + PFX.
 *
 * output_dir     — directory to write files into
 * ca_password    — password to encrypt CA private key (NULL = no password)
 * signer_password — password to encrypt PFX
 * validity_days  — code signing cert validity in days (0 = default 90)
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
                  int validity_days);

#endif /* CERT_GEN_H */
