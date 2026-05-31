#ifndef BATCH_SIGNER_H
#define BATCH_SIGNER_H

/* Progress callback: called for each file processed */
typedef void (*batch_progress_cb)(const char *filename,
                                   int current, int total,
                                   int success, void *user_data);

/*
 * Batch-sign all PE files in a directory.
 *
 * dir_path        — directory to scan (non-recursive unless recursive=1)
 * pfx_path        — path to PFX/P12 file
 * pfx_password    — PFX password
 * timestamp_url   — TSA URL (NULL to skip)
 * output_dir      — output directory (NULL = overwrite originals)
 * force           — re-sign already-signed files
 * recursive       — scan subdirectories
 * cb              — progress callback (NULL = no callback)
 * cb_data         — user data passed to callback
 *
 * Returns number of files successfully signed.
 *         0 if all files were already signed (skipped).
 *        -1 if no PE files found in directory.
 */
int batch_sign(const char *dir_path,
               const char *pfx_path,
               const char *pfx_password,
               const char *timestamp_url,
               const char *output_dir,
               int force,
               int recursive,
               batch_progress_cb cb,
               void *cb_data);

/*
 * Batch-verify Authenticode signatures of all PE files in a directory.
 *
 * dir_path   — directory to scan
 * ca_path    — CA certificate for chain verification (NULL = skip chain check)
 * recursive  — scan subdirectories
 * cb         — progress callback (NULL = no callback)
 * cb_data    — user data passed to callback
 *
 * Callback success values:
 *   1  = signature valid
 *   0  = signature invalid or verification failed
 *  -1  = not signed (no signature found)
 *  -2  = skipped (already reported)
 *  -3  = info message
 *  -4  = per-file status detail
 *
 * Returns number of files with valid signatures.
 *         0 if no files had valid signatures.
 *        -1 if no PE files found in directory.
 */
int batch_verify(const char *dir_path,
                 const char *ca_path,
                 int recursive,
                 batch_progress_cb cb,
                 void *cb_data);

#endif /* BATCH_SIGNER_H */
