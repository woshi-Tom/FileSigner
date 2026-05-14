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
 * Returns number of files successfully signed, or -1 on error.
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

#endif /* BATCH_SIGNER_H */
