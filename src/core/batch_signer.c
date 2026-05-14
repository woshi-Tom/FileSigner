#include "batch_signer.h"
#include "authenticode.h"
#include "file_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#define PATH_SEP '\\'
#else
#define PATH_SEP '/'
#endif

#define MAX_PATH_LEN 4096

/* Collect PE files into a list */
typedef struct {
    char **files;
    int    count;
    int    capacity;
} PEList;

static void pe_list_init(PEList *list)
{
    list->files = NULL;
    list->count = 0;
    list->capacity = 0;
}

static void pe_list_free(PEList *list)
{
    for (int i = 0; i < list->count; i++)
        free(list->files[i]);
    free(list->files);
}

static int pe_list_add(PEList *list, const char *path)
{
    if (list->count >= list->capacity) {
        int new_cap = list->capacity == 0 ? 32 : list->capacity * 2;
        char **tmp = (char **)realloc(list->files, new_cap * sizeof(char *));
        if (!tmp) return 0;
        list->files = tmp;
        list->capacity = new_cap;
    }
    list->files[list->count] = strdup(path);
    if (!list->files[list->count]) return 0;
    list->count++;
    return 1;
}

/* Scan directory for .exe files */
static void scan_directory(const char *dir_path, int recursive, PEList *list)
{
    DIR *dir;
    struct dirent *entry;
    char fullpath[MAX_PATH_LEN];

    dir = opendir(dir_path);
    if (!dir) return;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath, sizeof(fullpath), "%s%c%s", dir_path, PATH_SEP, entry->d_name);

        struct stat st;
        if (stat(fullpath, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            if (recursive)
                scan_directory(fullpath, recursive, list);
        } else if (S_ISREG(st.st_mode)) {
            /* Check if .exe extension */
            const char *ext = strrchr(entry->d_name, '.');
            if (ext && _stricmp(ext, ".exe") == 0) {
                pe_list_add(list, fullpath);
            }
        }
    }

    closedir(dir);
}

/* ------------------------------------------------------------------ */

int batch_sign(const char *dir_path,
               const char *pfx_path,
               const char *pfx_password,
               const char *timestamp_url,
               const char *output_dir,
               int force,
               int recursive,
               batch_progress_cb cb,
               void *cb_data)
{
    PEList list;
    int signed_count = 0;
    char outpath[MAX_PATH_LEN];

    pe_list_init(&list);

    /* Scan for PE files */
    scan_directory(dir_path, recursive, &list);

    if (list.count == 0) {
        printf("No .exe files found in: %s\n", dir_path);
        return 0;
    }

    printf("Found %d .exe file(s)\n", list.count);

    /* Process each file */
    for (int i = 0; i < list.count; i++) {
        const char *filepath = list.files[i];
        const char *filename = strrchr(filepath, PATH_SEP);
        filename = filename ? filename + 1 : filepath;

        /* Notify progress */
        if (cb) cb(filename, i + 1, list.count, -1, cb_data);

        /* Check if already signed */
        int is_signed = authenticode_is_signed(filepath);
        if (is_signed == 1 && !force) {
            printf("  [%d/%d] Skip (already signed): %s\n",
                   i + 1, list.count, filename);
            if (cb) cb(filename, i + 1, list.count, 0, cb_data);
            continue;
        }

        /* Determine output path */
        const char *out;
        if (output_dir) {
            snprintf(outpath, sizeof(outpath), "%s%c%s", output_dir, PATH_SEP, filename);
            out = outpath;
        } else {
            out = filepath;
        }

        /* Sign */
        printf("  [%d/%d] Signing: %s\n", i + 1, list.count, filename);

        if (authenticode_sign(filepath, pfx_path, pfx_password, timestamp_url, out)) {
            signed_count++;
            if (cb) cb(filename, i + 1, list.count, 1, cb_data);
        } else {
            fprintf(stderr, "  [%d/%d] Failed: %s\n", i + 1, list.count, filename);
            if (cb) cb(filename, i + 1, list.count, 0, cb_data);
        }
    }

    pe_list_free(&list);
    return signed_count;
}
