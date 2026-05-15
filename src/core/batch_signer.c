#include "batch_signer.h"
#include "authenticode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define PATH_SEP '\\'
#define strdup _strdup

/* Convert wide string (UTF-16) to UTF-8. Caller frees returned buffer. */
static char *wide_to_utf8(const wchar_t *wstr)
{
    if (!wstr || !wstr[0]) return strdup("");
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return strdup("");
    char *buf = (char *)malloc(len);
    if (!buf) return NULL;
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, buf, len, NULL, NULL);
    return buf;
}
#else
#include <dirent.h>
#include <sys/stat.h>
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
#ifdef _WIN32
    /* Convert UTF-8 dir_path to wide for W API */
    int wlen = MultiByteToWideChar(CP_UTF8, 0, dir_path, -1, NULL, 0);
    if (wlen <= 0) return;
    wchar_t *wdir = (wchar_t *)malloc(wlen * sizeof(wchar_t));
    if (!wdir) return;
    MultiByteToWideChar(CP_UTF8, 0, dir_path, -1, wdir, wlen);

    wchar_t search_pattern[MAX_PATH_LEN];
    _snwprintf(search_pattern, MAX_PATH_LEN, L"%s\\*", wdir);
    free(wdir);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search_pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;

        /* Convert filename to UTF-8 */
        char *fname_utf8 = wide_to_utf8(fd.cFileName);
        if (!fname_utf8) continue;

        char fullpath[MAX_PATH_LEN];
        snprintf(fullpath, sizeof(fullpath), "%s\\%s", dir_path, fname_utf8);
        free(fname_utf8);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (recursive)
                scan_directory(fullpath, recursive, list);
        } else {
            const wchar_t *ext = wcsrchr(fd.cFileName, L'.');
            if (ext && _wcsicmp(ext, L".exe") == 0) {
                pe_list_add(list, fullpath);
            }
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
#else
    DIR *dir;
    struct dirent *entry;
    char fullpath[MAX_PATH_LEN];

    dir = opendir(dir_path);
    if (!dir) return;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_path, entry->d_name);

        struct stat st;
        if (stat(fullpath, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            if (recursive)
                scan_directory(fullpath, recursive, list);
        } else if (S_ISREG(st.st_mode)) {
            const char *ext = strrchr(entry->d_name, '.');
            if (ext && strcasecmp(ext, ".exe") == 0) {
                pe_list_add(list, fullpath);
            }
        }
    }
    closedir(dir);
#endif
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
