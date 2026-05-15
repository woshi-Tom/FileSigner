#include "file_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#define PATH_SEPARATOR "\\"
#define strcasecmp _stricmp
#define strdup _strdup
#define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)

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

/* Convert UTF-8 to wide string. Caller frees returned buffer. */
static wchar_t *utf8_to_wide(const char *str)
{
    if (!str || !str[0]) return wcsdup(L"");
    int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (len <= 0) return wcsdup(L"");
    wchar_t *buf = (wchar_t *)malloc(len * sizeof(wchar_t));
    if (!buf) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, str, -1, buf, len);
    return buf;
}

/* UTF-8 aware stat for Windows */
static int stat_utf8(const char *path, struct stat *st)
{
    wchar_t *wpath = utf8_to_wide(path);
    if (!wpath) return -1;
    int ret = _wstat(wpath, st);
    free(wpath);
    return ret;
}

/* UTF-8 aware fopen for Windows (public, supports Chinese paths) */
FILE *fopen_utf8(const char *path, const char *mode)
{
    wchar_t *wpath = utf8_to_wide(path);
    if (!wpath) return NULL;
    wchar_t wmode[8];
    MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, 8);
    FILE *f = _wfopen(wpath, wmode);
    free(wpath);
    return f;
}

/* UTF-8 aware mkdir for Windows */
static int mkdir_utf8(const char *path)
{
    wchar_t *wpath = utf8_to_wide(path);
    if (!wpath) return -1;
    int ret = _wmkdir(wpath);
    free(wpath);
    return ret;
}

wchar_t *utf8_to_wide_public(const char *str)
{
    return utf8_to_wide(str);
}
#else
#include <dirent.h>
#define PATH_SEPARATOR "/"
#endif

#define MAX_PATH_LEN 4096

int file_exists(const char* path) {
    struct stat st;
#ifdef _WIN32
    return (stat_utf8(path, &st) == 0 && S_ISREG(st.st_mode));
#else
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
#endif
}

int directory_exists(const char* path) {
    struct stat st;
#ifdef _WIN32
    return (stat_utf8(path, &st) == 0 && S_ISDIR(st.st_mode));
#else
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
#endif
}

int create_directory(const char* path) {
    if (directory_exists(path)) {
        return 1;
    }

    char tmp[MAX_PATH_LEN];
    char* p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);

    if (tmp[len - 1] == '/' || tmp[len - 1] == '\\') {
        tmp[len - 1] = '\0';
    }

    for (p = tmp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            *p = '\0';
            if (!directory_exists(tmp)) {
#ifdef _WIN32
                if (mkdir_utf8(tmp) != 0) {
#else
                if (mkdir(tmp, 0755) != 0) {
#endif
                    return 0;
                }
            }
            *p = '/';
        }
    }

#ifdef _WIN32
    return mkdir_utf8(tmp) == 0;
#else
    return mkdir(tmp, 0755) == 0;
#endif
}

long get_file_size(const char* filename) {
    struct stat st;
#ifdef _WIN32
    if (stat_utf8(filename, &st) == 0) {
#else
    if (stat(filename, &st) == 0) {
#endif
        return st.st_size;
    }
    return -1;
}

unsigned char* read_file(const char* filename, size_t* size) {
#ifdef _WIN32
    FILE* file = fopen_utf8(filename, "rb");
#else
    FILE* file = fopen(filename, "rb");
#endif
    if (!file) {
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size <= 0) {
        fclose(file);
        return NULL;
    }

    unsigned char* buffer = (unsigned char*)malloc(file_size + 1);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    size_t bytes_read = fread(buffer, 1, file_size, file);
    fclose(file);

    if (bytes_read != (size_t)file_size) {
        free(buffer);
        return NULL;
    }

    buffer[file_size] = '\0';
    if (size) {
        *size = file_size;
    }

    return buffer;
}

int write_file(const char* filename, const unsigned char* data, size_t size) {
#ifdef _WIN32
    FILE* file = fopen_utf8(filename, "wb");
#else
    FILE* file = fopen(filename, "wb");
#endif
    if (!file) {
        return 0;
    }

    size_t bytes_written = fwrite(data, 1, size, file);
    fclose(file);

    return bytes_written == size;
}

const char* get_file_extension(const char* filename) {
    const char* dot = strrchr(filename, '.');
    if (!dot || dot == filename) {
        return "";
    }
    return dot + 1;
}

int has_extension(const char* filename, const char* extension) {
    const char* ext = get_file_extension(filename);
    return strcasecmp(ext, extension) == 0;
}

FileList* get_files_in_directory(const char* directory,
    const char* extension_filter) {

    FileList* list = (FileList*)malloc(sizeof(FileList));
    if (!list) return NULL;

    list->files = NULL;
    list->count = 0;
    list->capacity = 0;

#ifdef _WIN32
    /* Convert UTF-8 directory to wide string for W API */
    int wlen_dir = MultiByteToWideChar(CP_UTF8, 0, directory, -1, NULL, 0);
    if (wlen_dir <= 0) { free(list); return NULL; }
    wchar_t *wdir = (wchar_t *)malloc(wlen_dir * sizeof(wchar_t));
    if (!wdir) { free(list); return NULL; }
    MultiByteToWideChar(CP_UTF8, 0, directory, -1, wdir, wlen_dir);

    wchar_t search_pattern[MAX_PATH_LEN];
    _snwprintf(search_pattern, MAX_PATH_LEN, L"%s\\*", wdir);
    free(wdir);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search_pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        free(list);
        return NULL;
    }

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        /* Convert filename to UTF-8 */
        char *fname_utf8 = wide_to_utf8(fd.cFileName);
        if (!fname_utf8) continue;

        if (extension_filter && strlen(extension_filter) > 0) {
            if (!has_extension(fname_utf8, extension_filter)) {
                free(fname_utf8);
                continue;
            }
        }

        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s\\%s", directory, fname_utf8);
        free(fname_utf8);

        if (list->count >= list->capacity) {
            size_t new_capacity = list->capacity == 0 ? 16 : list->capacity * 2;
            char** new_files = realloc(list->files, new_capacity * sizeof(char*));
            if (!new_files) {
                free_file_list(list);
                FindClose(hFind);
                return NULL;
            }
            list->files = new_files;
            list->capacity = new_capacity;
        }

        list->files[list->count] = strdup(path);
        if (!list->files[list->count]) {
            free_file_list(list);
            FindClose(hFind);
            return NULL;
        }
        list->count++;
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
#else
    DIR* dir = opendir(directory);
    if (!dir) {
        free(list);
        return NULL;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);

        struct stat st;
        if (stat(path, &st) != 0) continue;
        if (!S_ISREG(st.st_mode)) continue;

        if (extension_filter && strlen(extension_filter) > 0) {
            if (!has_extension(entry->d_name, extension_filter))
                continue;
        }

        if (list->count >= list->capacity) {
            size_t new_capacity = list->capacity == 0 ? 16 : list->capacity * 2;
            char** new_files = realloc(list->files, new_capacity * sizeof(char*));
            if (!new_files) {
                free_file_list(list);
                closedir(dir);
                return NULL;
            }
            list->files = new_files;
            list->capacity = new_capacity;
        }

        list->files[list->count] = strdup(path);
        if (!list->files[list->count]) {
            free_file_list(list);
            closedir(dir);
            return NULL;
        }
        list->count++;
    }

    closedir(dir);
#endif

    return list;
}

void free_file_list(FileList* list) {
    if (list) {
        for (size_t i = 0; i < list->count; i++) {
            free(list->files[i]);
        }
        free(list->files);
        free(list);
    }
}

char* get_basename(const char* path) {
    const char* slash = strrchr(path, '/');
    if (!slash) {
        slash = strrchr(path, '\\');
    }

    if (slash) {
        return strdup(slash + 1);
    }
    else {
        return strdup(path);
    }
}

char* get_dirname(const char* path) {
    char* result = strdup(path);
    if (!result) return NULL;

    char* slash = strrchr(result, '/');
    if (!slash) {
        slash = strrchr(result, '\\');
    }

    if (slash) {
        *slash = '\0';
    }
    else {
        free(result);
        result = strdup(".");
    }

    return result;
}

char* path_join(const char* dir, const char* file) {
    size_t dir_len = strlen(dir);
    size_t file_len = strlen(file);
    size_t total_len = dir_len + file_len + 2;

    char* result = (char*)malloc(total_len);
    if (!result) return NULL;

    snprintf(result, total_len, "%s/%s", dir, file);
    return result;
}
