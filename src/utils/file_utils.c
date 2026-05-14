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
#else
#include <dirent.h>
#define PATH_SEPARATOR "/"
#endif

#define MAX_PATH_LEN 4096

int file_exists(const char* path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
}

int directory_exists(const char* path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
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
                if (mkdir(tmp, 0755) != 0) {
                    return 0;
                }
            }
            *p = '/';
        }
    }

    return mkdir(tmp, 0755) == 0;
}

long get_file_size(const char* filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_size;
    }
    return -1;
}

unsigned char* read_file(const char* filename, size_t* size) {
    FILE* file = fopen(filename, "rb");
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
    FILE* file = fopen(filename, "wb");
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
    char search_pattern[MAX_PATH_LEN];
    WIN32_FIND_DATAA fd;
    HANDLE hFind;

    snprintf(search_pattern, sizeof(search_pattern), "%s\\*", directory);
    hFind = FindFirstFileA(search_pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        free(list);
        return NULL;
    }

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        if (extension_filter && strlen(extension_filter) > 0) {
            if (!has_extension(fd.cFileName, extension_filter))
                continue;
        }

        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s\\%s", directory, fd.cFileName);

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
    } while (FindNextFileA(hFind, &fd));

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
