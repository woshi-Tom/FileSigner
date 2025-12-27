#include "file_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif

#define MAX_PATH_LEN 4096

// 检查文件是否存在
int file_exists(const char* path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
}

// 检查目录是否存在
int directory_exists(const char* path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

// 创建目录（包括父目录）
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

// 获取文件大小
long get_file_size(const char* filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_size;
    }
    return -1;
}

// 读取文件内容
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

// 写入文件内容
int write_file(const char* filename, const unsigned char* data, size_t size) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        return 0;
    }

    size_t bytes_written = fwrite(data, 1, size, file);
    fclose(file);

    return bytes_written == size;
}

// 获取文件扩展名
const char* get_file_extension(const char* filename) {
    const char* dot = strrchr(filename, '.');
    if (!dot || dot == filename) {
        return "";
    }
    return dot + 1;
}

// 检查文件是否匹配扩展名
int has_extension(const char* filename, const char* extension) {
    const char* ext = get_file_extension(filename);
    return strcasecmp(ext, extension) == 0;
}

// 获取目录中的文件列表
FileList* get_files_in_directory(const char* directory,
    const char* extension_filter) {
    DIR* dir = opendir(directory);
    if (!dir) {
        return NULL;
    }

    FileList* list = (FileList*)malloc(sizeof(FileList));
    if (!list) {
        closedir(dir);
        return NULL;
    }

    list->files = NULL;
    list->count = 0;
    list->capacity = 0;

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        // 跳过 . 和 ..
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // 构建完整路径
        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);

        struct stat st;
        if (stat(path, &st) != 0) {
            continue;
        }

        // 只处理普通文件
        if (!S_ISREG(st.st_mode)) {
            continue;
        }

        // 应用扩展名过滤器
        if (extension_filter && strlen(extension_filter) > 0) {
            if (!has_extension(entry->d_name, extension_filter)) {
                continue;
            }
        }

        // 添加到列表
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
    return list;
}

// 释放文件列表
void free_file_list(FileList* list) {
    if (list) {
        for (size_t i = 0; i < list->count; i++) {
            free(list->files[i]);
        }
        free(list->files);
        free(list);
    }
}

// 获取文件名（不包含路径）
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

// 获取目录名
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

// 连接路径
char* path_join(const char* dir, const char* file) {
    size_t dir_len = strlen(dir);
    size_t file_len = strlen(file);
    size_t total_len = dir_len + file_len + 2;

    char* result = (char*)malloc(total_len);
    if (!result) return NULL;

    snprintf(result, total_len, "%s/%s", dir, file);
    return result;
}