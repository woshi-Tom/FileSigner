#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <stdlib.h>

// 文件列表结构体
typedef struct {
    char** files;        // 文件路径数组
    size_t count;        // 文件数量
    size_t capacity;     // 数组容量
} FileList;

// 文件操作函数
int file_exists(const char* path);
int directory_exists(const char* path);
int create_directory(const char* path);
long get_file_size(const char* filename);

unsigned char* read_file(const char* filename, size_t* size);
int write_file(const char* filename, const unsigned char* data, size_t size);

const char* get_file_extension(const char* filename);
int has_extension(const char* filename, const char* extension);

FileList* get_files_in_directory(const char* directory,
    const char* extension_filter);
void free_file_list(FileList* list);

char* get_basename(const char* path);
char* get_dirname(const char* path);
char* path_join(const char* dir, const char* file);

#endif // FILE_UTILS_H