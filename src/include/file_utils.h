#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#endif

typedef struct {
    char** files;
    size_t count;
    size_t capacity;
} FileList;

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

#ifdef _WIN32
/* UTF-8 to wide string conversion. Caller frees returned buffer. */
wchar_t* utf8_to_wide_public(const char* str);

/* UTF-8 aware fopen for Windows (supports Chinese paths). */
FILE* fopen_utf8(const char* path, const char* mode);
#else
#define fopen_utf8 fopen
#endif

#endif /* FILE_UTILS_H */
