#ifndef PE_FILE_H
#define PE_FILE_H

#include <stdint.h>
#include <stddef.h>

/* PE signature */
#define PE_SIGNATURE 0x00004550  /* "PE\0\0" */
#define MZ_SIGNATURE 0x5A4D      /* "MZ" */

/* Optional Header magic */
#define PE32_MAGIC  0x10B
#define PE64_MAGIC  0x20B

/* Data Directory indices */
#define DIR_CERTIFICATE_TABLE 4

/* WIN_CERTIFICATE */
#define WIN_CERT_REVISION_2_0 0x0200
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA 0x0002

#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;       /* 0x5A4D */
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;      /* Offset to PE signature */
} DOS_HEADER;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} DATA_DIRECTORY;

typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    DATA_DIRECTORY DataDirectory[16];
} OPTIONAL_HEADER_32;

typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    DATA_DIRECTORY DataDirectory[16];
} OPTIONAL_HEADER_64;

typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} SECTION_HEADER;

typedef struct {
    uint32_t dwLength;
    uint16_t wRevision;
    uint16_t wCertificateType;
    /* uint8_t bCertificate[]; follows immediately */
} WIN_CERTIFICATE;

#pragma pack(pop)

/* Parsed PE file in memory */
typedef struct {
    uint8_t  *data;
    size_t    size;

    DOS_HEADER       *dos;
    COFF_HEADER      *coff;
    uint16_t          opt_magic;
    uint32_t         *p_checksum;       /* pointer to CheckSum field in data */
    DATA_DIRECTORY   *cert_dir;         /* pointer to Certificate Table entry */
    SECTION_HEADER   *sections;

    int               is_pe32plus;      /* 1 = 64-bit, 0 = 32-bit */

    /* Existing certificate table (if any) */
    uint32_t          cert_offset;      /* raw file offset, 0 if none */
    uint32_t          cert_size;        /* size including WIN_CERTIFICATE header */
} PE_FILE;

/* Load / free */
PE_FILE* pe_load(const char *path);
void     pe_free(PE_FILE *pe);

/* Queries */
int      pe_is_signed(const PE_FILE *pe);

/* Compute Authenticode hash (skips CheckSum, CertTable entry, cert data) */
int      pe_compute_hash(const PE_FILE *pe,
                          const void *md,       /* EVP_MD* */
                          unsigned char *out_hash,
                          unsigned int *out_len);

/* Attach PKCS#7 DER signature as WIN_CERTIFICATE (8-byte aligned) */
int      pe_attach_signature(PE_FILE *pe,
                              const unsigned char *sig_der,
                              uint32_t sig_len);

/* Recalculate PE checksum */
void     pe_recalc_checksum(PE_FILE *pe);

/* Write modified PE to file */
int      pe_save(const PE_FILE *pe, const char *path);

/* Extract existing signature DER data (caller must free) */
unsigned char* pe_extract_signature(const PE_FILE *pe, uint32_t *out_len);

#endif /* PE_FILE_H */
