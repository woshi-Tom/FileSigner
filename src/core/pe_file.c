#include "pe_file.h"
#include "file_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

/*
 * Partial CheckSum calculation (for PE files).
 * Accumulates 16-bit words, folding carries.  The existing checksum field
 * in the file is treated as zero during computation.
 */
static uint32_t calc_checksum(const uint8_t *data, size_t size,
                               size_t checksum_offset)
{
    uint64_t sum = 0;
    size_t   i;

    for (i = 0; i + 1 < size; i += 2) {
        if (i == checksum_offset)
            continue;                       /* skip existing checksum */
        if (i == checksum_offset + 2)
            continue;
        sum += (uint32_t)data[i] | ((uint32_t)data[i + 1] << 8);
        if (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (size & 1)
        sum += (uint32_t)data[size - 1];

    /* Standard CheckSumMappedFile folds file size (as DWORD) into the result */
    sum += (uint32_t)size;
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += (sum >> 16);
    return (uint32_t)(sum & 0xFFFF);
}

/* ------------------------------------------------------------------ */

PE_FILE* pe_load(const char *path)
{
    size_t file_size;
    uint8_t *raw;
    PE_FILE *pe;
    uint32_t pe_offset;
    uint32_t opt_offset;
    uint16_t num_dirs;

    raw = read_file(path, &file_size);
    if (!raw)
        return NULL;

    /* Minimum size check */
    if (file_size < sizeof(DOS_HEADER) + 4 + sizeof(COFF_HEADER)) {
        free(raw);
        return NULL;
    }

    /* Allocate */
    pe = (PE_FILE *)calloc(1, sizeof(PE_FILE));
    if (!pe) { free(raw); return NULL; }

    pe->data = raw;
    pe->size = file_size;

    /* DOS header */
    pe->dos = (DOS_HEADER *)raw;
    if (pe->dos->e_magic != MZ_SIGNATURE) {
        pe_free(pe);
        return NULL;
    }

    /* PE signature */
    pe_offset = pe->dos->e_lfanew;
    if (pe_offset < sizeof(DOS_HEADER) ||   /* must be past DOS header */
        pe_offset + 4 > file_size ||
        *(uint32_t *)(raw + pe_offset) != PE_SIGNATURE) {
        pe_free(pe);
        return NULL;
    }

    /* COFF header */
    pe->coff = (COFF_HEADER *)(raw + pe_offset + 4);

    /* Optional header */
    opt_offset = pe_offset + 4 + sizeof(COFF_HEADER);
    if (opt_offset + 2 > file_size) { pe_free(pe); return NULL; }

    pe->opt_magic = *(uint16_t *)(raw + opt_offset);
    if (pe->opt_magic == PE32_MAGIC) {
        OPTIONAL_HEADER_32 *opt;
        if (opt_offset + sizeof(OPTIONAL_HEADER_32) > file_size) {
            pe_free(pe); return NULL;
        }
        opt = (OPTIONAL_HEADER_32 *)(raw + opt_offset);
        pe->is_pe32plus = 0;
        pe->p_checksum  = &opt->CheckSum;
        num_dirs        = opt->NumberOfRvaAndSizes;
        if (num_dirs > DIR_CERTIFICATE_TABLE + 1)
            pe->cert_dir = &opt->DataDirectory[DIR_CERTIFICATE_TABLE];
    } else if (pe->opt_magic == PE64_MAGIC) {
        OPTIONAL_HEADER_64 *opt;
        if (opt_offset + sizeof(OPTIONAL_HEADER_64) > file_size) {
            pe_free(pe); return NULL;
        }
        opt = (OPTIONAL_HEADER_64 *)(raw + opt_offset);
        pe->is_pe32plus = 1;
        pe->p_checksum  = &opt->CheckSum;
        num_dirs        = opt->NumberOfRvaAndSizes;
        if (num_dirs > DIR_CERTIFICATE_TABLE + 1)
            pe->cert_dir = &opt->DataDirectory[DIR_CERTIFICATE_TABLE];
    } else {
        pe_free(pe);
        return NULL;
    }

    /* Section headers */
    pe->sections = (SECTION_HEADER *)(raw + opt_offset + pe->coff->SizeOfOptionalHeader);

    /* Certificate table */
    if (pe->cert_dir && pe->cert_dir->VirtualAddress && pe->cert_dir->Size) {
        pe->cert_offset = pe->cert_dir->VirtualAddress; /* RVA = raw offset for certs */
        pe->cert_size   = pe->cert_dir->Size;
        if (pe->cert_offset + pe->cert_size > file_size) {
            /* Invalid cert table, ignore */
            pe->cert_offset = 0;
            pe->cert_size   = 0;
        }
    }

    return pe;
}

void pe_free(PE_FILE *pe)
{
    if (pe) {
        free(pe->data);
        free(pe);
    }
}

int pe_is_signed(const PE_FILE *pe)
{
    WIN_CERTIFICATE *wcert;

    if (!pe || !pe->cert_offset || pe->cert_size < sizeof(WIN_CERTIFICATE))
        return 0;

    /* Bounds check */
    if (pe->cert_offset + sizeof(WIN_CERTIFICATE) > pe->size)
        return 0;

    wcert = (WIN_CERTIFICATE *)(pe->data + pe->cert_offset);

    /* Validate certificate type and length */
    if (wcert->wCertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA)
        return 0;
    if (wcert->dwLength < sizeof(WIN_CERTIFICATE) || wcert->dwLength > pe->cert_size)
        return 0;

    return 1;
}

/*
 * Compute Authenticode hash.
 * Hash data in sequential chunks, skipping:
 *   1) the CheckSum field (8 bytes at offset from file start)
 *   2) the Certificate Table DATA_DIRECTORY entry (8 bytes)
 *   3) the certificate data at the end of the file
 *
 * We build a sorted list of skip ranges, then walk through the file
 * hashing only the non-skipped parts.
 */
typedef struct {
    size_t start;
    size_t end;   /* exclusive */
} SKIP_RANGE;

static int cmp_skip(const void *a, const void *b)
{
    const SKIP_RANGE *sa = (const SKIP_RANGE *)a;
    const SKIP_RANGE *sb = (const SKIP_RANGE *)b;
    if (sa->start < sb->start) return -1;
    if (sa->start > sb->start) return 1;
    return 0;
}

int pe_compute_hash(const PE_FILE *pe, const void *md,
                     unsigned char *out_hash, unsigned int *out_len)
{
    SKIP_RANGE skips[3];
    int nskip = 0;
    size_t i;

    /* CheckSum offset from file start */
    size_t checksum_off = (size_t)((uint8_t *)pe->p_checksum - pe->data);
    skips[nskip].start = checksum_off;
    skips[nskip].end   = checksum_off + 4;
    nskip++;

    /* Certificate Table entry offset from file start */
    if (pe->cert_dir) {
        size_t certdir_off = (size_t)((uint8_t *)pe->cert_dir - pe->data);
        skips[nskip].start = certdir_off;
        skips[nskip].end   = certdir_off + sizeof(DATA_DIRECTORY);
        nskip++;
    }

    /* Certificate data */
    if (pe->cert_offset && pe->cert_size) {
        skips[nskip].start = pe->cert_offset;
        skips[nskip].end   = pe->cert_offset + pe->cert_size;
        nskip++;
    }

    qsort(skips, nskip, sizeof(SKIP_RANGE), cmp_skip);

    /* Use OpenSSL EVP to hash */
    {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) return 0;

        if (EVP_DigestInit_ex(ctx, (const EVP_MD *)md, NULL) != 1) {
            EVP_MD_CTX_free(ctx);
            return 0;
        }

        size_t pos = 0;
        for (i = 0; i < (size_t)nskip; i++) {
            if (skips[i].start > pos) {
                EVP_DigestUpdate(ctx, pe->data + pos, skips[i].start - pos);
            }
            pos = skips[i].end;
        }
        if (pos < pe->size) {
            EVP_DigestUpdate(ctx, pe->data + pos, pe->size - pos);
        }

        EVP_DigestFinal_ex(ctx, out_hash, out_len);
        EVP_MD_CTX_free(ctx);
    }

    return 1;
}

/*
 * Attach a PKCS#7 DER signature to the PE file.
 * Creates/replaces the WIN_CERTIFICATE structure at the end of the file.
 */
int pe_attach_signature(PE_FILE *pe, const unsigned char *sig_der, uint32_t sig_len)
{
    /* Calculate new cert table size: WIN_CERTIFICATE header + DER data, 8-byte aligned */
    uint32_t total_size = sizeof(WIN_CERTIFICATE) + sig_len;
    uint32_t aligned = (total_size + 7) & ~7u;

    /* Determine where to place the certificate table.
     * If there's an existing one, replace it (in-place if big enough, else relocate).
     * Otherwise append to end of file. */
    size_t new_file_size;
    uint8_t *new_data;
    size_t cert_write_offset;

    if (pe->cert_offset && pe->cert_size) {
        if (aligned <= pe->cert_size) {
            /* Fits in existing space — reuse */
            cert_write_offset = pe->cert_offset;
            /* Zero out old area */
            memset(pe->data + cert_write_offset, 0, pe->cert_size);
            new_file_size = pe->size;
        } else {
            /* Need to append */
            cert_write_offset = pe->size;
            new_file_size = pe->size + aligned;
            new_data = (uint8_t *)realloc(pe->data, new_file_size);
            if (!new_data) return 0;
            pe->data = new_data;
            pe->size = new_file_size;
            /* Re-base pointers after realloc */
            pe->dos = (DOS_HEADER *)pe->data;
            uint32_t pe_off = pe->dos->e_lfanew;
            pe->coff = (COFF_HEADER *)(pe->data + pe_off + 4);
            pe->sections = (SECTION_HEADER *)(pe->data + pe_off + 4
                             + sizeof(COFF_HEADER) + pe->coff->SizeOfOptionalHeader);
        }
    } else {
        cert_write_offset = pe->size;
        new_file_size = pe->size + aligned;
        new_data = (uint8_t *)realloc(pe->data, new_file_size);
        if (!new_data) return 0;
        pe->data = new_data;
        pe->size = new_file_size;
        pe->dos = (DOS_HEADER *)pe->data;
        uint32_t pe_off = pe->dos->e_lfanew;
        pe->coff = (COFF_HEADER *)(pe->data + pe_off + 4);
        pe->sections = (SECTION_HEADER *)(pe->data + pe_off + 4
                         + sizeof(COFF_HEADER) + pe->coff->SizeOfOptionalHeader);
    }

    /* Write WIN_CERTIFICATE header */
    WIN_CERTIFICATE *wcert = (WIN_CERTIFICATE *)(pe->data + cert_write_offset);
    wcert->dwLength         = total_size;
    wcert->wRevision        = WIN_CERT_REVISION_2_0;
    wcert->wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA;

    /* Write PKCS#7 DER data */
    memcpy(pe->data + cert_write_offset + sizeof(WIN_CERTIFICATE), sig_der, sig_len);

    /* Zero padding */
    uint32_t padding = aligned - total_size;
    if (padding)
        memset(pe->data + cert_write_offset + total_size, 0, padding);

    /* Update Certificate Table directory entry.
     * We need to re-find the cert_dir pointer since realloc may have moved data. */
    {
        uint32_t pe_offset = pe->dos->e_lfanew;
        uint32_t opt_offset = pe_offset + 4 + sizeof(COFF_HEADER);
        pe->coff = (COFF_HEADER *)(pe->data + pe_offset + 4);

        if (pe->is_pe32plus) {
            OPTIONAL_HEADER_64 *opt = (OPTIONAL_HEADER_64 *)(pe->data + opt_offset);
            pe->p_checksum = &opt->CheckSum;
            pe->cert_dir = &opt->DataDirectory[DIR_CERTIFICATE_TABLE];
            pe->sections = (SECTION_HEADER *)(pe->data + opt_offset + pe->coff->SizeOfOptionalHeader);
        } else {
            OPTIONAL_HEADER_32 *opt = (OPTIONAL_HEADER_32 *)(pe->data + opt_offset);
            pe->p_checksum = &opt->CheckSum;
            pe->cert_dir = &opt->DataDirectory[DIR_CERTIFICATE_TABLE];
            pe->sections = (SECTION_HEADER *)(pe->data + opt_offset + pe->coff->SizeOfOptionalHeader);
        }
    }

    pe->cert_dir->VirtualAddress = (uint32_t)cert_write_offset;
    pe->cert_dir->Size           = aligned;
    pe->cert_offset = (uint32_t)cert_write_offset;
    pe->cert_size   = aligned;

    return 1;
}

/*
 * Recalculate PE checksum.
 * Uses the standard algorithm: sum all 16-bit words, fold carries,
 * add file size.  Checksum field is treated as zero during sum.
 */
void pe_recalc_checksum(PE_FILE *pe)
{
    size_t checksum_off = (size_t)((uint8_t *)pe->p_checksum - pe->data);
    *pe->p_checksum = calc_checksum(pe->data, pe->size, checksum_off);
}

int pe_save(const PE_FILE *pe, const char *path)
{
    return write_file(path, pe->data, pe->size);
}

/*
 * Extract the PKCS#7 DER data from the certificate table.
 * Returns allocated buffer; caller must free.
 */
unsigned char* pe_extract_signature(const PE_FILE *pe, uint32_t *out_len)
{
    unsigned char *buf;
    WIN_CERTIFICATE *wcert;

    if (!pe_is_signed(pe))
        return NULL;

    wcert = (WIN_CERTIFICATE *)(pe->data + pe->cert_offset);

    if (wcert->wCertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA)
        return NULL;

    uint32_t der_len = wcert->dwLength - sizeof(WIN_CERTIFICATE);
    buf = (unsigned char *)malloc(der_len);
    if (!buf) return NULL;

    memcpy(buf, pe->data + pe->cert_offset + sizeof(WIN_CERTIFICATE), der_len);

    if (out_len)
        *out_len = der_len;

    return buf;
}
