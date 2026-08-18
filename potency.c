#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/acl.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/wait.h>
#include <linux/fs.h>
#include <linux/fiemap.h>
#include <linux/capability.h>
#include <linux/stat.h>
#include <linux/version.h>
#include <linux/limits.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <math.h>
#include <ctype.h>
#include <zlib.h>
#include <bzlib.h>
#include <lzma.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <sys/statfs.h>
#include <mntent.h>
#include <inttypes.h>
#include <stdint.h>
#include <dirent.h>
#include <libgen.h>
#include <regex.h>
#include <fnmatch.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/un.h>
#include <sys/sendfile.h>
#include <sys/uio.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/fanotify.h>
#include <sys/mount.h>
#include <sys/swap.h>
#include <sys/quota.h>
#include <linux/dqblk_xfs.h>
#include <elf.h>

#define VERSION "5.2"
#define MAX_PATH_LEN 8192
#define MAX_XATTRS 2048
#define HASH_BUFFER 262144
#define ENTROPY_BUFFER 524288
#define MAX_EXTENTS 8192
#define MAX_GROUPS 1024
#define MAX_STRINGS 100000
#define MAX_STRING_LEN 256
#define MAX_IMPORTS 4096
#define MAX_SECTIONS 256
#define MAX_SEGMENTS 64

#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

#ifndef BLAKE2B512_DIGEST_LENGTH
#define BLAKE2B512_DIGEST_LENGTH 64
#endif

#ifndef BLAKE2S256_DIGEST_LENGTH
#define BLAKE2S256_DIGEST_LENGTH 32
#endif

typedef enum {
    ANALYZER_OK = 0,
    ANALYZER_ERR_NOMEM,
    ANALYZER_ERR_IO,
    ANALYZER_ERR_PERMISSION,
    ANALYZER_ERR_NOT_FOUND,
    ANALYZER_ERR_UNSUPPORTED,
    ANALYZER_ERR_INVALID,
    ANALYZER_ERR_INTERRUPTED
} AnalyzerError;

typedef struct {
    int compute_checksums;
    int compute_entropy;
    int compute_statistics;
    int show_extended_attrs;
    int show_acls;
    int show_capabilities;
    int show_extents;
    int show_filesystem;
    int show_mounts;
    int detect_compression;
    int detect_forensics;
    int detect_anomalies;
    int deep_analysis;
    int output_json;
    int quiet_mode;
    int show_progress;
    int follow_symlinks;
    int all_features;
    int extract_strings;
    int min_string_len;
    int max_strings;
} AnalysisOptions;

typedef struct {
    char *string;
    size_t offset;
    int length;
} StringEntry;

typedef struct {
    char *name;
    uint64_t address;
    size_t size;
    uint32_t flags;
    uint32_t type;
    double entropy;
} SectionInfo;

typedef struct {
    char *name;
    uint64_t virtual_address;
    uint64_t virtual_size;
    uint64_t raw_offset;
    uint64_t raw_size;
    uint32_t characteristics;
    double entropy;
} PESection;

typedef struct {
    struct stat st;
    
    char **xattr_names;
    unsigned char **xattr_values;
    size_t *xattr_sizes;
    int xattr_count;
    
    acl_t acl;
    acl_t default_acl;
    
    unsigned char *cap_data;
    ssize_t cap_size;
    int cap_version;
    uint64_t cap_permitted;
    uint64_t cap_inheritable;
    uint64_t cap_effective;
    
    struct statfs fs_info;
    struct statvfs vfs_info;
    
    struct fiemap *extent_map;
    int extent_count;
    
    unsigned char md5[MD5_DIGEST_LENGTH];
    unsigned char sha1[SHA_DIGEST_LENGTH];
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    unsigned char sha512[SHA512_DIGEST_LENGTH];
    unsigned char ripemd160[RIPEMD160_DIGEST_LENGTH];
    unsigned char blake2b[BLAKE2B512_DIGEST_LENGTH];
    unsigned char blake2s[BLAKE2S256_DIGEST_LENGTH];
    int checksums_computed;
    
    double entropy;
    double chi_square;
    double arithmetic_mean;
    double monte_carlo_pi;
    double serial_correlation;
    int is_compressed;
    char compression_type[32];
    char magic_bytes[128];
    char mime_type[128];
    char file_description[256];
    char charset[32];
    
    uid_t uid;
    gid_t gid;
    char owner_name[256];
    char group_name[256];
    char *groups[MAX_GROUPS];
    int group_count;
    
    unsigned long inode_flags;
    int is_sparse;
    int is_encrypted;
    int is_packed;
    int has_hidden_data;
    int is_suspicious;
    
    char mount_point[MAX_PATH_LEN];
    char mount_options[1024];
    char filesystem_type[64];
    
    StringEntry *strings;
    int string_count;
    
    SectionInfo *elf_sections;
    int elf_section_count;
    int is_elf;
    int elf_class;
    int elf_endian;
    int elf_type;
    char *elf_interp;
    
    PESection *pe_sections;
    int pe_section_count;
    int is_pe;
    char *pe_subsystem;
    
    int is_macho;
    int is_pdf;
    int is_archive;
    
    double *entropy_curve;
    int entropy_curve_points;
    
} FileInfo;

static volatile sig_atomic_t g_running = 1;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static const char* error_string(AnalyzerError err) {
    switch (err) {
        case ANALYZER_OK: return "Success";
        case ANALYZER_ERR_NOMEM: return "Out of memory";
        case ANALYZER_ERR_IO: return "I/O error";
        case ANALYZER_ERR_PERMISSION: return "Permission denied";
        case ANALYZER_ERR_NOT_FOUND: return "File not found";
        case ANALYZER_ERR_UNSUPPORTED: return "Operation not supported";
        case ANALYZER_ERR_INVALID: return "Invalid argument";
        case ANALYZER_ERR_INTERRUPTED: return "Operation interrupted";
        default: return "Unknown error";
    }
}

static void cleanup_file_info(FileInfo *info) {
    if (!info) return;
    
    if (info->xattr_names) {
        for (int i = 0; i < info->xattr_count; i++) {
            free(info->xattr_names[i]);
            free(info->xattr_values[i]);
        }
        free(info->xattr_names);
        free(info->xattr_values);
        free(info->xattr_sizes);
    }
    
    if (info->acl) acl_free(info->acl);
    if (info->default_acl) acl_free(info->default_acl);
    if (info->cap_data) free(info->cap_data);
    if (info->extent_map) free(info->extent_map);
    
    for (int i = 0; i < info->group_count; i++) {
        free(info->groups[i]);
    }
    
    if (info->strings) {
        for (int i = 0; i < info->string_count; i++) {
            free(info->strings[i].string);
        }
        free(info->strings);
    }
    
    if (info->elf_sections) {
        for (int i = 0; i < info->elf_section_count; i++) {
            free(info->elf_sections[i].name);
        }
        free(info->elf_sections);
    }
    
    if (info->elf_interp) free(info->elf_interp);
    
    if (info->pe_sections) {
        for (int i = 0; i < info->pe_section_count; i++) {
            free(info->pe_sections[i].name);
        }
        free(info->pe_sections);
    }
    
    if (info->pe_subsystem) free(info->pe_subsystem);
    
    if (info->entropy_curve) free(info->entropy_curve);
    
    memset(info, 0, sizeof(*info));
}

static const char* get_file_type_str(mode_t mode) {
    switch (mode & S_IFMT) {
        case S_IFREG: return "regular";
        case S_IFDIR: return "directory";
        case S_IFCHR: return "character_device";
        case S_IFBLK: return "block_device";
        case S_IFIFO: return "fifo";
        case S_IFLNK: return "symlink";
        case S_IFSOCK: return "socket";
        default: return "unknown";
    }
}

static void get_permission_string(mode_t mode, char *buf, size_t buf_size) {
    if (buf_size < 11) return;
    
    buf[0] = (mode & S_IFMT) == S_IFDIR ? 'd' :
             (mode & S_IFMT) == S_IFLNK ? 'l' : '-';
    buf[1] = (mode & S_IRUSR) ? 'r' : '-';
    buf[2] = (mode & S_IWUSR) ? 'w' : '-';
    buf[3] = (mode & S_IXUSR) ? 'x' : '-';
    buf[4] = (mode & S_IRGRP) ? 'r' : '-';
    buf[5] = (mode & S_IWGRP) ? 'w' : '-';
    buf[6] = (mode & S_IXGRP) ? 'x' : '-';
    buf[7] = (mode & S_IROTH) ? 'r' : '-';
    buf[8] = (mode & S_IWOTH) ? 'w' : '-';
    buf[9] = (mode & S_IXOTH) ? 'x' : '-';
    buf[10] = '\0';
    
    if (mode & S_ISUID) buf[3] = (buf[3] == 'x') ? 's' : 'S';
    if (mode & S_ISGID) buf[6] = (buf[6] == 'x') ? 's' : 'S';
    if (mode & S_ISVTX) buf[9] = (buf[9] == 'x') ? 't' : 'T';
}

static void json_escape(const char *str, char *out, size_t out_size) {
    if (!str || !out || out_size == 0) return;
    
    size_t pos = 0;
    for (size_t i = 0; str[i] && pos < out_size - 1; i++) {
        unsigned char c = (unsigned char)str[i];
        switch (c) {
            case '"':
                if (pos + 2 < out_size) { out[pos++] = '\\'; out[pos++] = '"'; }
                break;
            case '\\':
                if (pos + 2 < out_size) { out[pos++] = '\\'; out[pos++] = '\\'; }
                break;
            case '\n':
                if (pos + 2 < out_size) { out[pos++] = '\\'; out[pos++] = 'n'; }
                break;
            case '\r':
                if (pos + 2 < out_size) { out[pos++] = '\\'; out[pos++] = 'r'; }
                break;
            case '\t':
                if (pos + 2 < out_size) { out[pos++] = '\\'; out[pos++] = 't'; }
                break;
            default:
                if (c < 0x20) {
                    if (pos + 6 < out_size) {
                        snprintf(out + pos, out_size - pos, "\\u%04x", c);
                        pos += 6;
                    }
                } else {
                    out[pos++] = (char)c;
                }
        }
    }
    out[pos] = '\0';
}

static void calculate_entropy(const unsigned char *data, size_t len, double *entropy) {
    if (!data || !entropy || len == 0) {
        if (entropy) *entropy = 0.0;
        return;
    }
    
    unsigned int counts[256] = {0};
    
    for (size_t i = 0; i < len; i++) {
        counts[data[i]]++;
    }
    
    double ent = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double prob = (double)counts[i] / (double)len;
            ent -= prob * log2(prob);
        }
    }
    
    *entropy = ent;
}

static void calculate_chi_square(const unsigned char *data, size_t len, FileInfo *info) {
    if (len == 0) return;
    
    double expected = (double)len / 256.0;
    double chi = 0.0;
    unsigned int counts[256] = {0};
    
    for (size_t i = 0; i < len; i++) {
        counts[data[i]]++;
    }
    
    for (int i = 0; i < 256; i++) {
        double diff = (double)counts[i] - expected;
        chi += (diff * diff) / expected;
    }
    
    info->chi_square = chi;
}

static void calculate_arithmetic_mean(const unsigned char *data, size_t len, FileInfo *info) {
    if (len == 0) return;
    
    double sum = 0.0;
    for (size_t i = 0; i < len; i++) {
        sum += (double)data[i];
    }
    info->arithmetic_mean = sum / (double)len;
}

static void calculate_monte_carlo_pi(const unsigned char *data, size_t len, FileInfo *info) {
    if (len < 6) {
        info->monte_carlo_pi = 0.0;
        return;
    }
    
    int in_circle = 0;
    size_t total = len / 2;
    
    for (size_t i = 0; i < total; i++) {
        double x = ((double)data[i * 2] / 255.0) * 2.0 - 1.0;
        double y = ((double)data[i * 2 + 1] / 255.0) * 2.0 - 1.0;
        if (x * x + y * y <= 1.0) {
            in_circle++;
        }
    }
    
    info->monte_carlo_pi = 4.0 * (double)in_circle / (double)total;
}

static void calculate_serial_correlation(const unsigned char *data, size_t len, FileInfo *info) {
    if (len < 2) {
        info->serial_correlation = 0.0;
        return;
    }
    
    double sum_x = 0.0, sum_y = 0.0, sum_xy = 0.0, sum_x2 = 0.0, sum_y2 = 0.0;
    size_t n = len - 1;
    
    for (size_t i = 0; i < n; i++) {
        double x = (double)data[i];
        double y = (double)data[i + 1];
        sum_x += x;
        sum_y += y;
        sum_xy += x * y;
        sum_x2 += x * x;
        sum_y2 += y * y;
    }
    
    double n_d = (double)n;
    double numerator = n_d * sum_xy - sum_x * sum_y;
    double denominator = sqrt((n_d * sum_x2 - sum_x * sum_x) * (n_d * sum_y2 - sum_y * sum_y));
    
    info->serial_correlation = (denominator != 0.0) ? numerator / denominator : 0.0;
}

static void detect_charset(const unsigned char *data, size_t len, FileInfo *info) {
    int has_utf8 = 0;
    int has_ascii = 1;
    int has_binary = 0;
    
    if (len >= 2 && data[0] == 0xFF && data[1] == 0xFE) {
        snprintf(info->charset, sizeof(info->charset), "UTF-16LE");
        return;
    }
    if (len >= 2 && data[0] == 0xFE && data[1] == 0xFF) {
        snprintf(info->charset, sizeof(info->charset), "UTF-16BE");
        return;
    }
    if (len >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) {
        snprintf(info->charset, sizeof(info->charset), "UTF-8-BOM");
        return;
    }
    
    for (size_t i = 0; i < len && i < 10000; i++) {
        if (data[i] > 127) {
            has_ascii = 0;
            if ((data[i] & 0xE0) == 0xC0 && i + 1 < len) {
                if ((data[i+1] & 0xC0) == 0x80) { has_utf8 = 1; i++; }
                else has_binary = 1;
            } else if ((data[i] & 0xF0) == 0xE0 && i + 2 < len) {
                if ((data[i+1] & 0xC0) == 0x80 && (data[i+2] & 0xC0) == 0x80) { has_utf8 = 1; i += 2; }
                else has_binary = 1;
            } else if ((data[i] & 0xF8) == 0xF0 && i + 3 < len) {
                if ((data[i+1] & 0xC0) == 0x80 && (data[i+2] & 0xC0) == 0x80 && (data[i+3] & 0xC0) == 0x80) { has_utf8 = 1; i += 3; }
                else has_binary = 1;
            } else if (data[i] < 0x20 && data[i] != 0x09 && data[i] != 0x0A && data[i] != 0x0D) {
                has_binary = 1;
            }
        } else if (data[i] < 0x20 && data[i] != 0x09 && data[i] != 0x0A && data[i] != 0x0D) {
            has_binary = 1;
        }
    }
    
    if (has_ascii && !has_binary) snprintf(info->charset, sizeof(info->charset), "ASCII");
    else if (has_utf8 && !has_binary) snprintf(info->charset, sizeof(info->charset), "UTF-8");
    else if (has_binary) snprintf(info->charset, sizeof(info->charset), "Binary");
    else snprintf(info->charset, sizeof(info->charset), "Unknown");
}

static void extract_strings(const unsigned char *data, size_t len, FileInfo *info, AnalysisOptions *opts) {
    if (!opts->extract_strings || len == 0) return;
    
    int min_len = opts->min_string_len > 0 ? opts->min_string_len : 4;
    int max_strings = opts->max_strings > 0 ? opts->max_strings : MAX_STRINGS;
    
    info->strings = calloc((size_t)max_strings, sizeof(StringEntry));
    if (!info->strings) return;
    
    size_t start = 0;
    int count = 0;
    int in_string = 0;
    
    for (size_t i = 0; i < len && count < max_strings; i++) {
        if (isprint(data[i]) || data[i] == '\t') {
            if (!in_string) {
                in_string = 1;
                start = i;
            }
        } else {
            if (in_string) {
                size_t str_len = i - start;
                if (str_len >= (size_t)min_len) {
                    info->strings[count].string = malloc(str_len + 1);
                    if (info->strings[count].string) {
                        memcpy(info->strings[count].string, data + start, str_len);
                        info->strings[count].string[str_len] = '\0';
                        info->strings[count].offset = start;
                        info->strings[count].length = (int)str_len;
                        count++;
                    }
                }
                in_string = 0;
            }
        }
    }
    
    if (in_string && count < max_strings) {
        size_t str_len = len - start;
        if (str_len >= (size_t)min_len) {
            info->strings[count].string = malloc(str_len + 1);
            if (info->strings[count].string) {
                memcpy(info->strings[count].string, data + start, str_len);
                info->strings[count].string[str_len] = '\0';
                info->strings[count].offset = start;
                info->strings[count].length = (int)str_len;
                count++;
            }
        }
    }
    
    info->string_count = count;
}

static void detect_elf(const unsigned char *data, size_t len, FileInfo *info) {
    if (len < sizeof(Elf64_Ehdr)) return;
    
    if (memcmp(data, ELFMAG, SELFMAG) != 0) return;
    
    info->is_elf = 1;
    info->elf_class = data[EI_CLASS];
    info->elf_endian = data[EI_DATA];
    
    if (info->elf_class == ELFCLASS64 && len >= sizeof(Elf64_Ehdr)) {
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
        info->elf_type = ehdr->e_type;
        
        if (ehdr->e_shoff > 0 && ehdr->e_shentsize > 0 && ehdr->e_shnum > 0) {
            size_t shoff = ehdr->e_shoff;
            size_t shentsize = ehdr->e_shentsize;
            int shnum = ehdr->e_shnum;
            int shstrndx = ehdr->e_shstrndx;
            
            if (shoff + (size_t)shnum * shentsize <= len && shstrndx < shnum) {
                Elf64_Shdr *shdrs = (Elf64_Shdr *)(data + shoff);
                Elf64_Shdr *shstr = &shdrs[shstrndx];
                const char *shstrtab = (const char *)(data + shstr->sh_offset);
                
                info->elf_sections = calloc((size_t)shnum, sizeof(SectionInfo));
                if (info->elf_sections) {
                    for (int i = 0; i < shnum && i < MAX_SECTIONS; i++) {
                        if (shstr->sh_offset + shdrs[i].sh_name < len) {
                            info->elf_sections[i].name = strdup(shstrtab + shdrs[i].sh_name);
                            info->elf_sections[i].address = shdrs[i].sh_addr;
                            info->elf_sections[i].size = shdrs[i].sh_size;
                            info->elf_sections[i].flags = shdrs[i].sh_flags;
                            info->elf_sections[i].type = shdrs[i].sh_type;
                            
                            if (shdrs[i].sh_size > 0 && shdrs[i].sh_offset + shdrs[i].sh_size <= len) {
                                double ent = 0.0;
                                calculate_entropy(data + shdrs[i].sh_offset, shdrs[i].sh_size, &ent);
                                info->elf_sections[i].entropy = ent;
                            }
                        }
                    }
                    info->elf_section_count = shnum < MAX_SECTIONS ? shnum : MAX_SECTIONS;
                }
            }
        }
        
        if (ehdr->e_phoff > 0 && ehdr->e_phentsize > 0 && ehdr->e_phnum > 0) {
            size_t phoff = ehdr->e_phoff;
            size_t phentsize = ehdr->e_phentsize;
            int phnum = ehdr->e_phnum;
            
            if (phoff + (size_t)phnum * phentsize <= len) {
                Elf64_Phdr *phdrs = (Elf64_Phdr *)(data + phoff);
                for (int i = 0; i < phnum && i < MAX_SEGMENTS; i++) {
                    if (phdrs[i].p_type == PT_INTERP) {
                        if (phdrs[i].p_offset + phdrs[i].p_filesz <= len) {
                            info->elf_interp = strdup((const char *)(data + phdrs[i].p_offset));
                        }
                    }
                }
            }
        }
    } else if (info->elf_class == ELFCLASS32 && len >= sizeof(Elf32_Ehdr)) {
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)data;
        info->elf_type = ehdr->e_type;
    }
    
    switch (info->elf_type) {
        case ET_EXEC: snprintf(info->file_description, sizeof(info->file_description), "ELF Executable"); break;
        case ET_DYN: snprintf(info->file_description, sizeof(info->file_description), "ELF Shared Object"); break;
        case ET_REL: snprintf(info->file_description, sizeof(info->file_description), "ELF Relocatable"); break;
        case ET_CORE: snprintf(info->file_description, sizeof(info->file_description), "ELF Core Dump"); break;
        default: snprintf(info->file_description, sizeof(info->file_description), "ELF (type %d)", info->elf_type); break;
    }
}

static void detect_pe(const unsigned char *data, size_t len, FileInfo *info) {
    if (len < 64) return;
    
    if (data[0] != 'M' || data[1] != 'Z') return;
    
    uint32_t pe_offset = *(uint32_t *)(data + 0x3C);
    if (pe_offset + 24 > len) return;
    
    if (memcmp(data + pe_offset, "PE\0\0", 4) != 0) return;
    
    info->is_pe = 1;
    snprintf(info->file_description, sizeof(info->file_description), "PE Executable");
    
    uint16_t num_sections = *(uint16_t *)(data + pe_offset + 6);
    uint16_t opt_size = *(uint16_t *)(data + pe_offset + 20);
    uint32_t opt_offset = pe_offset + 24;
    
    if (opt_offset + opt_size + (size_t)num_sections * 40 <= len) {
        info->pe_sections = calloc((size_t)num_sections, sizeof(PESection));
        if (info->pe_sections) {
            uint32_t section_offset = opt_offset + opt_size;
            for (uint16_t i = 0; i < num_sections && i < MAX_SECTIONS; i++) {
                unsigned char *sec = (unsigned char *)(data + section_offset + (size_t)i * 40);
                info->pe_sections[i].name = malloc(9);
                if (info->pe_sections[i].name) {
                    memcpy(info->pe_sections[i].name, sec, 8);
                    info->pe_sections[i].name[8] = '\0';
                }
                info->pe_sections[i].virtual_size = *(uint32_t *)(sec + 8);
                info->pe_sections[i].virtual_address = *(uint32_t *)(sec + 12);
                info->pe_sections[i].raw_size = *(uint32_t *)(sec + 16);
                info->pe_sections[i].raw_offset = *(uint32_t *)(sec + 20);
                info->pe_sections[i].characteristics = *(uint32_t *)(sec + 36);
                
                if (info->pe_sections[i].raw_size > 0 && 
                    info->pe_sections[i].raw_offset + info->pe_sections[i].raw_size <= len) {
                    double ent = 0.0;
                    calculate_entropy(data + info->pe_sections[i].raw_offset, 
                                     info->pe_sections[i].raw_size, &ent);
                    info->pe_sections[i].entropy = ent;
                }
            }
            info->pe_section_count = num_sections < MAX_SECTIONS ? num_sections : MAX_SECTIONS;
        }
    }
    
    uint16_t subsystem = *(uint16_t *)(data + opt_offset + 68);
    switch (subsystem) {
        case 2: info->pe_subsystem = strdup("Windows GUI"); break;
        case 3: info->pe_subsystem = strdup("Windows Console"); break;
        case 9: info->pe_subsystem = strdup("Windows CE GUI"); break;
        case 10: info->pe_subsystem = strdup("EFI Application"); break;
        case 11: info->pe_subsystem = strdup("EFI Boot Service Driver"); break;
        case 12: info->pe_subsystem = strdup("EFI Runtime Driver"); break;
        case 16: info->pe_subsystem = strdup("Xbox"); break;
        default: info->pe_subsystem = strdup("Unknown"); break;
    }
}

static void detect_macho(const unsigned char *data, size_t len, FileInfo *info) {
    if (len < 4) return;
    
    uint32_t magic = *(uint32_t *)data;
    if (magic == 0xFEEDFACE || magic == 0xFEEDFACF || 
        magic == 0xCEFAEDFE || magic == 0xCFFAEDFE) {
        info->is_macho = 1;
        snprintf(info->file_description, sizeof(info->file_description), "Mach-O Binary");
    }
}

static void detect_pdf(const unsigned char *data, size_t len, FileInfo *info) {
    if (len >= 5 && memcmp(data, "%PDF-", 5) == 0) {
        info->is_pdf = 1;
        snprintf(info->file_description, sizeof(info->file_description), "PDF Document");
    }
}

static void detect_archive(const unsigned char *data, size_t len, FileInfo *info) {
    if (len < 4) return;
    
    if (memcmp(data, "PK\x03\x04", 4) == 0) {
        info->is_archive = 1;
        snprintf(info->file_description, sizeof(info->file_description), "ZIP Archive");
    } else if (len >= 6 && memcmp(data, "Rar!\x1a\x07", 6) == 0) {
        info->is_archive = 1;
        snprintf(info->file_description, sizeof(info->file_description), "RAR Archive");
    } else if (len >= 6 && memcmp(data, "7z\xbc\xaf\x27\x1c", 6) == 0) {
        info->is_archive = 1;
        snprintf(info->file_description, sizeof(info->file_description), "7-Zip Archive");
    } else if (len >= 3 && memcmp(data, "\x1f\x8b\x08", 3) == 0) {
        info->is_archive = 1;
        snprintf(info->file_description, sizeof(info->file_description), "gzip Archive");
    }
}

static void detect_anomalies(FileInfo *info) {
    if (!info) return;
    
    int score = 0;
    
    if (info->is_packed) score += 3;
    if (info->is_encrypted) score += 3;
    if (info->has_hidden_data) score += 2;
    if (info->is_sparse) score += 1;
    
    if (info->entropy > 7.8) score += 3;
    else if (info->entropy > 7.0) score += 2;
    else if (info->entropy > 6.0) score += 1;
    
    if (info->is_elf) {
        if (info->elf_section_count == 0) score += 2;
        if (info->elf_interp == NULL) score += 1;
    }
    
    if (info->is_pe) {
        for (int i = 0; i < info->pe_section_count; i++) {
            if (info->pe_sections[i].entropy > 7.5) score += 2;
            if (info->pe_sections[i].name && strstr(info->pe_sections[i].name, "UPX")) score += 3;
        }
    }
    
    if (score >= 8) info->is_suspicious = 1;
}

static void calculate_entropy_curve(const unsigned char *data, size_t len, FileInfo *info) {
    if (len == 0) return;
    
    int points = 64;
    info->entropy_curve = calloc((size_t)points, sizeof(double));
    if (!info->entropy_curve) return;
    
    size_t chunk_size = len / (size_t)points;
    if (chunk_size == 0) chunk_size = 1;
    
    for (int i = 0; i < points; i++) {
        size_t offset = (size_t)i * chunk_size;
        size_t size = (offset + chunk_size <= len) ? chunk_size : (len - offset);
        if (size == 0) break;
        
        double ent = 0.0;
        calculate_entropy(data + offset, size, &ent);
        info->entropy_curve[i] = ent;
        info->entropy_curve_points = i + 1;
    }
}

static void detect_compression_type(const unsigned char *data, size_t len, FileInfo *info) {
    if (len < 2) return;
    
    if (len >= 2 && data[0] == 0x1f && data[1] == 0x8b) {
        info->is_compressed = 1;
        snprintf(info->compression_type, sizeof(info->compression_type), "gzip");
    } else if (len >= 3 && memcmp(data, "BZh", 3) == 0) {
        info->is_compressed = 1;
        snprintf(info->compression_type, sizeof(info->compression_type), "bzip2");
    } else if (len >= 6 && data[0] == 0xfd && data[1] == '7' && data[2] == 'z' &&
               data[3] == 'X' && data[4] == 'Z' && data[5] == 0x00) {
        info->is_compressed = 1;
        snprintf(info->compression_type, sizeof(info->compression_type), "xz");
    } else if (len >= 4 && memcmp(data, "PK\x03\x04", 4) == 0) {
        info->is_compressed = 1;
        snprintf(info->compression_type, sizeof(info->compression_type), "zip");
    } else if (len >= 2 && (data[0] & 0x0f) == 0x08 && 
               ((data[0] << 8) | data[1]) % 31 == 0) {
        info->is_compressed = 1;
        snprintf(info->compression_type, sizeof(info->compression_type), "zlib");
    } else if (len >= 4 && memcmp(data, "Rar!", 4) == 0) {
        info->is_compressed = 1;
        snprintf(info->compression_type, sizeof(info->compression_type), "rar");
    } else if (len >= 4 && data[0] == '7' && data[1] == 'z' && 
               data[2] == 0xbc && data[3] == 0xaf) {
        info->is_compressed = 1;
        snprintf(info->compression_type, sizeof(info->compression_type), "7-zip");
    } else if (len >= 4 && memcmp(data, "\x28\xb5\x2f\xfd", 4) == 0) {
        info->is_compressed = 1;
        snprintf(info->compression_type, sizeof(info->compression_type), "zstd");
    } else if (len >= 4 && memcmp(data, "LZIP", 4) == 0) {
        info->is_compressed = 1;
        snprintf(info->compression_type, sizeof(info->compression_type), "lzip");
    } else if (len >= 4 && memcmp(data, "\x89LZO", 4) == 0) {
        info->is_compressed = 1;
        snprintf(info->compression_type, sizeof(info->compression_type), "lzop");
    }
}

static void get_magic_bytes(const unsigned char *data, size_t len, FileInfo *info) {
    if (len == 0) {
        snprintf(info->magic_bytes, sizeof(info->magic_bytes), "empty");
        return;
    }
    
    size_t display_len = len < 16 ? len : 16;
    char *ptr = info->magic_bytes;
    size_t remaining = sizeof(info->magic_bytes);
    
    for (size_t i = 0; i < display_len && remaining > 3; i++) {
        int written = snprintf(ptr, remaining, "%02x ", data[i]);
        if (written < 0 || (size_t)written >= remaining) break;
        ptr += written;
        remaining -= (size_t)written;
    }
    
    if (ptr > info->magic_bytes && ptr[-1] == ' ') {
        ptr[-1] = '\0';
    }
}

static void get_mime_type(const unsigned char *data, size_t len, FileInfo *info) {
    if (len < 4) {
        snprintf(info->mime_type, sizeof(info->mime_type), "application/octet-stream");
        return;
    }
    
    if (data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
        snprintf(info->mime_type, sizeof(info->mime_type), "application/x-executable");
    } else if (data[0] == 0xFF && data[1] == 0xD8) {
        snprintf(info->mime_type, sizeof(info->mime_type), "image/jpeg");
    } else if (data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G') {
        snprintf(info->mime_type, sizeof(info->mime_type), "image/png");
    } else if (data[0] == '%' && data[1] == 'P' && data[2] == 'D' && data[3] == 'F') {
        snprintf(info->mime_type, sizeof(info->mime_type), "application/pdf");
    } else if (data[0] == 'P' && data[1] == 'K') {
        snprintf(info->mime_type, sizeof(info->mime_type), "application/zip");
    } else if (data[0] == 0x1F && data[1] == 0x8B) {
        snprintf(info->mime_type, sizeof(info->mime_type), "application/gzip");
    } else if (data[0] == 'B' && data[1] == 'Z' && data[2] == 'h') {
        snprintf(info->mime_type, sizeof(info->mime_type), "application/x-bzip2");
    } else if (len >= 8 && memcmp(data, "\x89PNG\r\n\x1a\n", 8) == 0) {
        snprintf(info->mime_type, sizeof(info->mime_type), "image/png");
    } else if (data[0] == 'M' && data[1] == 'Z') {
        snprintf(info->mime_type, sizeof(info->mime_type), "application/x-msdownload");
    } else {
        snprintf(info->mime_type, sizeof(info->mime_type), "application/octet-stream");
    }
}

static void detect_forensics(const char *path, FileInfo *info) {
    if (!S_ISREG(info->st.st_mode)) return;
    
    blkcnt_t expected_blocks = (info->st.st_size + 511) / 512;
    info->is_sparse = info->st.st_blocks < expected_blocks;
    
    if (info->st.st_size < info->st.st_blocks * 512) {
        info->has_hidden_data = 1;
    }
    
    if (info->entropy > 7.5 && !info->is_compressed) {
        info->is_encrypted = 1;
    }
    
    if (S_ISREG(info->st.st_mode) && (info->st.st_mode & S_IXUSR)) {
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            unsigned char header[64];
            ssize_t len = read(fd, header, sizeof(header));
            close(fd);
            
            if (len >= 4) {
                if (memcmp(header, "UPX!", 4) == 0) {
                    info->is_packed = 1;
                } else if (len >= 2 && header[0] == 'M' && header[1] == 'Z') {
                    info->is_packed = 1;
                }
            }
        }
    }
}

static void get_user_groups(const char *username, FileInfo *info) {
    struct passwd *pw = getpwnam(username);
    if (!pw) return;
    
    int ngroups = 0;
    if (getgrouplist(username, pw->pw_gid, NULL, &ngroups) < 0 && ngroups <= 0) {
        return;
    }
    
    if (ngroups <= 0 || ngroups > MAX_GROUPS) return;
    
    gid_t *groups = malloc((size_t)ngroups * sizeof(gid_t));
    if (!groups) return;
    
    if (getgrouplist(username, pw->pw_gid, groups, &ngroups) >= 0) {
        info->group_count = ngroups;
        for (int i = 0; i < ngroups; i++) {
            struct group *gr = getgrgid(groups[i]);
            if (gr) {
                info->groups[i] = strdup(gr->gr_name);
            }
        }
    }
    
    free(groups);
}

static AnalyzerError get_extended_attributes(const char *path, FileInfo *info) {
    ssize_t list_len = llistxattr(path, NULL, 0);
    if (list_len <= 0) {
        if (list_len == 0 || errno == ENOTSUP) return ANALYZER_OK;
        return ANALYZER_ERR_IO;
    }
    
    char *list = malloc((size_t)list_len);
    if (!list) return ANALYZER_ERR_NOMEM;
    
    ssize_t actual_len = llistxattr(path, list, (size_t)list_len);
    if (actual_len <= 0) {
        free(list);
        return ANALYZER_ERR_IO;
    }
    
    int count = 0;
    for (char *name = list; name < list + actual_len; name += strlen(name) + 1) {
        count++;
        if (count >= MAX_XATTRS) break;
    }
    
    if (count == 0) {
        free(list);
        return ANALYZER_OK;
    }
    
    info->xattr_names = calloc((size_t)count, sizeof(char *));
    info->xattr_values = calloc((size_t)count, sizeof(unsigned char *));
    info->xattr_sizes = calloc((size_t)count, sizeof(size_t));
    
    if (!info->xattr_names || !info->xattr_values || !info->xattr_sizes) {
        free(list);
        free(info->xattr_names);
        free(info->xattr_values);
        free(info->xattr_sizes);
        info->xattr_names = NULL;
        info->xattr_values = NULL;
        info->xattr_sizes = NULL;
        return ANALYZER_ERR_NOMEM;
    }
    
    int index = 0;
    for (char *name = list; name < list + actual_len && index < count; 
         name += strlen(name) + 1) {
        
        ssize_t attr_len = lgetxattr(path, name, NULL, 0);
        if (attr_len > 0) {
            info->xattr_names[index] = strdup(name);
            info->xattr_values[index] = malloc((size_t)attr_len);
            info->xattr_sizes[index] = (size_t)attr_len;
            
            if (!info->xattr_names[index] || !info->xattr_values[index]) {
                free(list);
                return ANALYZER_ERR_NOMEM;
            }
            
            if (lgetxattr(path, name, info->xattr_values[index], (size_t)attr_len) != attr_len) {
                free(list);
                return ANALYZER_ERR_IO;
            }
            
            index++;
        }
    }
    
    info->xattr_count = index;
    free(list);
    return ANALYZER_OK;
}

static AnalyzerError get_capabilities(const char *path, FileInfo *info) {
    ssize_t size = getxattr(path, "security.capability", NULL, 0);
    if (size <= 0) {
        if (size == 0 || errno == ENODATA || errno == ENOTSUP) {
            return ANALYZER_OK;
        }
        return ANALYZER_ERR_IO;
    }
    
    info->cap_data = malloc((size_t)size);
    if (!info->cap_data) return ANALYZER_ERR_NOMEM;
    
    ssize_t actual_size = getxattr(path, "security.capability", info->cap_data, (size_t)size);
    if (actual_size <= 0) {
        free(info->cap_data);
        info->cap_data = NULL;
        return ANALYZER_ERR_IO;
    }
    
    info->cap_size = actual_size;
    
    if ((size_t)actual_size >= sizeof(struct vfs_cap_data)) {
        struct vfs_cap_data *cap = (struct vfs_cap_data *)info->cap_data;
        info->cap_version = (int)((cap->magic_etc & VFS_CAP_REVISION_MASK) >> VFS_CAP_REVISION_SHIFT);
        
        if (info->cap_version == VFS_CAP_REVISION_2) {
            info->cap_permitted = (uint64_t)cap->data[1].permitted << 32 | cap->data[0].permitted;
            info->cap_inheritable = (uint64_t)cap->data[1].inheritable << 32 | cap->data[0].inheritable;
        } else if (info->cap_version == VFS_CAP_REVISION_3) {
            struct vfs_ns_cap_data *cap3 = (struct vfs_ns_cap_data *)info->cap_data;
            info->cap_permitted = (uint64_t)cap3->data[1].permitted << 32 | cap3->data[0].permitted;
            info->cap_inheritable = (uint64_t)cap3->data[1].inheritable << 32 | cap3->data[0].inheritable;
        } else {
            info->cap_permitted = cap->data[0].permitted;
            info->cap_inheritable = cap->data[0].inheritable;
        }
        info->cap_effective = info->cap_permitted;
    }
    
    return ANALYZER_OK;
}

static AnalyzerError get_extents(const char *path, FileInfo *info) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return ANALYZER_ERR_IO;
    
    info->extent_map = calloc(1, sizeof(struct fiemap) + 
                              (size_t)MAX_EXTENTS * sizeof(struct fiemap_extent));
    if (!info->extent_map) {
        close(fd);
        return ANALYZER_ERR_NOMEM;
    }
    
    info->extent_map->fm_length = FIEMAP_MAX_OFFSET;
    info->extent_map->fm_extent_count = MAX_EXTENTS;
    
    if (ioctl(fd, FS_IOC_FIEMAP, info->extent_map) == 0) {
        info->extent_count = (int)info->extent_map->fm_mapped_extents;
    } else {
        free(info->extent_map);
        info->extent_map = NULL;
        info->extent_count = 0;
    }
    
    close(fd);
    return ANALYZER_OK;
}

static AnalyzerError get_inode_flags(const char *path, FileInfo *info) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return ANALYZER_ERR_IO;
    
    if (ioctl(fd, FS_IOC_GETFLAGS, &info->inode_flags) != 0) {
        close(fd);
        return ANALYZER_ERR_UNSUPPORTED;
    }
    
    close(fd);
    return ANALYZER_OK;
}

static AnalyzerError get_mount_info(const char *path, FileInfo *info) {
    FILE *mtab = setmntent("/proc/mounts", "r");
    if (!mtab) return ANALYZER_ERR_IO;
    
    char resolved_path[PATH_MAX];
    if (realpath(path, resolved_path) == NULL) {
        endmntent(mtab);
        return ANALYZER_ERR_IO;
    }
    
    struct mntent *entry;
    size_t best_match = 0;
    
    while ((entry = getmntent(mtab)) != NULL) {
        size_t len = strlen(entry->mnt_dir);
        if (strncmp(entry->mnt_dir, resolved_path, len) == 0 && len > best_match) {
            best_match = len;
            snprintf(info->mount_point, sizeof(info->mount_point), "%s", entry->mnt_dir);
            snprintf(info->mount_options, sizeof(info->mount_options), "%s", entry->mnt_opts);
            snprintf(info->filesystem_type, sizeof(info->filesystem_type), "%s", entry->mnt_type);
        }
    }
    
    endmntent(mtab);
    return best_match > 0 ? ANALYZER_OK : ANALYZER_ERR_NOT_FOUND;
}

static AnalyzerError calculate_checksums(const char *path, FileInfo *info, AnalysisOptions *opts) {
    if (!opts->compute_checksums) return ANALYZER_OK;
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) return ANALYZER_ERR_IO;
    
    EVP_MD_CTX *contexts[5];
    const EVP_MD *algorithms[5] = {
        EVP_md5(), EVP_sha1(), EVP_sha256(), EVP_sha512(), EVP_ripemd160()
    };
    unsigned char *outputs[5] = {
        info->md5, info->sha1, info->sha256, info->sha512, info->ripemd160
    };
    
    for (int i = 0; i < 5; i++) {
        contexts[i] = EVP_MD_CTX_new();
        if (!contexts[i]) {
            for (int j = 0; j < i; j++) EVP_MD_CTX_free(contexts[j]);
            close(fd);
            return ANALYZER_ERR_NOMEM;
        }
        EVP_DigestInit_ex(contexts[i], algorithms[i], NULL);
    }
    
    unsigned char *buffer = malloc(HASH_BUFFER);
    if (!buffer) {
        for (int i = 0; i < 5; i++) EVP_MD_CTX_free(contexts[i]);
        close(fd);
        return ANALYZER_ERR_NOMEM;
    }
    
    off_t total_size = info->st.st_size;
    off_t processed = 0;
    ssize_t bytes_read;
    
    while (g_running && (bytes_read = read(fd, buffer, HASH_BUFFER)) > 0) {
        for (int i = 0; i < 5; i++) {
            EVP_DigestUpdate(contexts[i], buffer, (size_t)bytes_read);
        }
        
        processed += bytes_read;
        
        if (opts->show_progress && total_size > 0 && !opts->quiet_mode) {
            fprintf(stderr, "\r%" PRIu64 "%%", (uint64_t)((processed * 100) / total_size));
        }
    }
    
    if (opts->show_progress && !opts->quiet_mode) {
        fprintf(stderr, "\r100%%\n");
    }
    
    free(buffer);
    close(fd);
    
    if (!g_running) {
        for (int i = 0; i < 5; i++) EVP_MD_CTX_free(contexts[i]);
        return ANALYZER_ERR_INTERRUPTED;
    }
    
    unsigned int len;
    for (int i = 0; i < 5; i++) {
        EVP_DigestFinal_ex(contexts[i], outputs[i], &len);
        EVP_MD_CTX_free(contexts[i]);
    }
    
    info->checksums_computed = 1;
    return ANALYZER_OK;
}

static AnalyzerError analyze_file(const char *path, FileInfo *info, AnalysisOptions *opts) {
    memset(info, 0, sizeof(*info));
    
    int stat_result = opts->follow_symlinks ? stat(path, &info->st) : lstat(path, &info->st);
    
    if (stat_result != 0) {
        if (errno == EACCES) return ANALYZER_ERR_PERMISSION;
        if (errno == ENOENT) return ANALYZER_ERR_NOT_FOUND;
        return ANALYZER_ERR_IO;
    }
    
    info->uid = info->st.st_uid;
    info->gid = info->st.st_gid;
    
    struct passwd *pw = getpwuid(info->uid);
    struct group *gr = getgrgid(info->gid);
    
    if (pw) {
        snprintf(info->owner_name, sizeof(info->owner_name), "%s", pw->pw_name);
        get_user_groups(pw->pw_name, info);
    } else {
        snprintf(info->owner_name, sizeof(info->owner_name), "%d", info->uid);
    }
    
    if (gr) {
        snprintf(info->group_name, sizeof(info->group_name), "%s", gr->gr_name);
    } else {
        snprintf(info->group_name, sizeof(info->group_name), "%d", info->gid);
    }
    
    if (statfs(path, &info->fs_info) == 0) {
        /* Success */
    }
    
    if (statvfs(path, &info->vfs_info) == 0) {
        /* Success */
    }
    
    if (opts->show_mounts) {
        (void)get_mount_info(path, info);
    }
    
    if (S_ISREG(info->st.st_mode)) {
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            size_t read_size = (info->st.st_size > 0 && (uintmax_t)info->st.st_size < ENTROPY_BUFFER) ? 
                              (size_t)info->st.st_size : ENTROPY_BUFFER;
            unsigned char *buffer = malloc(read_size > 0 ? read_size : 1);
            
            if (buffer) {
                ssize_t bytes_read = read(fd, buffer, read_size);
                
                if (bytes_read > 0) {
                    size_t br = (size_t)bytes_read;
                    get_mime_type(buffer, br, info);
                    get_magic_bytes(buffer, br, info);
                    detect_charset(buffer, br, info);
                    
                    if (opts->detect_compression) {
                        detect_compression_type(buffer, br, info);
                    }
                    
                    if (opts->compute_entropy) {
                        calculate_entropy(buffer, br, &info->entropy);
                    }
                    
                    if (opts->compute_statistics) {
                        calculate_chi_square(buffer, br, info);
                        calculate_arithmetic_mean(buffer, br, info);
                        calculate_monte_carlo_pi(buffer, br, info);
                        calculate_serial_correlation(buffer, br, info);
                    }
                    
                    if (opts->extract_strings) {
                        extract_strings(buffer, br, info, opts);
                    }
                    
                    if (opts->deep_analysis) {
                        detect_elf(buffer, br, info);
                        detect_pe(buffer, br, info);
                        detect_macho(buffer, br, info);
                        detect_pdf(buffer, br, info);
                        detect_archive(buffer, br, info);
                        calculate_entropy_curve(buffer, br, info);
                    }
                }
                
                free(buffer);
            }
            close(fd);
        }
    }
    
    if (opts->show_extended_attrs) {
        (void)get_extended_attributes(path, info);
    }
    
    if (opts->show_acls) {
        info->acl = acl_get_file(path, ACL_TYPE_ACCESS);
        info->default_acl = acl_get_file(path, ACL_TYPE_DEFAULT);
    }
    
    if (opts->show_capabilities) {
        (void)get_capabilities(path, info);
    }
    
    if (opts->show_extents) {
        (void)get_extents(path, info);
    }
    
    (void)get_inode_flags(path, info);
    
    if (opts->compute_checksums && S_ISREG(info->st.st_mode)) {
        (void)calculate_checksums(path, info, opts);
    }
    
    if (opts->detect_forensics) {
        detect_forensics(path, info);
    }
    
    if (opts->detect_anomalies) {
        detect_anomalies(info);
    }
    
    return ANALYZER_OK;
}

static void print_json_output(const char *path, FileInfo *info, AnalysisOptions *opts) {
    char perm_str[11];
    char escaped_path[MAX_PATH_LEN * 2];
    char escaped_owner[512];
    char escaped_group[512];
    char escaped_mime[256];
    char escaped_compression[64];
    char escaped_mount[PATH_MAX * 2];
    char escaped_fstype[128];
    char escaped_charset[64];
    char escaped_desc[512];
    char escaped_interp[256];
    char escaped_subsystem[256];
    
    get_permission_string(info->st.st_mode, perm_str, sizeof(perm_str));
    json_escape(path, escaped_path, sizeof(escaped_path));
    json_escape(info->owner_name, escaped_owner, sizeof(escaped_owner));
    json_escape(info->group_name, escaped_group, sizeof(escaped_group));
    json_escape(info->mime_type, escaped_mime, sizeof(escaped_mime));
    json_escape(info->compression_type, escaped_compression, sizeof(escaped_compression));
    json_escape(info->mount_point, escaped_mount, sizeof(escaped_mount));
    json_escape(info->filesystem_type, escaped_fstype, sizeof(escaped_fstype));
    json_escape(info->charset, escaped_charset, sizeof(escaped_charset));
    json_escape(info->file_description, escaped_desc, sizeof(escaped_desc));
    json_escape(info->elf_interp ? info->elf_interp : "", escaped_interp, sizeof(escaped_interp));
    json_escape(info->pe_subsystem ? info->pe_subsystem : "", escaped_subsystem, sizeof(escaped_subsystem));
    
    printf("{\n");
    printf("  \"path\": \"%s\",\n", escaped_path);
    printf("  \"type\": \"%s\",\n", get_file_type_str(info->st.st_mode));
    printf("  \"size\": %lld,\n", (long long)info->st.st_size);
    printf("  \"permissions\": \"%s\",\n", perm_str);
    printf("  \"owner\": \"%s\",\n", escaped_owner);
    printf("  \"group\": \"%s\",\n", escaped_group);
    printf("  \"uid\": %d,\n", info->uid);
    printf("  \"gid\": %d,\n", info->gid);
    printf("  \"mime_type\": \"%s\",\n", escaped_mime);
    printf("  \"magic_bytes\": \"%s\",\n", info->magic_bytes);
    printf("  \"charset\": \"%s\",\n", escaped_charset);
    printf("  \"description\": \"%s\"", escaped_desc);
    
    if (opts->detect_compression && info->is_compressed) {
        printf(",\n  \"compression\": \"%s\"", escaped_compression);
    }
    
    if (opts->detect_forensics) {
        if (info->is_sparse) printf(",\n  \"sparse\": true");
        if (info->is_encrypted) printf(",\n  \"encrypted\": true");
        if (info->is_packed) printf(",\n  \"packed\": true");
        if (info->has_hidden_data) printf(",\n  \"hidden_data\": true");
    }
    
    if (opts->detect_anomalies) {
        printf(",\n  \"suspicious\": %s", info->is_suspicious ? "true" : "false");
    }
    
    if (info->checksums_computed) {
        printf(",\n  \"checksums\": {\n");
        printf("    \"md5\": \"");
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", info->md5[i]);
        printf("\",\n");
        printf("    \"sha1\": \"");
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++) printf("%02x", info->sha1[i]);
        printf("\",\n");
        printf("    \"sha256\": \"");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", info->sha256[i]);
        printf("\",\n");
        printf("    \"sha512\": \"");
        for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) printf("%02x", info->sha512[i]);
        printf("\",\n");
        printf("    \"ripemd160\": \"");
        for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) printf("%02x", info->ripemd160[i]);
        printf("\"\n");
        printf("  }");
    }
    
    if (opts->compute_entropy && info->entropy > 0) {
        printf(",\n  \"entropy\": %.6f", info->entropy);
    }
    
    if (opts->compute_statistics && info->chi_square > 0) {
        printf(",\n  \"statistics\": {\n");
        printf("    \"chi_square\": %.6f,\n", info->chi_square);
        printf("    \"arithmetic_mean\": %.6f,\n", info->arithmetic_mean);
        printf("    \"monte_carlo_pi\": %.6f,\n", info->monte_carlo_pi);
        printf("    \"serial_correlation\": %.6f\n", info->serial_correlation);
        printf("  }");
    }
    
    if (info->entropy_curve && info->entropy_curve_points > 0) {
        printf(",\n  \"entropy_curve\": [");
        for (int i = 0; i < info->entropy_curve_points; i++) {
            printf("%.4f%s", info->entropy_curve[i], (i < info->entropy_curve_points - 1) ? ", " : "");
        }
        printf("]");
    }
    
    if (opts->show_extended_attrs && info->xattr_count > 0) {
        printf(",\n  \"xattrs\": {\n");
        for (int i = 0; i < info->xattr_count; i++) {
            char escaped_name[256];
            json_escape(info->xattr_names[i], escaped_name, sizeof(escaped_name));
            printf("    \"%s\": \"", escaped_name);
            for (size_t j = 0; j < info->xattr_sizes[i] && j < 256; j++) {
                if (isprint(info->xattr_values[i][j])) {
                    printf("%c", info->xattr_values[i][j]);
                } else {
                    printf("\\x%02x", info->xattr_values[i][j]);
                }
            }
            printf("\"%s\n", (i < info->xattr_count - 1) ? "," : "");
        }
        printf("  }");
    }
    
    if (opts->show_acls && info->acl) {
        char *acl_text = acl_to_text(info->acl, NULL);
        if (acl_text) {
            char escaped_acl[4096];
            json_escape(acl_text, escaped_acl, sizeof(escaped_acl));
            printf(",\n  \"acl\": \"%s\"", escaped_acl);
            acl_free(acl_text);
        }
    }
    
    if (opts->show_capabilities && info->cap_data) {
        printf(",\n  \"capabilities\": {\n");
        printf("    \"version\": %d,\n", info->cap_version);
        printf("    \"permitted\": %" PRIu64 ",\n", info->cap_permitted);
        printf("    \"inheritable\": %" PRIu64 ",\n", info->cap_inheritable);
        printf("    \"effective\": %" PRIu64 "\n", info->cap_effective);
        printf("  }");
    }
    
    if (opts->show_extents && info->extent_count > 0) {
        printf(",\n  \"extents\": [\n");
        for (int i = 0; i < info->extent_count; i++) {
            printf("    {\"logical\": %llu, \"physical\": %llu, \"length\": %llu}%s\n",
                   (unsigned long long)info->extent_map->fm_extents[i].fe_logical,
                   (unsigned long long)info->extent_map->fm_extents[i].fe_physical,
                   (unsigned long long)info->extent_map->fm_extents[i].fe_length,
                   (i < info->extent_count - 1) ? "," : "");
        }
        printf("  ]");
    }
    
    if (info->inode_flags) {
        printf(",\n  \"inode_flags\": %lu", info->inode_flags);
    }
    
    if (opts->show_filesystem) {
        printf(",\n  \"filesystem\": {\n");
        printf("    \"block_size\": %ld,\n", (long)info->fs_info.f_bsize);
        printf("    \"total_blocks\": %ld,\n", (long)info->fs_info.f_blocks);
        printf("    \"free_blocks\": %ld,\n", (long)info->fs_info.f_bfree);
        printf("    \"total_inodes\": %ld,\n", (long)info->fs_info.f_files);
        printf("    \"free_inodes\": %ld\n", (long)info->fs_info.f_ffree);
        printf("  }");
    }
    
    if (opts->show_mounts && info->mount_point[0]) {
        printf(",\n  \"mount\": {\n");
        printf("    \"point\": \"%s\",\n", escaped_mount);
        printf("    \"type\": \"%s\"\n", escaped_fstype);
        printf("  }");
    }
    
    if (info->group_count > 0) {
        printf(",\n  \"groups\": [");
        for (int i = 0; i < info->group_count; i++) {
            if (info->groups[i]) {
                char escaped_group_name[256];
                json_escape(info->groups[i], escaped_group_name, sizeof(escaped_group_name));
                printf("\"%s\"%s", escaped_group_name, (i < info->group_count - 1) ? ", " : "");
            }
        }
        printf("]");
    }
    
    if (info->is_elf) {
        printf(",\n  \"elf\": {\n");
        printf("    \"class\": %d,\n", info->elf_class);
        printf("    \"endian\": %d,\n", info->elf_endian);
        printf("    \"type\": %d,\n", info->elf_type);
        printf("    \"interpreter\": \"%s\",\n", escaped_interp);
        printf("    \"sections\": [\n");
        for (int i = 0; i < info->elf_section_count; i++) {
            char escaped_section_name[256];
            json_escape(info->elf_sections[i].name ? info->elf_sections[i].name : "",
                       escaped_section_name, sizeof(escaped_section_name));
            printf("      {\"name\": \"%s\", \"address\": %llu, \"size\": %zu, \"entropy\": %.4f}%s\n",
                   escaped_section_name,
                   (unsigned long long)info->elf_sections[i].address,
                   info->elf_sections[i].size,
                   info->elf_sections[i].entropy,
                   (i < info->elf_section_count - 1) ? "," : "");
        }
        printf("    ]\n");
        printf("  }");
    }
    
    if (info->is_pe) {
        printf(",\n  \"pe\": {\n");
        printf("    \"subsystem\": \"%s\",\n", escaped_subsystem);
        printf("    \"sections\": [\n");
        for (int i = 0; i < info->pe_section_count; i++) {
            char escaped_section_name[256];
            json_escape(info->pe_sections[i].name ? info->pe_sections[i].name : "",
                       escaped_section_name, sizeof(escaped_section_name));
            printf("      {\"name\": \"%s\", \"virtual_address\": %llu, \"virtual_size\": %llu, \"raw_size\": %llu, \"entropy\": %.4f}%s\n",
                   escaped_section_name,
                   (unsigned long long)info->pe_sections[i].virtual_address,
                   (unsigned long long)info->pe_sections[i].virtual_size,
                   (unsigned long long)info->pe_sections[i].raw_size,
                   info->pe_sections[i].entropy,
                   (i < info->pe_section_count - 1) ? "," : "");
        }
        printf("    ]\n");
        printf("  }");
    }
    
    if (opts->extract_strings && info->string_count > 0) {
        printf(",\n  \"strings\": [\n");
        for (int i = 0; i < info->string_count; i++) {
            char escaped_string[MAX_STRING_LEN * 2];
            json_escape(info->strings[i].string, escaped_string, sizeof(escaped_string));
            printf("    {\"offset\": %zu, \"string\": \"%s\"}%s\n",
                   info->strings[i].offset, escaped_string,
                   (i < info->string_count - 1) ? "," : "");
        }
        printf("  ]");
    }
    
    printf("\n}\n");
}

static void print_human_readable(const char *path, FileInfo *info, AnalysisOptions *opts) {
    char perm_str[11];
    char time_str[64];
    struct tm *tm_info;
    
    get_permission_string(info->st.st_mode, perm_str, sizeof(perm_str));
    
    printf("=== File Analysis ===\n");
    printf("Path: %s\n", path);
    printf("Type: %s\n", get_file_type_str(info->st.st_mode));
    printf("Size: %lld bytes (%.2f KB, %.2f MB)\n", 
           (long long)info->st.st_size,
           info->st.st_size / 1024.0,
           info->st.st_size / (1024.0 * 1024.0));
    printf("Permissions: %s (0%o)\n", perm_str, info->st.st_mode & 07777);
    printf("Owner: %s (%d)\n", info->owner_name, info->uid);
    printf("Group: %s (%d)\n", info->group_name, info->gid);
    
    if (info->group_count > 0) {
        printf("Groups: ");
        for (int i = 0; i < info->group_count; i++) {
            if (info->groups[i]) {
                printf("%s%s", info->groups[i], (i < info->group_count - 1) ? ", " : "");
            }
        }
        printf("\n");
    }
    
    tm_info = localtime(&info->st.st_atime);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    printf("Access Time: %s\n", time_str);
    
    tm_info = localtime(&info->st.st_mtime);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    printf("Modify Time: %s\n", time_str);
    
    tm_info = localtime(&info->st.st_ctime);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    printf("Change Time: %s\n", time_str);
    
    printf("Inode: %llu\n", (unsigned long long)info->st.st_ino);
    printf("Device: %llu:%llu\n", 
           (unsigned long long)major(info->st.st_dev),
           (unsigned long long)minor(info->st.st_dev));
    printf("Blocks: %lld\n", (long long)info->st.st_blocks);
    printf("Block Size: %d\n", info->st.st_blksize);
    printf("Hard Links: %llu\n", (unsigned long long)info->st.st_nlink);
    
    if (info->mime_type[0]) printf("MIME Type: %s\n", info->mime_type);
    if (info->magic_bytes[0]) printf("Magic Bytes: %s\n", info->magic_bytes);
    if (info->charset[0]) printf("Character Set: %s\n", info->charset);
    if (info->file_description[0]) printf("Description: %s\n", info->file_description);
    
    if (opts->detect_compression && info->is_compressed) {
        printf("Compression: %s\n", info->compression_type);
    }
    
    if (opts->detect_forensics) {
        printf("Sparse File: %s\n", info->is_sparse ? "yes" : "no");
        printf("Encrypted: %s\n", info->is_encrypted ? "yes" : "no");
        printf("Packed: %s\n", info->is_packed ? "yes" : "no");
        printf("Hidden Data: %s\n", info->has_hidden_data ? "yes" : "no");
    }
    
    if (opts->detect_anomalies) {
        printf("Suspicious: %s\n", info->is_suspicious ? "YES" : "no");
    }
    
    if (info->checksums_computed) {
        printf("\nChecksums:\n");
        printf("  MD5:        ");
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", info->md5[i]);
        printf("\n");
        printf("  SHA1:       ");
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++) printf("%02x", info->sha1[i]);
        printf("\n");
        printf("  SHA256:     ");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", info->sha256[i]);
        printf("\n");
        printf("  SHA512:     ");
        for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) printf("%02x", info->sha512[i]);
        printf("\n");
        printf("  RIPEMD160:  ");
        for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) printf("%02x", info->ripemd160[i]);
        printf("\n");
    }
    
    if (opts->compute_entropy && info->entropy > 0) {
        printf("\nEntropy Analysis:\n");
        printf("  Shannon Entropy: %.6f bits/byte (%.1f%%)\n", info->entropy, (info->entropy / 8.0) * 100.0);
    }
    
    if (opts->compute_statistics && info->chi_square > 0) {
        printf("  Chi-Square: %.6f\n", info->chi_square);
        printf("  Arithmetic Mean: %.6f\n", info->arithmetic_mean);
        printf("  Monte Carlo PI: %.6f\n", info->monte_carlo_pi);
        printf("  Serial Correlation: %.6f\n", info->serial_correlation);
    }
    
    if (info->entropy_curve && info->entropy_curve_points > 0) {
        printf("\nEntropy Curve (%d points):\n", info->entropy_curve_points);
        for (int i = 0; i < info->entropy_curve_points; i++) {
            printf("  [%2d] %.4f\n", i, info->entropy_curve[i]);
        }
    }
    
    if (opts->show_extended_attrs && info->xattr_count > 0) {
        printf("\nExtended Attributes (%d):\n", info->xattr_count);
        for (int i = 0; i < info->xattr_count; i++) {
            printf("  %s: ", info->xattr_names[i]);
            for (size_t j = 0; j < info->xattr_sizes[i] && j < 256; j++) {
                if (isprint(info->xattr_values[i][j])) {
                    printf("%c", info->xattr_values[i][j]);
                } else {
                    printf("\\x%02x", info->xattr_values[i][j]);
                }
            }
            if (info->xattr_sizes[i] > 256) printf("...");
            printf("\n");
        }
    }
    
    if (opts->show_acls && info->acl) {
        char *acl_text = acl_to_text(info->acl, NULL);
        if (acl_text) {
            printf("\nACL: %s\n", acl_text);
            acl_free(acl_text);
        }
    }
    
    if (opts->show_capabilities && info->cap_data) {
        printf("\nCapabilities (v%d):\n", info->cap_version);
        printf("  Permitted: %" PRIu64 "\n", info->cap_permitted);
        printf("  Inheritable: %" PRIu64 "\n", info->cap_inheritable);
        printf("  Effective: %" PRIu64 "\n", info->cap_effective);
    }
    
    if (opts->show_extents && info->extent_count > 0) {
        printf("\nExtents (%d):\n", info->extent_count);
        for (int i = 0; i < info->extent_count; i++) {
            printf("  %d: logical=%llu physical=%llu length=%llu\n", i,
                   (unsigned long long)info->extent_map->fm_extents[i].fe_logical,
                   (unsigned long long)info->extent_map->fm_extents[i].fe_physical,
                   (unsigned long long)info->extent_map->fm_extents[i].fe_length);
        }
    }
    
    if (info->inode_flags) {
        printf("\nInode Flags: 0x%lx\n", info->inode_flags);
        if (info->inode_flags & FS_IMMUTABLE_FL) printf("  - Immutable\n");
        if (info->inode_flags & FS_APPEND_FL) printf("  - Append Only\n");
        if (info->inode_flags & FS_NODUMP_FL) printf("  - No Dump\n");
        if (info->inode_flags & FS_NOATIME_FL) printf("  - No Atime\n");
        if (info->inode_flags & FS_SYNC_FL) printf("  - Synchronous\n");
        if (info->inode_flags & FS_COMPR_FL) printf("  - Compressed\n");
    }
    
    if (opts->show_filesystem) {
        printf("\nFilesystem Info:\n");
        printf("  Block Size: %ld\n", (long)info->fs_info.f_bsize);
        printf("  Total Blocks: %ld\n", (long)info->fs_info.f_blocks);
        printf("  Free Blocks: %ld\n", (long)info->fs_info.f_bfree);
        printf("  Available Blocks: %ld\n", (long)info->fs_info.f_bavail);
        printf("  Total Inodes: %ld\n", (long)info->fs_info.f_files);
        printf("  Free Inodes: %ld\n", (long)info->fs_info.f_ffree);
        printf("  Max Filename: %ld\n", (long)info->fs_info.f_namelen);
    }
    
    if (opts->show_mounts && info->mount_point[0]) {
        printf("\nMount Info:\n");
        printf("  Mount Point: %s\n", info->mount_point);
        printf("  Filesystem Type: %s\n", info->filesystem_type);
        printf("  Mount Options: %s\n", info->mount_options);
    }
    
    if (info->is_elf) {
        printf("\nELF Analysis:\n");
        printf("  Class: %s\n", info->elf_class == ELFCLASS64 ? "64-bit" : 
                         info->elf_class == ELFCLASS32 ? "32-bit" : "Unknown");
        printf("  Endian: %s\n", info->elf_endian == ELFDATA2LSB ? "Little Endian" :
                           info->elf_endian == ELFDATA2MSB ? "Big Endian" : "Unknown");
        printf("  Type: %d\n", info->elf_type);
        if (info->elf_interp) printf("  Interpreter: %s\n", info->elf_interp);
        
        if (info->elf_section_count > 0) {
            printf("  Sections (%d):\n", info->elf_section_count);
            for (int i = 0; i < info->elf_section_count; i++) {
                if (info->elf_sections[i].name) {
                    printf("    %s: addr=0x%llx size=%zu entropy=%.4f\n",
                           info->elf_sections[i].name,
                           (unsigned long long)info->elf_sections[i].address,
                           info->elf_sections[i].size,
                           info->elf_sections[i].entropy);
                }
            }
        }
    }
    
    if (info->is_pe) {
        printf("\nPE Analysis:\n");
        if (info->pe_subsystem) printf("  Subsystem: %s\n", info->pe_subsystem);
        
        if (info->pe_section_count > 0) {
            printf("  Sections (%d):\n", info->pe_section_count);
            for (int i = 0; i < info->pe_section_count; i++) {
                if (info->pe_sections[i].name) {
                    printf("    %s: va=0x%llx vsize=%llu rsize=%llu entropy=%.4f\n",
                           info->pe_sections[i].name,
                           (unsigned long long)info->pe_sections[i].virtual_address,
                           (unsigned long long)info->pe_sections[i].virtual_size,
                           (unsigned long long)info->pe_sections[i].raw_size,
                           info->pe_sections[i].entropy);
                }
            }
        }
    }
    
    if (opts->extract_strings && info->string_count > 0) {
        printf("\nExtracted Strings (%d):\n", info->string_count);
        for (int i = 0; i < info->string_count; i++) {
            printf("  [0x%04zx] %s\n", info->strings[i].offset, info->strings[i].string);
        }
    }
}

static void print_usage(const char *program_name) {
    printf("Usage: %s [options] <file>\n\n", program_name);
    printf("Options:\n");
    printf("  -c, --checksums       Calculate checksums\n");
    printf("  -e, --entropy         Calculate entropy\n");
    printf("  -s, --statistics      Calculate statistical analysis\n");
    printf("  -x, --xattrs          Show extended attributes\n");
    printf("  -a, --acls            Show ACLs\n");
    printf("  -p, --capabilities    Show capabilities\n");
    printf("  -t, --extents         Show file extents\n");
    printf("  -f, --filesystem      Show filesystem info\n");
    printf("  -m, --mounts          Show mount info\n");
    printf("  -z, --compression     Detect compression\n");
    printf("  -F, --forensics       Forensic analysis\n");
    printf("  -N, --anomalies       Detect anomalies\n");
    printf("  -D, --deep            Deep analysis (ELF/PE/Mach-O/PDF/Archive)\n");
    printf("  -S, --strings         Extract strings\n");
    printf("  -j, --json            JSON output\n");
    printf("  -L, --follow          Follow symlinks\n");
    printf("  -P, --progress        Show progress\n");
    printf("  -q, --quiet           Quiet mode\n");
    printf("  -A, --all             Enable all features\n");
    printf("      --min-string      Minimum string length (default: 4)\n");
    printf("      --max-strings     Maximum strings to extract (default: 100000)\n");
    printf("  -h, --help            Show help\n");
    printf("  -v, --version         Show version\n");
}

static AnalyzerError parse_options(int argc, char *argv[], AnalysisOptions *opts,
                                   const char **filepath) {
    static struct option long_options[] = {
        {"checksums",    no_argument, 0, 'c'},
        {"entropy",      no_argument, 0, 'e'},
        {"statistics",   no_argument, 0, 's'},
        {"xattrs",       no_argument, 0, 'x'},
        {"acls",         no_argument, 0, 'a'},
        {"capabilities", no_argument, 0, 'p'},
        {"extents",      no_argument, 0, 't'},
        {"filesystem",   no_argument, 0, 'f'},
        {"mounts",       no_argument, 0, 'm'},
        {"compression",  no_argument, 0, 'z'},
        {"forensics",    no_argument, 0, 'F'},
        {"anomalies",    no_argument, 0, 'N'},
        {"deep",         no_argument, 0, 'D'},
        {"strings",      no_argument, 0, 'S'},
        {"json",         no_argument, 0, 'j'},
        {"follow",       no_argument, 0, 'L'},
        {"progress",     no_argument, 0, 'P'},
        {"quiet",        no_argument, 0, 'q'},
        {"all",          no_argument, 0, 'A'},
        {"min-string",   required_argument, 0, 1000},
        {"max-strings",  required_argument, 0, 1001},
        {"help",         no_argument, 0, 'h'},
        {"version",      no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "cesxaptfmzFNDSjLPqAhv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c': opts->compute_checksums = 1; break;
            case 'e': opts->compute_entropy = 1; break;
            case 's': opts->compute_statistics = 1; break;
            case 'x': opts->show_extended_attrs = 1; break;
            case 'a': opts->show_acls = 1; break;
            case 'p': opts->show_capabilities = 1; break;
            case 't': opts->show_extents = 1; break;
            case 'f': opts->show_filesystem = 1; break;
            case 'm': opts->show_mounts = 1; break;
            case 'z': opts->detect_compression = 1; break;
            case 'F': opts->detect_forensics = 1; break;
            case 'N': opts->detect_anomalies = 1; break;
            case 'D': opts->deep_analysis = 1; break;
            case 'S': opts->extract_strings = 1; break;
            case 'j': opts->output_json = 1; break;
            case 'L': opts->follow_symlinks = 1; break;
            case 'P': opts->show_progress = 1; break;
            case 'q': opts->quiet_mode = 1; break;
            case 'A': opts->all_features = 1; break;
            case 1000: opts->min_string_len = atoi(optarg); break;
            case 1001: opts->max_strings = atoi(optarg); break;
            case 'h': print_usage(argv[0]); exit(0);
            case 'v': printf("%s\n", VERSION); exit(0);
            default: return ANALYZER_ERR_INVALID;
        }
    }
    
    if (optind >= argc) {
        return ANALYZER_ERR_INVALID;
    }
    
    *filepath = argv[optind];
    
    if (opts->all_features) {
        opts->compute_checksums = 1;
        opts->compute_entropy = 1;
        opts->compute_statistics = 1;
        opts->show_extended_attrs = 1;
        opts->show_acls = 1;
        opts->show_capabilities = 1;
        opts->show_extents = 1;
        opts->show_filesystem = 1;
        opts->show_mounts = 1;
        opts->detect_compression = 1;
        opts->detect_forensics = 1;
        opts->detect_anomalies = 1;
        opts->deep_analysis = 1;
        opts->extract_strings = 1;
    }
    
    return ANALYZER_OK;
}

int main(int argc, char *argv[]) {
    AnalysisOptions opts;
    memset(&opts, 0, sizeof(opts));
    
    const char *filepath = NULL;
    AnalyzerError err = parse_options(argc, argv, &opts, &filepath);
    
    if (err != ANALYZER_OK) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    
    FileInfo info;
    memset(&info, 0, sizeof(info));
    
    err = analyze_file(filepath, &info, &opts);
    
    if (err != ANALYZER_OK) {
        if (!opts.quiet_mode) {
            fprintf(stderr, "Error: %s\n", error_string(err));
        }
        cleanup_file_info(&info);
        return EXIT_FAILURE;
    }
    
    if (opts.output_json) {
        print_json_output(filepath, &info, &opts);
    } else {
        print_human_readable(filepath, &info, &opts);
    }
    
    cleanup_file_info(&info);
    
    return EXIT_SUCCESS;
}
