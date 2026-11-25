/* SPDX-License-Identifier: MIT */
/* gralloc_dump: inspect the gralloc private handle and the shared-metadata
 * region of freshly allocated AHardwareBuffers, to derive the ShmLayout
 * (sources/stablec_shim/src/gralloc_layout.h) for a new SoC.
 *
 * No root needed: it only allocates buffers owned by this process.
 *
 * Build (Termux):
 *   pkg install clang
 *   clang -O2 -o gralloc_dump gralloc_dump.c -ldl
 *
 * Run:
 *   ./gralloc_dump [outdir]          (default: ./gralloc_out)
 *
 * Scan mode (needs root): look for live shared-metadata regions inside another
 * process (e.g. surfaceflinger) and print the non-zero words of each distinct
 * one. Used to find slots that only producers fill in, such as crop.
 *   pid=$(su -c pidof surfaceflinger)
 *   su -c "$PWD/gralloc_dump --scan $pid"
 * The output includes buffer names (window/app names): review it first.
 *
 * Everything is also printed, so the files are a backup: send both the
 * console output and the outdir contents.
 */
#define _GNU_SOURCE
#include <android/hardware_buffer.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* Same layout as libcutils native_handle_t. */
typedef struct {
    int version;
    int numFds;
    int numInts;
    int data[];
} raw_handle;

/* Offsets the shim assumes (gralloc_layout.h). */
#define PH_OFF_MAGIC   0x20
#define PH_MAGIC       0x3141592u
#define PH_FDINT_SUM   0x55
#define PH_ION_FD_IDX  0x28
#define PH_INTFMT      0x50
#define PH_MAPPED_SIZE 0x148

typedef int (*alloc_fn)(const AHardwareBuffer_Desc*, AHardwareBuffer**);
typedef void (*release_fn)(AHardwareBuffer*);
typedef const raw_handle* (*get_handle_fn)(const AHardwareBuffer*);

static alloc_fn p_alloc;
static release_fn p_release;
static get_handle_fn p_get_handle;

static uint32_t rd32(const void* base, size_t off) {
    uint32_t v;
    memcpy(&v, (const char*)base + off, 4);
    return v;
}

static uint64_t rd64(const void* base, size_t off) {
    uint64_t v;
    memcpy(&v, (const char*)base + off, 8);
    return v;
}

static void hexdump(const uint8_t* p, size_t len, size_t base_off) {
    for (size_t i = 0; i < len; i += 16) {
        printf("    %06zx:", base_off + i);
        for (size_t k = 0; k < 16 && i + k < len; k++) printf(" %02x", p[i + k]);
        printf("\n");
    }
}

static void write_file(const char* dir, const char* name, const void* data, size_t len) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE* f = fopen(path, "wb");
    if (!f) {
        printf("  ! cannot write %s: %s\n", path, strerror(errno));
        return;
    }
    fwrite(data, 1, len, f);
    fclose(f);
    printf("  wrote %s (%zu bytes)\n", path, len);
}

static void dump_one(const char* outdir, uint32_t fmt, uint32_t w, uint32_t h) {
    printf("\n=== format 0x%x, %ux%u ===\n", fmt, w, h);

    AHardwareBuffer_Desc d;
    memset(&d, 0, sizeof(d));
    d.width = w;
    d.height = h;
    d.layers = 1;
    d.format = fmt;
    d.usage = AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN | AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN |
              AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE;

    AHardwareBuffer* buf = NULL;
    int rc = p_alloc(&d, &buf);
    if (rc != 0 || !buf) {
        printf("  allocate failed (rc=%d)\n", rc);
        return;
    }

    const raw_handle* hd = p_get_handle(buf);
    if (!hd) {
        printf("  getNativeHandle returned NULL\n");
        p_release(buf);
        return;
    }

    size_t hlen = sizeof(raw_handle) + (size_t)(hd->numInts + hd->numFds) * 4;
    printf("  version=0x%x numFds=%d numInts=%d (sum=0x%x)\n", hd->version, hd->numFds,
           hd->numInts, (unsigned)(hd->numFds + hd->numInts));
    uint32_t magic = hlen > PH_OFF_MAGIC + 4 ? rd32(hd, PH_OFF_MAGIC) : 0;
    int matches = hd->version == 0xc && magic == PH_MAGIC &&
                  (hd->numFds + hd->numInts) == PH_FDINT_SUM;
    printf("  magic@+0x20=0x%x -> handle matches shim assumptions: %s\n", magic,
           matches ? "YES" : "NO");

    char name[96];
    snprintf(name, sizeof(name), "handle_%x_%ux%u.bin", fmt, w, h);
    write_file(outdir, name, hd, hlen);

    if (hlen < PH_MAPPED_SIZE + 8) {
        printf("  handle too short for the assumed offsets, stopping\n");
        p_release(buf);
        return;
    }

    uint32_t idx = rd32(hd, PH_ION_FD_IDX);
    uint64_t intfmt = rd64(hd, PH_INTFMT);
    uint64_t map_size = rd64(hd, PH_MAPPED_SIZE);
    printf("  fd index @+0x28 = %u, internal format @+0x50 = 0x%" PRIx64
           ", mapped size @+0x148 = 0x%" PRIx64 "\n",
           idx, intfmt, map_size);

    if (idx < 1 || idx > 4 || (int)idx >= hd->numFds || map_size == 0 ||
        map_size > (64u << 20)) {
        printf("  fd index or size out of range, cannot map the region\n");
        p_release(buf);
        return;
    }

    void* m = mmap(NULL, (size_t)map_size, PROT_READ, MAP_SHARED, hd->data[idx], 0);
    if (m == MAP_FAILED) {
        printf("  mmap failed: %s\n", strerror(errno));
        p_release(buf);
        return;
    }

    snprintf(name, sizeof(name), "shm_%x_%ux%u.bin", fmt, w, h);
    write_file(outdir, name, m, (size_t)map_size);

    /* Hypothesis from the known SoCs: slots anchored at the end of the region.
     * dataspace flag/value = size-8 / size-4; crop flag/rect = size-0x28 / size-0x24. */
    if (map_size >= 0x40) {
        printf("  tail slots (hypothesis: end-anchored):\n");
        printf("    crop flag      @0x%" PRIx64 " = %u\n", map_size - 0x28,
               rd32(m, (size_t)map_size - 0x28));
        printf("    crop rect      @0x%" PRIx64 " = %d %d %d %d\n", map_size - 0x24,
               (int)rd32(m, (size_t)map_size - 0x24), (int)rd32(m, (size_t)map_size - 0x20),
               (int)rd32(m, (size_t)map_size - 0x1c), (int)rd32(m, (size_t)map_size - 0x18));
        printf("    dataspace flag @0x%" PRIx64 " = %u\n", map_size - 8,
               rd32(m, (size_t)map_size - 8));
        printf("    dataspace val  @0x%" PRIx64 " = 0x%x\n", map_size - 4,
               rd32(m, (size_t)map_size - 4));
        size_t tail = map_size >= 0x80 ? 0x80 : (size_t)map_size;
        printf("  last 0x%zx bytes of the region:\n", tail);
        hexdump((const uint8_t*)m + map_size - tail, tail, (size_t)map_size - tail);
    }

    munmap(m, (size_t)map_size);
    p_release(buf);
}

/* Layout seen on the Exynos 1380 (A54): region of 0x33c8 bytes, name slot
 * (u32 length + ASCII) at 0x32c0, dataspace flag/value at 0x2a88/0x2a8c. */
#define SCAN_MAP_SIZE 0x33c8
#define SCAN_NAME_OFF 0x32c0
#define SCAN_DS_OFF   0x2a88
#define SCAN_MAX_SHOWN 40

static uint64_t fnv1a(const uint8_t* p, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static int scan_pid(const char* pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/maps", pid);
    FILE* maps = fopen(path, "r");
    if (!maps) {
        perror(path);
        return 1;
    }
    snprintf(path, sizeof(path), "/proc/%s/mem", pid);
    int mem = open(path, O_RDONLY);
    if (mem < 0) {
        perror(path);
        fclose(maps);
        return 1;
    }
    uint8_t* buf = malloc(SCAN_MAP_SIZE);
    if (!buf) {
        close(mem);
        fclose(maps);
        return 1;
    }

    const unsigned long long rounded = (SCAN_MAP_SIZE + 0xfffULL) & ~0xfffULL;
    uint64_t seen[256];
    unsigned nseen = 0, cand = 0, valid = 0, shown = 0;
    char line[512];

    while (fgets(line, sizeof(line), maps)) {
        unsigned long long s, e;
        char perms[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &s, &e, perms) != 3) continue;
        if (e - s != rounded || perms[0] != 'r' || perms[3] != 's') continue;
        cand++;
        if (pread(mem, buf, SCAN_MAP_SIZE, (off_t)s) != SCAN_MAP_SIZE) continue;

        uint32_t nlen = rd32(buf, SCAN_NAME_OFF);
        if (nlen == 0 || nlen > 0xfc) continue;
        int printable = 1;
        for (uint32_t i = 0; i < nlen; i++) {
            uint8_t c = buf[SCAN_NAME_OFF + 4 + i];
            if (c < 0x20 || c > 0x7e) {
                printable = 0;
                break;
            }
        }
        if (!printable) continue;
        valid++;

        /* Skip regions whose metadata (everything before the name) repeats. */
        uint64_t hsh = fnv1a(buf, SCAN_NAME_OFF);
        int dup = 0;
        for (unsigned i = 0; i < nseen; i++) {
            if (seen[i] == hsh) {
                dup = 1;
                break;
            }
        }
        if (dup) continue;
        if (nseen < sizeof(seen) / sizeof(seen[0])) seen[nseen++] = hsh;
        if (shown >= SCAN_MAX_SHOWN) continue;
        shown++;

        printf("\n--- region @0x%llx name=\"%.*s\"\n", s, (int)nlen,
               (const char*)buf + SCAN_NAME_OFF + 4);
        printf("    dataspace flag=%u value=0x%x\n", rd32(buf, SCAN_DS_OFF),
               rd32(buf, SCAN_DS_OFF + 4));
        unsigned printed = 0;
        for (size_t o = 0; o + 4 <= SCAN_NAME_OFF && printed < 32; o += 4) {
            uint32_t v = rd32(buf, o);
            if (!v) continue;
            printf("    0x%04zx = 0x%08x (%d)\n", o, v, (int)v);
            printed++;
        }
    }

    printf("\nscan summary: %u mappings of size 0x%llx, %u look like metadata, "
           "%u distinct shown\n", cand, rounded, valid, shown);
    free(buf);
    close(mem);
    fclose(maps);
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 3 && strcmp(argv[1], "--scan") == 0) return scan_pid(argv[2]);
    const char* outdir = argc > 1 ? argv[1] : "./gralloc_out";
    if (mkdir(outdir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "cannot create %s: %s\n", outdir, strerror(errno));
        return 1;
    }

    void* lib = dlopen("libandroid.so", RTLD_NOW);
    if (!lib) {
        fprintf(stderr, "dlopen libandroid.so failed: %s\n", dlerror());
        return 1;
    }
    p_alloc = (alloc_fn)dlsym(lib, "AHardwareBuffer_allocate");
    p_release = (release_fn)dlsym(lib, "AHardwareBuffer_release");
    p_get_handle = (get_handle_fn)dlsym(lib, "AHardwareBuffer_getNativeHandle");
    if (!p_alloc || !p_release || !p_get_handle) {
        fprintf(stderr, "missing AHardwareBuffer symbols (alloc=%p release=%p handle=%p)\n",
                (void*)p_alloc, (void*)p_release, (void*)p_get_handle);
        fprintf(stderr, "AHardwareBuffer_getNativeHandle needs Android 12+ (API 31)\n");
        return 1;
    }

    static const uint32_t kFormats[] = {
        AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM,
        AHARDWAREBUFFER_FORMAT_Y8Cb8Cr8_420,
    };
    static const uint32_t kSizes[][2] = {{64, 64}, {1280, 720}, {1920, 1080}};

    for (size_t f = 0; f < sizeof(kFormats) / sizeof(kFormats[0]); f++) {
        for (size_t s = 0; s < sizeof(kSizes) / sizeof(kSizes[0]); s++) {
            dump_one(outdir, kFormats[f], kSizes[s][0], kSizes[s][1]);
        }
    }

    printf("\nDone. Send this output plus the files in %s\n", outdir);
    return 0;
}
