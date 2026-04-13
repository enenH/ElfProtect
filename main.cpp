#include "HideImport.hpp"
#include "obfusheader.h"
#include "miniz.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <string.h>

// ==================== Payload Trailer Format ====================
// [Stub ELF] [Encrypted ZIP Payload] [32-byte RC4 Key] [8-byte Size LE] [8-byte Magic]
static constexpr size_t kKeySize = 32;
static constexpr size_t kSizeField = 8;
static constexpr size_t kMagicSize = 8;
static constexpr size_t kTrailerFixedSize = kKeySize + kSizeField + kMagicSize; // 48
static constexpr uint8_t kExpectedMagic[kMagicSize] = { 'E', 'L', 'F', 'P', 'R', 'O', 'T', '\0' };
static constexpr uint8_t kElfMagic[4] = { 0x7F, 'E', 'L', 'F' };

// ==================== android_dlextinfo (avoid #include <android/dlext.h>) ====================
struct android_dlextinfo_t {
    uint64_t flags;
    void* reserved_addr;
    size_t reserved_size;
    int relro_fd;
    int library_fd;
    off64_t library_fd_offset;
    void* library_namespace;
};

// ==================== Function Pointer Types ====================
using fn_dlsym = void*(*)(void*, const char*);
using fn_syscall = long(*)(long, ...);
using fn_write = ssize_t(*)(int, const void*, size_t);
using fn_close = int(*)(int);
using fn_munmap = int(*)(void*, size_t);
using fn_android_dlopen_ext = void*(*)(const char*, int, const android_dlextinfo_t*);
using fn_dlclose = int(*)(void*);
using fn_malloc = void*(*)(size_t);
using fn_free = void(*)(void*);
using fn_realloc = void*(*)(void*, size_t);
using fn_memcpy = void*(*)(void*, const void*, size_t);
using fn_JNI_OnLoad = int(*)(void*, void*);

struct miniz_alloc_context {
    fn_malloc malloc_fn;
    fn_free free_fn;
    fn_realloc realloc_fn;
};

void* miniz_alloc_bridge(void* opaque, size_t items, size_t size) {
    auto* ctx = static_cast<miniz_alloc_context*>(opaque);
    if (!ctx || !ctx->malloc_fn)
        return nullptr;

    const size_t total_size = items * size;
    if (items != 0 && total_size / items != size)
        return nullptr;

    return ctx->malloc_fn(total_size);
    return nullptr;
}

void miniz_free_bridge(void* opaque, void* address) {
    auto* ctx = static_cast<miniz_alloc_context*>(opaque);
    if (ctx && ctx->free_fn)
        ctx->free_fn(address);
}

void* miniz_realloc_bridge(void* opaque, void* address, size_t items, size_t size) {
    auto* ctx = static_cast<miniz_alloc_context*>(opaque);
    if (!ctx || !ctx->realloc_fn)
        return nullptr;

    const size_t total_size = items * size;
    if (items != 0 && total_size / items != size)
        return nullptr;

    return ctx->realloc_fn(address, total_size);
    return nullptr;
}

// ==================== RC4 Decryption ====================
// Non-static so CALL() macro can use it as a template parameter
void rc4_crypt(uint8_t* data, size_t len, const uint8_t* key, size_t key_len) {
    uint8_t S[256];
    for (int i = 0; i < 256; i++)
        S[i] = (uint8_t)i;

    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = j + S[i] + key[i % key_len];
        uint8_t tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }

    uint8_t a = 0;
    uint8_t b = 0;
    for (size_t n = 0; n < len; n++) {
        a = a + 1;
        b = b + S[a];
        uint8_t tmp = S[a];
        S[a] = S[b];
        S[b] = tmp;
        data[n] ^= S[(uint8_t)(S[a] + S[b])];
    }
}

// ==================== Main ====================
int main(int argc, char* argv[]) {
    // ===== Step 1: Bootstrap - resolve dlsym via HideImport (raw ELF parsing, zero extra imports) =====
    auto p_dlsym = RCAST(fn_dlsym, HI_GET(OBF("libdl.so"), OBF("dlsym")));
    if (!p_dlsym)
        return -1;

    // ===== Step 2: Resolve all functions via hidden dlsym + OBF-encrypted names =====
    auto p_syscall = RCAST(fn_syscall, p_dlsym(RTLD_DEFAULT, OBF("syscall")));
    auto p_write = RCAST(fn_write, p_dlsym(RTLD_DEFAULT, OBF("write")));
    auto p_close = RCAST(fn_close, p_dlsym(RTLD_DEFAULT, OBF("close")));
    auto p_munmap = RCAST(fn_munmap, p_dlsym(RTLD_DEFAULT, OBF("munmap")));
    auto p_dlopen_ex = RCAST(fn_android_dlopen_ext, p_dlsym(RTLD_DEFAULT, OBF("android_dlopen_ext")));
    auto p_dlclose = RCAST(fn_dlclose, p_dlsym(RTLD_DEFAULT, OBF("dlclose")));
    auto p_malloc = RCAST(fn_malloc, p_dlsym(RTLD_DEFAULT, OBF("malloc")));
    auto p_free = RCAST(fn_free, p_dlsym(RTLD_DEFAULT, OBF("free")));
    auto p_realloc = RCAST(fn_realloc, p_dlsym(RTLD_DEFAULT, OBF("realloc")));
    auto p_memcpy = RCAST(fn_memcpy, p_dlsym(RTLD_DEFAULT, OBF("memcpy")));

    if (!p_syscall || !p_write || !p_close || !p_munmap || !p_dlopen_ex || !p_dlclose ||
        !p_malloc || !p_free || !p_realloc || !p_memcpy) {
        return -1;
    }

    int result = -1;
    int fd = -1;
    int memfd = -1;
    size_t file_size = 0;
    void* file_map = MAP_FAILED;
    uint8_t* decrypted_zip = nullptr;
    void* extracted_elf = nullptr;
    size_t extracted_elf_size = 0;
    void* handle = nullptr;
    const uint8_t* base = nullptr;
    const uint8_t* file_magic = nullptr;
    const uint8_t* size_ptr = nullptr;
    uint64_t payload_size = 0;
    uint64_t max_payload_size = 0;
    const uint8_t* rc4_key = nullptr;
    const uint8_t* encrypted_payload = nullptr;
    const uint8_t* elf_bytes = nullptr;
    size_t written = 0;
    bool magic_ok = false;
    struct stat st{};
    mz_zip_archive_file_stat file_stat{};
    android_dlextinfo_t info{};
    fn_JNI_OnLoad p_JNI_OnLoad = nullptr;
    mz_zip_archive zip_archive{};
    bool zip_reader_initialized = false;
    miniz_alloc_context zip_alloc_ctx{};
    zip_alloc_ctx.malloc_fn = p_malloc;
    zip_alloc_ctx.free_fn = p_free;
    zip_alloc_ctx.realloc_fn = p_realloc;

    // ===== Step 3: Open /proc/self/exe =====
    fd = (int)p_syscall((long)__NR_openat, AT_FDCWD, OBF("/proc/self/exe"), O_RDONLY);
    if (fd < 0)
        goto cleanup;

    // ===== Step 4: Get file size via fstat =====
    if (p_syscall((long)__NR_fstat, fd, &st) < 0)
        goto cleanup;
    file_size = (size_t)st.st_size;

    // ===== Step 5: mmap the entire file =====
    file_map = (void*)p_syscall((long)__NR_mmap, (void*)nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, (off_t)0);
    p_close(fd);
    fd = -1;

    if (file_map == MAP_FAILED)
        goto cleanup;

    base = (const uint8_t*)file_map;

    // ===== Step 6: Validate magic at the end =====
    if (file_size < kTrailerFixedSize)
        goto cleanup;

    file_magic = base + file_size - kMagicSize;

    magic_ok = true;
    for (size_t i = 0; i < kMagicSize; i++) {
        if (file_magic[i] != kExpectedMagic[i]) {
            magic_ok = false;
            break;
        }
    }
    if (!magic_ok)
        goto cleanup;

    // ===== Step 7: Read payload size and RC4 key =====
    size_ptr = base + file_size - kMagicSize - kSizeField;
    payload_size = 0;
    for (int i = 0; i < 8; i++)
        payload_size |= ((uint64_t)size_ptr[i]) << (i * 8);

    rc4_key = base + file_size - kMagicSize - kSizeField - kKeySize;
    max_payload_size = (uint64_t)(file_size - kTrailerFixedSize);

    if (payload_size == 0 || payload_size > max_payload_size)
        goto cleanup;

    encrypted_payload = base + file_size - kTrailerFixedSize - payload_size;

    // ===== Step 8: Copy encrypted ZIP payload and decrypt =====
    decrypted_zip = (uint8_t*)p_malloc((size_t)payload_size);
    if (!decrypted_zip)
        goto cleanup;

    p_memcpy(decrypted_zip, encrypted_payload, (size_t)payload_size);
    CALL(&rc4_crypt, decrypted_zip, (size_t)payload_size, rc4_key, kKeySize);

    p_munmap(file_map, file_size);
    file_map = MAP_FAILED;

    // ===== Step 9: Read ZIP from memory and extract the only payload entry =====
    zip_archive.m_pAlloc = miniz_alloc_bridge;
    zip_archive.m_pFree = miniz_free_bridge;
    zip_archive.m_pRealloc = miniz_realloc_bridge;
    zip_archive.m_pAlloc_opaque = &zip_alloc_ctx;

    if (!mz_zip_reader_init_mem(&zip_archive, decrypted_zip, (size_t)payload_size, 0))
        goto cleanup;
    zip_reader_initialized = true;

    if (mz_zip_reader_get_num_files(&zip_archive) != 1)
        goto cleanup;

    if (!mz_zip_reader_file_stat(&zip_archive, 0, &file_stat))
        goto cleanup;

    if (file_stat.m_is_directory || !file_stat.m_is_supported)
        goto cleanup;

    extracted_elf = mz_zip_reader_extract_to_heap(&zip_archive, 0, &extracted_elf_size, 0);
    if (!extracted_elf)
        goto cleanup;

    elf_bytes = (const uint8_t*)extracted_elf;
    if (extracted_elf_size < 4 ||
        elf_bytes[0] != kElfMagic[0] ||
        elf_bytes[1] != kElfMagic[1] ||
        elf_bytes[2] != kElfMagic[2] ||
        elf_bytes[3] != kElfMagic[3]) {
        goto cleanup;
    }

    mz_zip_reader_end(&zip_archive);
    zip_reader_initialized = false;

    p_free(decrypted_zip);
    decrypted_zip = nullptr;

    // ===== Step 10: Create memfd (syscall 279 on arm64, MFD_CLOEXEC = 1) =====
    memfd = (int)p_syscall((long)OBF(279), OBF(""), OBF(1));
    if (memfd < 0)
        goto cleanup;

    // ===== Step 11: Write extracted ELF to memfd =====
    written = 0;
    while (written < extracted_elf_size) {
        ssize_t ret = p_write(memfd, elf_bytes + written, extracted_elf_size - written);
        if (ret <= 0)
            goto cleanup;
        written += (size_t)ret;
    }

    if (written != extracted_elf_size)
        goto cleanup;

    // ===== Step 12: Load via android_dlopen_ext (ANDROID_DLEXT_USE_LIBRARY_FD = 0x10) =====
    info.flags = OBF(0x10);
    info.library_fd = memfd;

    handle = p_dlopen_ex(OBF("libpayload.so"), OBF(2) /* RTLD_NOW */, &info);
    p_close(memfd);
    memfd = -1;

    if (!handle)
        goto cleanup;

    // ===== Step 13: Resolve JNI_OnLoad =====
    p_JNI_OnLoad = RCAST(fn_JNI_OnLoad, p_dlsym(handle, OBF("JNI_OnLoad")));
    if (!p_JNI_OnLoad)
        goto cleanup;

    // ===== Step 14: Call JNI_OnLoad - argc as JavaVM*, argv as reserved =====
    result = p_JNI_OnLoad(RCAST(void*, (intptr_t)argc), RCAST(void*, argv));

cleanup:
    if (handle)
        p_dlclose(handle);
    if (memfd >= 0)
        p_close(memfd);
    if (zip_reader_initialized)
        mz_zip_reader_end(&zip_archive);
    if (extracted_elf && zip_alloc_ctx.free_fn)
        zip_alloc_ctx.free_fn(extracted_elf);
    if (decrypted_zip)
        p_free(decrypted_zip);
    if (file_map != MAP_FAILED)
        p_munmap(file_map, file_size);
    if (fd >= 0)
        p_close(fd);

    return result;
}
