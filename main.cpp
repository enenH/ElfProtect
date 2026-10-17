#include "HideImport.hpp"
#include "miniz.h"
#include "PayloadFormat.h"

#include <jni.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <string.h>

#include "obfusheader.h"

// ==================== Payload Trailer Format ====================
// XZ-v1 and legacy ZIP formats are defined in the shared PayloadFormat.h.

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
using fn_dladdr = int(*)(const void*, Dl_info*);
using fn_malloc = void*(*)(size_t);
using fn_free = void(*)(void*);
using fn_realloc = void*(*)(void*, size_t);
using fn_memcpy = void*(*)(void*, const void*, size_t);
using fn_JNI_OnLoad = int(*)(void*, void*);

#if defined(ELFPROTECT_BUILD_SHARED)
static void* g_payload_handle = nullptr;
static int g_payload_jni_result = JNI_ERR;
#endif

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
void rc4_crypt(uint8_t* data, size_t len, const uint8_t* key) {
    elfprotect_payload::rc4Crypt(data, len, key);
}

// ==================== Protected Payload Loader ====================
static int load_protected_payload(void* java_vm, void* reserved, const char* self_path, bool keep_payload_loaded,
                                  void** kept_payload_handle) {
    if (kept_payload_handle)
        *kept_payload_handle = nullptr;
    if (!self_path)
        return JNI_ERR;

    // ===== Step 1: Bootstrap - resolve dlsym via HideImport (raw ELF parsing, zero extra imports) =====
    auto p_dlsym = RCAST(fn_dlsym, HI_GET(OBF("libdl.so"), OBF("dlsym")));
    if (!p_dlsym)
        return JNI_ERR;

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
        return JNI_ERR;
    }

    int result = JNI_ERR;
    int fd = -1;
    int memfd = -1;
    size_t file_size = 0;
    void* file_map = MAP_FAILED;
    uint8_t* compressed = nullptr;
    void* extracted_elf = nullptr;
    size_t extracted_elf_size = 0;
    void* handle = nullptr;
    const uint8_t* base = nullptr;
    elfprotect_payload::Trailer trailer{};
    const uint8_t* rc4_key = nullptr;
    const uint8_t* encrypted_payload = nullptr;
    const uint8_t* elf_bytes = nullptr;
    size_t written = 0;
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

    // ===== Step 3: Open current loader file =====
    fd = (int)p_syscall((long)__NR_openat, AT_FDCWD, self_path, O_RDONLY);
    if (fd < 0)
        goto cleanup;

    // ===== Step 4: Get file size via fstat =====
    if (p_syscall((long)__NR_fstat, fd, &st) < 0)
        goto cleanup;
    if (st.st_size <= 0 || static_cast<uint64_t>(st.st_size) > elfprotect_payload::kMaximumFileSize)
        goto cleanup;
    file_size = (size_t)st.st_size;

    // ===== Step 5: mmap the entire file =====
    file_map = (void*)p_syscall((long)__NR_mmap, (void*)nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, (off_t)0);
    p_close(fd);
    fd = -1;

    if (file_map == MAP_FAILED)
        goto cleanup;

    base = (const uint8_t*)file_map;

    // ===== Step 6: Validate format, lengths and trailer ranges =====
    if (!elfprotect_payload::parseTrailer(base, file_size, trailer))
        goto cleanup;

    // ===== Step 7: Read payload size and RC4 key =====
    rc4_key = base + trailer.keyOffset;
    encrypted_payload = base + trailer.encryptedOffset;

    // ===== Step 8: Copy compressed payload and decrypt =====
    compressed = (uint8_t*)p_malloc(trailer.encryptedSize);
    if (!compressed)
        goto cleanup;

    p_memcpy(compressed, encrypted_payload, trailer.encryptedSize);
    CALL(&rc4_crypt, compressed, trailer.encryptedSize, rc4_key);

    p_munmap(file_map, file_size);
    file_map = MAP_FAILED;

    // ===== Step 9: Decode one checked XZ stream, or read a legacy ZIP =====
    if (trailer.compression == elfprotect_payload::Compression::Xz) {
        extracted_elf_size = trailer.elfSize;
        extracted_elf = p_malloc(extracted_elf_size);
        if (!extracted_elf || !elfprotect_payload::decodeXz(compressed, trailer.encryptedSize,
                static_cast<uint8_t*>(extracted_elf), extracted_elf_size))
            goto cleanup;
    } else {
        zip_archive.m_pAlloc = miniz_alloc_bridge;
        zip_archive.m_pFree = miniz_free_bridge;
        zip_archive.m_pRealloc = miniz_realloc_bridge;
        zip_archive.m_pAlloc_opaque = &zip_alloc_ctx;

        if (!mz_zip_reader_init_mem(&zip_archive, compressed, trailer.encryptedSize, 0))
            goto cleanup;
        zip_reader_initialized = true;

        if (mz_zip_reader_get_num_files(&zip_archive) != 1)
            goto cleanup;

        if (!mz_zip_reader_file_stat(&zip_archive, 0, &file_stat))
            goto cleanup;

        if (file_stat.m_is_directory || !file_stat.m_is_supported ||
            file_stat.m_uncomp_size < 64 || file_stat.m_uncomp_size > elfprotect_payload::kMaximumElfSize)
            goto cleanup;

        extracted_elf = mz_zip_reader_extract_to_heap(&zip_archive, 0, &extracted_elf_size, 0);
        if (!extracted_elf)
            goto cleanup;
        mz_zip_reader_end(&zip_archive);
        zip_reader_initialized = false;
    }

    elf_bytes = (const uint8_t*)extracted_elf;
    if (!elfprotect_payload::isArm64SharedElf(elf_bytes, extracted_elf_size)) {
        goto cleanup;
    }

    p_free(compressed);
    compressed = nullptr;

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

    // ===== Step 14: Call original JNI_OnLoad =====
    result = p_JNI_OnLoad(java_vm, reserved);

cleanup:
    if (keep_payload_loaded && handle && result != JNI_ERR) {
        if (kept_payload_handle)
            *kept_payload_handle = handle;
        handle = nullptr;
    }
    if (handle)
        p_dlclose(handle);
    if (memfd >= 0)
        p_close(memfd);
    if (zip_reader_initialized)
        mz_zip_reader_end(&zip_archive);
    if (extracted_elf && zip_alloc_ctx.free_fn)
        zip_alloc_ctx.free_fn(extracted_elf);
    if (compressed)
        p_free(compressed);
    if (file_map != MAP_FAILED)
        p_munmap(file_map, file_size);
    if (fd >= 0)
        p_close(fd);

    return result;
}

#if defined(ELFPROTECT_BUILD_EXECUTABLE)
// ==================== Main ====================
int main(int argc, char* argv[]) {
    return load_protected_payload(RCAST(void*, (intptr_t)argc), RCAST(void*, argv), OBF("/proc/self/exe"), false,
                                  nullptr);
}
#endif

#if defined(ELFPROTECT_BUILD_SHARED)
// ==================== JNI Entry ====================
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    if (g_payload_handle)
        return g_payload_jni_result;

    auto p_dlsym = RCAST(fn_dlsym, HI_GET(OBF("libdl.so"), OBF("dlsym")));
    if (!p_dlsym)
        return JNI_ERR;

    auto p_dladdr = RCAST(fn_dladdr, p_dlsym(RTLD_DEFAULT, OBF("dladdr")));
    if (!p_dladdr)
        return JNI_ERR;

    Dl_info self_info{};
    if (!p_dladdr(RCAST(const void*, &JNI_OnLoad), &self_info) || !self_info.dli_fname)
        return JNI_ERR;

    void* kept_handle = nullptr;
    const int result = load_protected_payload(vm, reserved, self_info.dli_fname, true, &kept_handle);
    if (kept_handle) {
        g_payload_handle = kept_handle;
        g_payload_jni_result = result;
    }

    return result;
}
#endif
