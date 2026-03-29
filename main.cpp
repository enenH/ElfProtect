#include "HideImport.hpp"
#include "obfusheader.h"

#include <sys/syscall.h>
#include <sys/stat.h>
#include <stdint.h>
#include <string.h>

// ==================== Payload Trailer Format ====================
// [Stub ELF] [Encrypted Payload] [32-byte RC4 Key] [8-byte Size LE] [8-byte Magic]
static constexpr size_t kKeySize    = 32;
static constexpr size_t kSizeField  = 8;
static constexpr size_t kMagicSize  = 8;
static constexpr size_t kTrailerFixedSize = kKeySize + kSizeField + kMagicSize; // 48

// ==================== android_dlextinfo (avoid #include <android/dlext.h>) ====================
struct android_dlextinfo_t {
    uint64_t flags;
    void*    reserved_addr;
    size_t   reserved_size;
    int      relro_fd;
    int      library_fd;
    off64_t  library_fd_offset;
    void*    library_namespace;
};

// ==================== Function Pointer Types ====================
using fn_dlsym              = void*(*)(void*, const char*);
using fn_syscall            = long(*)(long, ...);
using fn_write              = ssize_t(*)(int, const void*, size_t);
using fn_close              = int(*)(int);
using fn_munmap             = int(*)(void*, size_t);
using fn_android_dlopen_ext = void*(*)(const char*, int, const android_dlextinfo_t*);
using fn_dlclose            = int(*)(void*);
using fn_malloc             = void*(*)(size_t);
using fn_free               = void(*)(void*);
using fn_memcpy             = void*(*)(void*, const void*, size_t);
using fn_JNI_OnLoad         = int(*)(void*, void*);

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

    uint8_t a = 0, b = 0;
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
    // ===== Step 1: Bootstrap — resolve dlsym via HideImport (raw ELF parsing, zero extra imports) =====
    auto p_dlsym = RCAST(fn_dlsym, HI_GET(OBF("libdl.so"), OBF("dlsym")));
    if (!p_dlsym)
        return -1;

    // ===== Step 2: Resolve all functions via hidden dlsym + OBF-encrypted names =====
    // Each call goes through p_dlsym pointer (indirect). Function name strings are compile-time encrypted.
    auto p_syscall   = RCAST(fn_syscall,            p_dlsym(RTLD_DEFAULT, OBF("syscall")));
    auto p_write     = RCAST(fn_write,              p_dlsym(RTLD_DEFAULT, OBF("write")));
    auto p_close     = RCAST(fn_close,              p_dlsym(RTLD_DEFAULT, OBF("close")));
    auto p_munmap    = RCAST(fn_munmap,             p_dlsym(RTLD_DEFAULT, OBF("munmap")));
    auto p_dlopen_ex = RCAST(fn_android_dlopen_ext, p_dlsym(RTLD_DEFAULT, OBF("android_dlopen_ext")));
    auto p_dlclose   = RCAST(fn_dlclose,            p_dlsym(RTLD_DEFAULT, OBF("dlclose")));
    auto p_malloc    = RCAST(fn_malloc,             p_dlsym(RTLD_DEFAULT, OBF("malloc")));
    auto p_free      = RCAST(fn_free,               p_dlsym(RTLD_DEFAULT, OBF("free")));
    auto p_memcpy    = RCAST(fn_memcpy,             p_dlsym(RTLD_DEFAULT, OBF("memcpy")));

    if (!p_syscall || !p_write || !p_close || !p_munmap || !p_dlopen_ex || !p_malloc || !p_free || !p_memcpy)
        return -1;

    // ===== Step 3: Open /proc/self/exe =====
    int fd = (int)p_syscall((long)__NR_openat, AT_FDCWD, OBF("/proc/self/exe"), O_RDONLY);
    if (fd < 0)
        return -1;

    // ===== Step 4: Get file size via fstat =====
    struct stat st{};
    if (p_syscall((long)__NR_fstat, fd, &st) < 0) {
        p_close(fd);
        return -1;
    }
    size_t file_size = (size_t)st.st_size;

    // ===== Step 5: mmap the entire file =====
    void* file_map = (void*)p_syscall((long)__NR_mmap,
        (void*)nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, (off_t)0);
    p_close(fd);

    if (file_map == MAP_FAILED)
        return -1;

    auto* base = (const uint8_t*)file_map;

    // ===== Step 6: Validate magic at the end =====
    if (file_size < kTrailerFixedSize) {
        p_munmap(file_map, file_size);
        return -1;
    }

    const uint8_t expected_magic[] = { 'E','L','F','P','R','O','T','\0' };
    const uint8_t* file_magic = base + file_size - kMagicSize;

    bool magic_ok = true;
    for (size_t i = 0; i < kMagicSize; i++) {
        if (file_magic[i] != expected_magic[i]) {
            magic_ok = false;
            break;
        }
    }
    if (!magic_ok) {
        p_munmap(file_map, file_size);
        return -1;
    }

    // ===== Step 7: Read payload size and RC4 key =====
    const uint8_t* size_ptr = base + file_size - kMagicSize - kSizeField;
    uint64_t payload_size = 0;
    for (int i = 0; i < 8; i++)
        payload_size |= ((uint64_t)size_ptr[i]) << (i * 8);

    const uint8_t* rc4_key = base + file_size - kMagicSize - kSizeField - kKeySize;

    // Sanity check
    if (payload_size == 0 || payload_size > file_size - kTrailerFixedSize) {
        p_munmap(file_map, file_size);
        return -1;
    }

    const uint8_t* encrypted_payload = base + file_size - kTrailerFixedSize - payload_size;

    // ===== Step 8: Copy encrypted payload and decrypt =====
    auto* decrypted = (uint8_t*)p_malloc((size_t)payload_size);
    if (!decrypted) {
        p_munmap(file_map, file_size);
        return -1;
    }
    p_memcpy(decrypted, encrypted_payload, (size_t)payload_size);

    // Decrypt via CALL() — compile-time function pointer hiding in shuffled array
    CALL(&rc4_crypt, decrypted, (size_t)payload_size, rc4_key, (size_t)kKeySize);

    // Done with the file mapping
    p_munmap(file_map, file_size);

    // ===== Step 9: Create memfd (syscall 279 on arm64, MFD_CLOEXEC = 1) =====
    int memfd = (int)p_syscall((long)OBF(279), OBF(""), OBF(1));
    if (memfd < 0) {
        p_free(decrypted);
        return -1;
    }

    // ===== Step 10: Write decrypted ELF to memfd =====
    size_t written = 0;
    while (written < payload_size) {
        ssize_t ret = p_write(memfd, decrypted + written, (size_t)(payload_size - written));
        if (ret <= 0)
            break;
        written += (size_t)ret;
    }
    p_free(decrypted);

    if (written != payload_size) {
        p_close(memfd);
        return -1;
    }

    // ===== Step 11: Load via android_dlopen_ext (ANDROID_DLEXT_USE_LIBRARY_FD = 0x10) =====
    android_dlextinfo_t info{};
    info.flags      = OBF(0x10);
    info.library_fd = memfd;

    void* handle = p_dlopen_ex(OBF("libpayload.so"), OBF(2) /* RTLD_NOW */, &info);
    p_close(memfd);

    if (!handle)
        return -1;

    // ===== Step 12: Resolve JNI_OnLoad =====
    auto p_JNI_OnLoad = RCAST(fn_JNI_OnLoad, p_dlsym(handle, OBF("JNI_OnLoad")));
    if (!p_JNI_OnLoad) {
        p_dlclose(handle);
        return -1;
    }

    // ===== Step 13: Call JNI_OnLoad — argc as JavaVM*, argv as reserved =====
    int result = p_JNI_OnLoad(RCAST(void*, (intptr_t)argc), RCAST(void*, argv));

    // ===== Step 14: Cleanup =====
    p_dlclose(handle);

    return result;
}
