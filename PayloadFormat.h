#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

// Keep this file identical to ElfProtect/PayloadFormat.h.
namespace elfprotect_payload {

inline constexpr uint8_t kXzMagic[8] = {'E', 'L', 'F', 'X', 'Z', '0', '1', 0};
inline constexpr uint8_t kZipMagic[8] = {'E', 'L', 'F', 'P', 'R', 'O', 'T', 0};
inline constexpr size_t kKeySize = 32;
inline constexpr size_t kXzTrailerSize = 56;
inline constexpr size_t kZipTrailerSize = 48;
inline constexpr uint64_t kMaximumFileSize = 1024ULL * 1024 * 1024;
inline constexpr uint64_t kMaximumElfSize = 512ULL * 1024 * 1024;
inline constexpr uint32_t kDictionarySize = 4U * 1024 * 1024;

// Packers require this retained marker before appending an XZ trailer. An old
// loader must fail at packing time, not ship a binary it cannot unpack.
#if defined(__ELF__)
__attribute__((used, retain))
#endif
inline const char kXzCapability[] = "ElfProtect:XZ1:LZMA2:4MiB:CRC64";

enum class Compression { Zip, Xz };

struct Trailer {
    Compression compression = Compression::Zip;
    size_t encryptedOffset = 0;
    size_t encryptedSize = 0;
    size_t keyOffset = 0;
    size_t elfSize = 0; // Legacy ZIP obtains this from the archive metadata.
};

inline uint64_t readLe64(const uint8_t* value) {
    uint64_t result = 0;
    for (size_t i = 0; i < 8; ++i)
        result |= static_cast<uint64_t>(value[i]) << (i * 8);
    return result;
}

inline bool isArm64SharedElf(const uint8_t* bytes, size_t size) {
    static constexpr uint8_t ident[] = {0x7F, 'E', 'L', 'F', 2, 1, 1};
    return bytes && size >= 64 && std::memcmp(bytes, ident, sizeof(ident)) == 0 &&
           bytes[16] == 3 && bytes[17] == 0 && bytes[18] == 183 && bytes[19] == 0;
}

// XZ v1: [RC4(XZ ELF)] [key:32] [ELF size:LE64] [XZ size:LE64] [ELFXZ01\0].
// Legacy: [RC4(ZIP)]   [key:32]                 [ZIP size:LE64] [ELFPROT\0].
inline bool parseTrailer(const uint8_t* bytes, size_t size, Trailer& trailer) {
    trailer = {};
    if (!bytes || size < kZipTrailerSize || size > kMaximumFileSize)
        return false;
    const bool xz = std::memcmp(bytes + size - 8, kXzMagic, 8) == 0;
    if (!xz && std::memcmp(bytes + size - 8, kZipMagic, 8) != 0)
        return false;
    const size_t fixedSize = xz ? kXzTrailerSize : kZipTrailerSize;
    if (size < fixedSize)
        return false;
    const uint64_t encryptedSize = readLe64(bytes + size - 16);
    const size_t keyOffset = size - fixedSize;
    if (!encryptedSize || encryptedSize > keyOffset)
        return false;
    const uint64_t elfSize = xz ? readLe64(bytes + size - 24) : 0;
    if (xz && (elfSize < 64 || elfSize > kMaximumElfSize))
        return false;
    trailer.compression = xz ? Compression::Xz : Compression::Zip;
    trailer.encryptedOffset = keyOffset - static_cast<size_t>(encryptedSize);
    trailer.encryptedSize = static_cast<size_t>(encryptedSize);
    trailer.keyOffset = keyOffset;
    trailer.elfSize = static_cast<size_t>(elfSize);
    return true;
}

inline void rc4Crypt(uint8_t* data, size_t size, const uint8_t* key) {
    uint8_t state[256];
    for (size_t i = 0; i < sizeof(state); ++i)
        state[i] = static_cast<uint8_t>(i);
    uint8_t j = 0;
    for (size_t i = 0; i < sizeof(state); ++i) {
        j = static_cast<uint8_t>(j + state[i] + key[i % kKeySize]);
        const uint8_t saved = state[i];
        state[i] = state[j];
        state[j] = saved;
    }
    uint8_t i = 0;
    j = 0;
    for (size_t offset = 0; offset < size; ++offset) {
        i = static_cast<uint8_t>(i + 1);
        j = static_cast<uint8_t>(j + state[i]);
        const uint8_t saved = state[i];
        state[i] = state[j];
        state[j] = saved;
        data[offset] ^= state[static_cast<uint8_t>(state[i] + state[j])];
    }
}

// One CRC64-checked XZ stream, bounded dictionary, exact output size, no suffix.
bool decodeXz(const uint8_t* input, size_t inputSize, uint8_t* output, size_t outputSize);

} // namespace elfprotect_payload
