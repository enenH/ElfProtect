#include "PayloadFormat.h"
#include <xz.h>

namespace elfprotect_payload {

bool decodeXz(const uint8_t* input, size_t inputSize, uint8_t* output, size_t outputSize) {
    static constexpr uint8_t magic[] = {0xFD, '7', 'z', 'X', 'Z', 0};
    if (!input || inputSize < 12 || !output || outputSize < 64 ||
        outputSize > kMaximumElfSize || std::memcmp(input, magic, sizeof(magic)) ||
        input[6] != 0 || input[7] != 4) // Require CRC64, including for malformed streams.
        return false;

    static const bool initialized = [] {
        xz_crc32_init();
        xz_crc64_init();
        return true;
    }();
    (void)initialized;
    xz_dec* decoder = xz_dec_init(XZ_DYNALLOC, kDictionarySize);
    if (!decoder)
        return false;
    xz_buf buffer{};
    buffer.in = input;
    buffer.in_size = inputSize;
    buffer.out = output;
    buffer.out_size = outputSize;
    xz_ret status;
    for (;;) {
        const size_t beforeIn = buffer.in_pos;
        const size_t beforeOut = buffer.out_pos;
        status = xz_dec_run(decoder, &buffer);
        if (status != XZ_OK ||
            (buffer.in_pos == beforeIn && buffer.out_pos == beforeOut))
            break;
    }
    xz_dec_end(decoder);
    return status == XZ_STREAM_END && buffer.in_pos == inputSize &&
           buffer.out_pos == outputSize;
}

} // namespace elfprotect_payload
