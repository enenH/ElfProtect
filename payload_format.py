"""Shared ElfProtect XZ-v1 envelope; keep identical in both repositories.

[RC4(XZ ELF)] [32-byte key] [ELF size LE64] [XZ size LE64] [ELFXZ01\\0]
Legacy ELFPROT ZIP envelopes remain readable for existing packed artifacts.
"""

import io
import lzma
import os
from pathlib import Path
import secrets
import struct
import tempfile
import zipfile

MAGIC = b"ELFXZ01\0"
LEGACY_MAGIC = b"ELFPROT\0"
STUB_CAPABILITY = b"ElfProtect:XZ1:LZMA2:4MiB:CRC64"
KEY_SIZE = 32
FIXED_TRAILER_SIZE = 56
XZ_DICTIONARY_SIZE = 4 * 1024 * 1024
MAX_ELF_SIZE = 512 * 1024 * 1024
MAX_FILE_SIZE = 1024 * 1024 * 1024


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 255
        state[i], state[j] = state[j], state[i]
    i = j = 0
    result = bytearray(len(data))
    for offset, value in enumerate(data):
        i = (i + 1) & 255
        j = (j + state[i]) & 255
        state[i], state[j] = state[j], state[i]
        result[offset] = value ^ state[(state[i] + state[j]) & 255]
    return bytes(result)


def verify_arm64_elf(data: bytes, source: Path, *, require_shared: bool) -> None:
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError(f"not a little-endian ELF64 file: {source}")
    kind, machine = struct.unpack_from("<HH", data, 16)
    if machine != 183 or (kind != 3 if require_shared else kind not in (2, 3)):
        raise ValueError(f"not an ARM64 {'shared library' if require_shared else 'ELF stub'}: {source}")


def extract_payload(protected: bytes) -> bytes:
    if len(protected) < 48 or len(protected) > MAX_FILE_SIZE:
        raise ValueError("invalid packed file size")
    magic = protected[-8:]
    if magic not in (MAGIC, LEGACY_MAGIC):
        raise ValueError("unknown payload trailer magic")
    fixed_size = FIXED_TRAILER_SIZE if magic == MAGIC else 48
    if len(protected) < fixed_size:
        raise ValueError("truncated payload trailer")
    compressed_size = struct.unpack_from("<Q", protected, len(protected) - 16)[0]
    key_offset = len(protected) - fixed_size
    if not compressed_size or compressed_size > key_offset:
        raise ValueError("invalid compressed payload size")
    elf_size = struct.unpack_from("<Q", protected, len(protected) - 24)[0] if magic == MAGIC else 0
    if magic == MAGIC and not 64 <= elf_size <= MAX_ELF_SIZE:
        raise ValueError("invalid uncompressed ELF size")
    key = protected[key_offset:key_offset + KEY_SIZE]
    compressed = rc4_crypt(protected[key_offset - compressed_size:key_offset], key)
    try:
        if magic == MAGIC:
            if len(compressed) < 12 or compressed[:8] != b"\xfd7zXZ\0\0\x04":
                raise ValueError("payload must be a CRC64-checked XZ stream")
            # A 5 MiB decoder budget permits our 4 MiB dictionary and decoder
            # state, but rejects the next supported dictionary size (6 MiB).
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ,
                                           memlimit=XZ_DICTIONARY_SIZE + 1024 * 1024)
            payload = decoder.decompress(compressed, max_length=elf_size + 1)
            if not decoder.eof or decoder.unused_data or len(payload) != elf_size:
                raise ValueError("XZ payload length, end marker or trailing data is invalid")
            return payload
        with zipfile.ZipFile(io.BytesIO(compressed)) as archive:
            entries = archive.infolist()
            if len(entries) != 1 or entries[0].filename != "payload.so":
                raise ValueError("legacy ZIP must contain only payload.so")
            if entries[0].is_dir() or entries[0].flag_bits & 1 or entries[0].compress_type not in (
                    zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise ValueError("unsupported legacy ZIP entry")
            if not 64 <= entries[0].file_size <= MAX_ELF_SIZE:
                raise ValueError("invalid legacy ELF size")
            return archive.read(entries[0])
    except (lzma.LZMAError, zipfile.BadZipFile) as error:
        raise ValueError(f"payload decompression/checksum failed: {error}") from error


def verify_packed(protected: bytes, expected_payload: bytes) -> None:
    if extract_payload(protected) != expected_payload:
        raise ValueError("packed payload differs from the source ELF")


def pack_payload(stub: bytes, payload: bytes) -> tuple[bytes, int]:
    if stub[-8:] in (MAGIC, LEGACY_MAGIC):
        raise ValueError("stub already contains a packed payload")
    if STUB_CAPABILITY not in stub:
        raise ValueError("stub does not support XZ-v1; rebuild the loader with the matching sources")
    if not 64 <= len(payload) <= MAX_ELF_SIZE:
        raise ValueError("payload ELF size is out of bounds")
    compressed = lzma.compress(payload, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64,
                               filters=[{"id": lzma.FILTER_LZMA2, "preset": 9,
                                         "dict_size": XZ_DICTIONARY_SIZE}])
    key = secrets.token_bytes(KEY_SIZE)
    protected = (stub + rc4_crypt(compressed, key) + key +
                 struct.pack("<QQ", len(payload), len(compressed)) + MAGIC)
    verify_packed(protected, payload)
    return protected, len(compressed)


def write_packed(output: Path, protected: bytes, expected_payload: bytes) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", prefix=f".{output.name}.", suffix=".tmp",
                                         dir=output.parent, delete=False) as temporary:
            temporary_name = temporary.name
            temporary.write(protected)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_name, 0o755)
        os.replace(temporary_name, output)
        temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
    written = output.read_bytes()
    if written != protected:
        raise ValueError("packed output changed while being written")
    verify_packed(written, expected_payload)
