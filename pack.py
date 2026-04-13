#!/usr/bin/env python3
"""
ElfProtect Packer - wraps an ELF payload in a single-file ZIP, encrypts it,
and appends it to the loader stub.

Trailer format (appended after the stub):
    [RC4 Encrypted ZIP Payload] [32-byte RC4 Key] [8-byte Payload Size LE] [8-byte Magic "ELFPROT\0"]

Usage:
    python pack.py <stub> <payload.so> <output>
"""

import io
import os
import secrets
import struct
import sys
import zipfile

MAGIC = b"ELFPROT\0"
KEY_SIZE = 32
ZIP_ENTRY_NAME = "payload.so"
ZIP_COMPRESSLEVEL = 9


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    result = bytearray(len(data))
    for n in range(len(data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result[n] = data[n] ^ S[(S[i] + S[j]) % 256]
    return bytes(result)


def build_zip_payload(payload: bytes) -> bytes:
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(
        zip_buffer,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=ZIP_COMPRESSLEVEL,
    ) as archive:
        archive.writestr(ZIP_ENTRY_NAME, payload)
    return zip_buffer.getvalue()


def pack(stub_path: str, payload_path: str, output_path: str) -> None:
    with open(stub_path, "rb") as f:
        stub = f.read()

    with open(payload_path, "rb") as f:
        payload = f.read()

    if len(payload) == 0:
        print("[!] Payload is empty", file=sys.stderr)
        sys.exit(1)

    if payload[:4] != b"\x7fELF":
        print("[!] Payload is not a valid ELF file", file=sys.stderr)
        sys.exit(1)

    zip_payload = build_zip_payload(payload)
    if len(zip_payload) == 0:
        print("[!] ZIP payload is empty", file=sys.stderr)
        sys.exit(1)

    key = secrets.token_bytes(KEY_SIZE)
    encrypted = rc4_crypt(zip_payload, key)

    size_field = struct.pack("<Q", len(encrypted))
    trailer = encrypted + key + size_field + MAGIC

    with open(output_path, "wb") as f:
        f.write(stub)
        f.write(trailer)

    try:
        os.chmod(output_path, 0o755)
    except OSError:
        pass

    print("[+] Packed successfully:")
    print(f"    Stub size:    {len(stub)} bytes")
    print(f"    Payload size: {len(payload)} bytes")
    print(f"    ZIP size:     {len(zip_payload)} bytes")
    print(f"    ZIP ratio:    {len(zip_payload) / len(payload):.2%}")
    print(f"    Output size:  {len(stub) + len(trailer)} bytes")
    print(f"    Output:       {output_path}")


def main() -> None:
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <stub> <payload.so> <output>")
        print("  stub       - compiled ElfProtect loader executable")
        print("  payload.so - original ELF shared library to protect")
        print("  output     - output protected binary")
        sys.exit(1)

    stub_path = sys.argv[1]
    payload_path = sys.argv[2]
    output_path = sys.argv[3]

    if not os.path.isfile(stub_path):
        print(f"[!] Stub not found: {stub_path}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(payload_path):
        print(f"[!] Payload not found: {payload_path}", file=sys.stderr)
        sys.exit(1)

    pack(stub_path, payload_path, output_path)


if __name__ == "__main__":
    main()
