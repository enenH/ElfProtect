#!/usr/bin/env python3
"""
ElfProtect Packer — Encrypts an ELF payload and appends it to the loader stub.

Trailer format (appended after the stub):
    [RC4 Encrypted Payload] [32-byte RC4 Key] [8-byte Payload Size LE] [8-byte Magic "ELFPROT\0"]

Usage:
    python pack.py <stub> <payload.so> <output>
"""

import sys
import os
import struct
import secrets

MAGIC = b"ELFPROT\0"
KEY_SIZE = 32


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


def pack(stub_path: str, payload_path: str, output_path: str) -> None:
    with open(stub_path, "rb") as f:
        stub = f.read()

    with open(payload_path, "rb") as f:
        payload = f.read()

    if len(payload) == 0:
        print("[!] Payload is empty", file=sys.stderr)
        sys.exit(1)

    # Verify payload is an ELF
    if payload[:4] != b"\x7fELF":
        print("[!] Payload is not a valid ELF file", file=sys.stderr)
        sys.exit(1)

    # Generate random RC4 key
    key = secrets.token_bytes(KEY_SIZE)

    # Encrypt
    encrypted = rc4_crypt(payload, key)

    # Build trailer
    size_field = struct.pack("<Q", len(encrypted))
    trailer = encrypted + key + size_field + MAGIC

    # Write output
    with open(output_path, "wb") as f:
        f.write(stub)
        f.write(trailer)

    # Preserve executable permission on Unix
    try:
        os.chmod(output_path, 0o755)
    except OSError:
        pass

    print(f"[+] Packed successfully:")
    print(f"    Stub size:    {len(stub)} bytes")
    print(f"    Payload size: {len(payload)} bytes")
    print(f"    Output size:  {len(stub) + len(trailer)} bytes")
    print(f"    Output:       {output_path}")


def main() -> None:
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <stub> <payload.so> <output>")
        print(f"  stub       - compiled ElfProtect loader executable")
        print(f"  payload.so - original ELF shared library to protect")
        print(f"  output     - output protected binary")
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
