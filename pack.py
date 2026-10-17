#!/usr/bin/env python3
"""Append an encrypted, CRC64-checked XZ-v1 ELF payload to a matching loader."""

import argparse
from pathlib import Path

from payload_format import pack_payload, verify_arm64_elf, write_packed


def pack(stub_path: str, payload_path: str, output_path: str) -> None:
    stub_path, payload_path, output_path = map(Path, (stub_path, payload_path, output_path))
    if output_path.resolve() in (stub_path.resolve(), payload_path.resolve()):
        raise ValueError("output must not overwrite the stub or payload input")
    stub = stub_path.read_bytes()
    payload = payload_path.read_bytes()
    verify_arm64_elf(stub, stub_path, require_shared=False)
    verify_arm64_elf(payload, payload_path, require_shared=True)
    protected, compressed_size = pack_payload(stub, payload)
    write_packed(output_path, protected, payload)
    print("[+] Packed successfully:")
    print(f"    Stub size:    {len(stub)} bytes")
    print(f"    Payload size: {len(payload)} bytes")
    print(f"    XZ size:      {compressed_size} bytes (4 MiB dictionary, CRC64)")
    print(f"    XZ ratio:     {compressed_size / len(payload):.2%}")
    print(f"    Output size:  {len(protected)} bytes")
    print(f"    Output:       {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stub", type=Path, help="matching ElfProtect executable or shared-library stub")
    parser.add_argument("payload", type=Path, help="ARM64 shared library")
    parser.add_argument("output", type=Path, help="packed output")
    args = parser.parse_args()
    try:
        pack(args.stub, args.payload, args.output)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
