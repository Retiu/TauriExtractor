#!/usr/bin/env python3
"""
TauriExtractor - Extract embedded assets from Tauri v2 Windows executables.

Assets in Tauri v2 PE binaries are stored in the .rdata section as a static
pointer table with entries of the form:
    [path_ptr: u64][path_len: u64][data_ptr: u64][data_len: u64]

Each asset is individually Brotli-compressed. This script locates all table
entries, decompresses the data, and writes files to disk preserving the
original directory structure.

Usage:
    python extract_tauri.py <app.exe>
    python extract_tauri.py <app.exe> --out <output_dir>
    python extract_tauri.py <app.exe> --out <output_dir> --verbose
"""

import argparse
import os
import re
import struct
import sys

try:
    import brotli
except ImportError:
    print("Error: 'brotli' is not installed. Run:  pip install brotli")
    sys.exit(1)


# Tauri v2 x86-64 PE binaries use this image base.
PE_IMAGE_BASE = 0x140000000

# Upper bound for valid virtual addresses in the asset table.
# Tauri v2 binaries observed in the wild use data pointers up to ~0x15C000000.
VA_UPPER_BOUND = 0x160000000

# Maximum plausible path length and asset size.
MAX_PATH_LEN = 1000
MAX_ASSET_SIZE = 500 * 1024 * 1024  # 500 MB

# Regex matching Tauri asset path strings embedded in the binary.
# Tauri stores paths with a leading slash, e.g. /assets/images/icon.png
PATH_PATTERN = re.compile(
    rb'/(?:assets|_next|vercel\.svg|next\.svg)[/a-zA-Z0-9_.@\-% ]{1,200}'
)


def parse_pe_sections(data: bytes) -> list[tuple]:
    """Parse the PE section table and return a list of (name, vaddr, raw_size, raw_off)."""
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    coff_offset = e_lfanew + 4
    num_sections = struct.unpack_from('<H', data, coff_offset + 2)[0]
    opt_header_size = struct.unpack_from('<H', data, coff_offset + 16)[0]
    section_table_offset = coff_offset + 20 + opt_header_size

    sections = []
    for i in range(num_sections):
        entry = section_table_offset + i * 40
        name = data[entry:entry + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        vaddr    = struct.unpack_from('<I', data, entry + 12)[0]
        raw_size = struct.unpack_from('<I', data, entry + 16)[0]
        raw_off  = struct.unpack_from('<I', data, entry + 20)[0]
        sections.append((name, vaddr, raw_size, raw_off))

    return sections


def make_va_to_offset(sections: list[tuple]):
    """Return a function that converts a virtual address to a raw file offset."""
    def va_to_offset(va: int) -> int | None:
        rva = va - PE_IMAGE_BASE
        for _, vaddr, raw_size, raw_off in sections:
            if vaddr <= rva < vaddr + raw_size:
                return rva - vaddr + raw_off
        return None
    return va_to_offset


def is_valid_va(va: int) -> bool:
    return PE_IMAGE_BASE <= va <= VA_UPPER_BOUND


def find_assets(data: bytes, sections: list[tuple], va_to_offset) -> dict[str, tuple[int, int]]:
    """
    Locate all asset table entries in the binary.

    Returns a dict mapping asset path -> (raw_file_offset, compressed_length).
    """
    # Step 1: find all embedded path strings and compute their virtual addresses.
    path_va_map: dict[int, tuple[int, int]] = {}  # path_va -> (raw_off, raw_len)

    for match in PATH_PATTERN.finditer(data):
        raw_off = match.start()
        for _, vaddr, raw_size, sect_raw_off in sections:
            if sect_raw_off <= raw_off < sect_raw_off + raw_size:
                rva = raw_off - sect_raw_off + vaddr
                va  = PE_IMAGE_BASE + rva
                path_va_map[va] = (raw_off, len(match.group()))
                break

    # Step 2: for each path VA, scan the binary for a matching 32-byte table entry:
    #   [path_ptr: u64][path_len: u64][data_ptr: u64][data_len: u64]
    assets: dict[str, tuple[int, int]] = {}

    for path_va, (path_raw_off, _) in path_va_map.items():
        needle = struct.pack('<Q', path_va)
        search_from = 0

        while True:
            ptr_pos = data.find(needle, search_from)
            if ptr_pos == -1:
                break
            search_from = ptr_pos + 1

            if ptr_pos + 32 > len(data):
                continue

            path_ptr, path_len, data_ptr, data_len = struct.unpack_from('<QQQQ', data, ptr_pos)

            if path_ptr != path_va:
                continue
            if not (0 < path_len < MAX_PATH_LEN):
                continue
            if not is_valid_va(data_ptr):
                continue
            if not (0 < data_len < MAX_ASSET_SIZE):
                continue

            data_off = va_to_offset(data_ptr)
            if data_off is None or data_off + data_len > len(data):
                continue

            try:
                path = data[path_raw_off:path_raw_off + path_len].decode('utf-8')
            except UnicodeDecodeError:
                continue

            if path not in assets:
                assets[path] = (data_off, data_len)

    return assets


def extract(exe_path: str, out_dir: str, verbose: bool = False) -> None:
    print(f"[*] Reading {exe_path}")
    with open(exe_path, 'rb') as f:
        data = f.read()
    print(f"[*] {len(data):,} bytes ({len(data) / 1024 / 1024:.1f} MB)")

    sections = parse_pe_sections(data)
    va_to_offset = make_va_to_offset(sections)

    if verbose:
        print("[*] PE sections:")
        for name, vaddr, raw_size, raw_off in sections:
            print(f"      {name:<10} raw={raw_off:#010x}  size={raw_size / 1024 / 1024:.1f} MB")

    print("[*] Scanning for asset table entries...")
    assets = find_assets(data, sections, va_to_offset)
    compressed_total = sum(length for _, length in assets.values())
    print(f"[*] Found {len(assets)} assets ({compressed_total / 1024 / 1024:.1f} MB compressed)")

    os.makedirs(out_dir, exist_ok=True)

    extracted   = 0
    failed      = 0
    output_total = 0

    for path, (raw_off, compressed_len) in sorted(assets.items()):
        relative = path.lstrip('/')
        out_path = os.path.join(out_dir, relative.replace('/', os.sep))
        os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)

        compressed = data[raw_off:raw_off + compressed_len]

        try:
            file_data = brotli.decompress(compressed)
        except brotli.error:
            # Store raw bytes on decompression failure rather than silently dropping.
            file_data = compressed
            failed += 1
            print(f"  [WARN] Brotli failed, storing raw: {path}")

        with open(out_path, 'wb') as f:
            f.write(file_data)

        extracted    += 1
        output_total += len(file_data)

        if verbose:
            print(f"  {compressed_len:>10,} -> {len(file_data):>10,}  {path}")

    print(f"\n[+] Done.")
    print(f"    Extracted : {extracted} files")
    print(f"    Output    : {output_total / 1024 / 1024:.1f} MB -> '{out_dir}/'")
    if failed:
        print(f"    Warnings  : {failed} file(s) stored raw (Brotli decompression failed)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract Brotli-compressed assets from a Tauri v2 Windows executable.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python extract_tauri.py MyApp.exe
  python extract_tauri.py MyApp.exe --out ./assets
  python extract_tauri.py MyApp.exe --out ./assets --verbose
        """
    )
    parser.add_argument('exe',         help="Path to the Tauri .exe file")
    parser.add_argument('--out',       default='extracted', metavar='DIR',
                        help="Output directory (default: extracted/)")
    parser.add_argument('--verbose',   action='store_true',
                        help="Print each extracted file")
    args = parser.parse_args()

    if not os.path.isfile(args.exe):
        parser.error(f"File not found: {args.exe}")

    extract(args.exe, args.out, verbose=args.verbose)


if __name__ == '__main__':
    main()
