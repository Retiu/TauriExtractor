#!/usr/bin/env python3
"""
Tauri v2 asset extractor - works on Waifu.exe and similar Tauri apps
Usage: python extract_tauri.py <app.exe> [output_dir]
Requires: pip install brotli
"""
import struct, os, sys, re
try:
    import brotli
except ImportError:
    print("Missing dependency: pip install brotli")
    sys.exit(1)

def extract(exe_path, out_dir='extracted'):
    with open(exe_path, 'rb') as f:
        data = f.read()
    print(f"[*] Loaded {len(data):,} bytes from {exe_path}")

    IMAGE_BASE = 0x140000000
    e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
    coff = e_lfanew + 4
    num_sections = struct.unpack_from('<H', data, coff + 2)[0]
    opt_size = struct.unpack_from('<H', data, coff + 16)[0]
    sect_start = coff + 20 + opt_size

    sections = []
    for i in range(num_sections):
        s = sect_start + i * 40
        name = data[s:s+8].rstrip(b'\x00').decode('ascii', 'replace')
        vaddr = struct.unpack_from('<I', data, s + 12)[0]
        raw_size = struct.unpack_from('<I', data, s + 16)[0]
        raw_off = struct.unpack_from('<I', data, s + 20)[0]
        sections.append((name, vaddr, raw_size, raw_off))

    def va_to_offset(va):
        rva = va - IMAGE_BASE
        for _, vaddr, raw_size, raw_off in sections:
            if vaddr <= rva < vaddr + raw_size:
                return rva - vaddr + raw_off
        return None

    def is_valid_va(va):
        return 0x140000000 <= va <= 0x160000000

    # Find all embedded asset path strings (Tauri uses leading '/')
    path_pattern = re.compile(rb'/(?:assets|_next|vercel\.svg|next\.svg)[/a-zA-Z0-9_.@\-% ]{1,200}')
    path_matches = list(path_pattern.finditer(data))
    print(f"[*] Found {len(path_matches)} path strings")

    # Map each path string's file offset -> virtual address
    path_va_map = {}
    for m in path_matches:
        off = m.start()
        for _, vaddr, raw_size, raw_off in sections:
            if raw_off <= off < raw_off + raw_size:
                rva = off - raw_off + vaddr
                va = IMAGE_BASE + rva
                path_va_map[va] = (m.start(), len(m.group()))
                break

    # Find all 32-byte asset table entries: [path_ptr(8), path_len(8), data_ptr(8), data_len(8)]
    entries = []
    seen_paths = set()

    for path_va, (path_raw, _) in path_va_map.items():
        va_bytes = struct.pack('<Q', path_va)
        search_pos = 0
        while True:
            ptr_pos = data.find(va_bytes, search_pos)
            if ptr_pos == -1:
                break
            search_pos = ptr_pos + 1
            if ptr_pos + 32 > len(data):
                continue
            path_ptr, path_len, data_ptr, data_len = struct.unpack_from('<QQQQ', data, ptr_pos)
            if path_ptr != path_va:
                continue
            if not (0 < path_len < 1000):
                continue
            if not is_valid_va(data_ptr):
                continue
            if not (0 < data_len < 500 * 1024 * 1024):
                continue
            data_off = va_to_offset(data_ptr)
            if data_off is None or data_off + data_len > len(data):
                continue
            try:
                path = data[path_raw:path_raw + path_len].decode('utf-8')
            except:
                continue
            if path in seen_paths:
                continue
            seen_paths.add(path)
            entries.append((path, data_off, data_len))

    print(f"[*] Found {len(entries)} unique assets, decompressing (brotli)...")
    os.makedirs(out_dir, exist_ok=True)
    ok = err = 0
    total_out = 0

    for path, off, length in sorted(entries):
        rel = path.lstrip('/')
        out_path = os.path.join(out_dir, rel.replace('/', os.sep))
        os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
        raw = data[off:off + length]
        try:
            decompressed = brotli.decompress(raw)
        except:
            decompressed = raw  # fallback: store as-is
            err += 1
        with open(out_path, 'wb') as f:
            f.write(decompressed)
        ok += 1
        total_out += len(decompressed)
        print(f"  {len(decompressed):>10,}b  {path}")

    print(f"\n[+] Done! {ok} files extracted to '{out_dir}/'")
    print(f"    Total size: {total_out:,} bytes ({total_out/1024/1024:.1f} MB)")
    if err:
        print(f"    {err} files stored raw (brotli failed)")

if __name__ == '__main__':
    exe = sys.argv[1] if len(sys.argv) > 1 else 'Waifu.exe'
    out = sys.argv[2] if len(sys.argv) > 2 else 'extracted'
    extract(exe, out)
