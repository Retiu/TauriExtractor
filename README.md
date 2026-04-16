# Tauri Extractor / Tauri Asset Ripper

A python script to extract embedded files and assets from Web-based executables built with the Tauri v2 framework

Tauri v2 bundles all assets directly into the ".rdata" section of the binary, individually compressed with Brotli. This tool locates the asset pointer table, decompresses every entry, and writes them to disk with their original directory structure intact.

> **Note:** This tool was partially written by [Claude](https://claude.ai) (Anthropic). The research of the EXE files of the Tauri v2 framework and reverse engineering was done collaboratively.

## What it extracts

Everything that was bundled at build time — for example from a typical app:

```
assets/images/       PNG, SVG, WEBM, JPG, etc.
assets/sounds/       MP3, WAV, OGG, etc.
assets/models/       VRM, FBX (3D models and animations)
assets/text/         JSON (dialogue, config, etc.)
_next/static/        Next.js JS/CSS chunks and source maps
```

## Requirements ##
- Python 3.10+
- [brotli](https://pypi.org/project/Brotli/)
```
pip install brotli
```

## Usage ##
```
python extract_tauri.py <app.exe>
python extract_tauri.py <app.exe> --out <output_dir>
python extract_tauri.py <app.exe> --out <output_dir> --verbose
```
### Options

| Flag | Default | Description |
|---|---|---|
| `exe` | — | Path to the Tauri `.exe` file |
| `--out DIR` | `extracted/` | Output directory |
| `--verbose` | off | Print each file as it's extracted |

### Example output

```
[*] Reading MyApp.exe
[*] 519,038,976 bytes (495.0 MB)
[*] Scanning for asset table entries...
[*] Found 260 assets (260.3 MB compressed)

[+] Done.
    Extracted : 260 files
    Output    : 661.5 MB -> 'extracted/'
```

## How it works

Tauri v2 stores assets in the `.rdata` section of the PE binary as a static array of 32-byte structs:

```
[path_ptr: u64][path_len: u64][data_ptr: u64][data_len: u64]
```

Each `data_ptr` points to a Brotli-compressed blob. The extractor:

1. Parses the PE section table to build a virtual address → file offset map
2. Scans `.rdata` for embedded path strings matching `/assets/`, `/_next/`, etc.
3. Computes the virtual address of each path string
4. Searches the binary for 32-byte table entries referencing those addresses
5. For each valid entry, reads and Brotli-decompresses the asset data
6. Writes files to disk, preserving the original path structure

## Compatibility

Tested against Tauri v2 x86-64 Windows builds. May not work on:

- Tauri v1 (uses a different asset storage format)
- ARM64 builds (different image base / section layout)
- macOS / Linux Tauri builds (different binary format entirely)

## Limitations

- **Read-only**: this tool only extracts assets. It does not repack or modify binaries.
- **Frontend assets only**: the Rust backend is compiled native code and is not recoverable with this tool.
- **No source maps filtering**: `.js.map` source map files are extracted alongside the JS if they were bundled.

## License

MIT — see [LICENSE](LICENSE).

## Testing ##
This tool was tested with the Steam game [Waifu/Clicker Cuties](https://store.steampowered.com/app/3188910/Clicker_Cuties__Anime_Idler/), if there's any more games or programs using the Tauri v2 framework, feel free to reach out to me for testing so I can update the script incase stuff does not work.
