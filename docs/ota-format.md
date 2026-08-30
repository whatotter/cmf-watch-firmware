# CMF Watch Pro 2 OTA Firmware Format

This documents the fully decoded binary format of the CMF Watch Pro 2
firmware dump (`bins/original 1724161837605-90.bin`). All multi-byte values
are little-endian. The SoC is an **Actions Technology ATS3089C** (ARM
Cortex-M4F-class core, MStar CPU @ 202 MHz, Zephyr RTOS + LVGL).

## Big picture

The file is an **`AOTA`** (Actions OTA) container: an uncompressed, CRC32-only
protected archive that nests several more containers.

```
bins/original ... .bin            AOTA container (outer)
├─ ota.xml                        raw XML FAT metadata
├─ TEMP.bin  ──► AOTA container (inner)
│   ├─ ota.xml                    raw XML FAT metadata
│   ├─ app.bin                    ACTHHTCA executable  ⇒ the Cortex-M firmware
│   └─ sdfs.bin ──► SDFS container (10 files: BT cal, configs)
├─ res.bin   ──► SDFS container   (83 files: .font, .svg watch faces, i18n)
├─ fonts.bin ──► SDFS container   (10 files: .font, .wfc watch faces)
├─ res_e.bin ──► SDFS container   (20 files: .ajs dynamic resources)
└─ sdfs_k.bin ──► SDFS container  (18 files: rings, fcc.bin, welcome.act)
```

## 1. AOTA header (offset 0x000, 512 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0x000 | 4   | magic `AOTA` |
| 0x004 | 4   | CRC32 of header + FAT (range 0x008..0x3FF) |
| 0x008 | 4   | flags (`00 01 00 04`) |
| 0x00C | 4   | file count (6 in the outer file) |
| 0x010 | 2   | FAT offset (always 0x200) |
| 0x012 | 2   | data offset (always 0x400) |
| 0x014 | 4   | total file size (with sector padding) |
| 0x018 | 4   | CRC32 of payload (0x400..EOF) |
| 0x040 | 32  | build/version string (`1.00_2408181820`) |
| 0x060 | 30  | platform id (`jx402_01_3089c`) |
| 0x07E | 2   | hardware revision |
| 0x080 | 4   | slot A/B protection flags |

## 2. FAT / directory table (offset 0x200, 32-byte entries)

Up to 16 entries; terminated by an all-zero name.

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 16 | filename (NUL padded) |
| 0x10 | 4  | absolute byte offset of the file **region** |
| 0x14 | 4  | size of the file **region** |
| 0x18 | 4  | reserved (0) |
| 0x1C | 4  | **CRC32 of the raw (still compressed) region** |

> The FAT CRC is over the compressed region bytes, *not* the decompressed
> output. The `info.xml` checksums, by contrast, are over the *decompressed*
> whole partition. Both use standard zlib crc32.

## 3. LZMA block container (inside file regions)

A file region that isn't just raw bytes is a concatenation of **LZMA blocks**.
Most partitions (`TEMP.bin`, `res.bin`, `fonts.bin`, `res_e.bin`, `sdfs_k.bin`)
are 2 KiB → tons of these; `ota.xml` and `app.bin` are raw (uncompressed).

Each block = a 16-byte header followed by **one XZ stream**:

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 4 | magic `LZMA` |
| 0x04 | 4 | `0x10 00 00 00` (header size 16) |
| 0x08 | 4 | compressed size of the XZ stream |
| 0x0C | 4 | uncompressed size after decompression |

The XZ stream starts immediately at `+0x10` (`\xfd7zXZ\x00`). Decompress it,
verify length == uncompressed size, concatenate all blocks ⇒ one partition.

Partition decompressed sizes (match `orig_size` in info.xml):

| Region | LZMA blocks | decompressed |
|--------|-------------|--------------|
| TEMP.bin | 2   | 0x25ba00 |
| res.bin  | 276 | 0x89da80 |
| fonts.bin| 291 | 0x912900 |
| res_e.bin|1794 | 0x380de00 |
| sdfs_k.bin| 16 | 0x7ff40 |

## 4. SDFS container (res/fonts/res_e/sdfs_k and inner sdfs.bin)

The resource partitions are **SDFS** (SD File System) images. The first entry
of their directory is the self-reference `sdfs.bin`; the table's length equals
`(data offset of the 1st real entry) / 32`. Entries are 32 bytes:

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 12 | filename |
| 0x0C | 4  | byte offset of file data |
| 0x10 | 4  | size |
| 0x14 | 8  | padding |
| 0x1C | 4  | crc |

File data is raw (not LZMA). Notable contents:
- `res.bin` → `num*.font`, `tiger.svg`, `bt_watch.{lang}` i18n files
- `fonts.bin` → `sans32.font`, `local*.wfc` watch faces
- `res_e.bin` → `*.ajs` dynamic resources
- `sdfs_k.bin` → `welcome.act`, `ring*.act`, `fcc.bin`, `logo.res`

## 5. ACTHHTCA boot header (app.bin, 40 bytes)

`app.bin` (the actual firmware) starts with an **Actions boot header**:

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 8  | magic `ACTHHTCA` |
| 0x08 | 4  | load address (reset vector in flash) e.g. `0x10102ec8` |
| 0x0C | 4  | block size (`0x62`) |
| 0x10 | 4  | padding (0) |
| 0x14 | 4  | exec address (= load addr) |
| 0x18 | 4  | boot-stub entry point (end of stub code) |
| 0x1C | 4  | header signature |
| 0x20 | 4  | payload signature |
| 0x24 | 4  | IVT offset (`0x200`) |

A Cortex-M interrupt vector table lives at IVT offset `0x200`:
- `0x200` initial MSP (`0x2ffb3940`)
- `0x204` reset vector (`0x10102ec9`, thumb bit set)
- then peripheral handlers.

## Repacking

Repacking must:
1. decompress each partition back to LZMA blocks (re-xz in ≤ the original
   block sizes),
2. keep hardware constants in the ACTH boot header and FAT,
3. recompute FAT crc32 (compressed regions), payload crc32, and header crc32.

## References / prior work

- `purrrock/ATS3085S_firmware_packer` (docs + pack/unpack tools for the very
  similar ATS3085S / G1 watch)
- `ambraglow/cmfparser` (OTA unpacker for the same ATS3089C / CMF Watch 2&3
  Pro)
- Quarkslab blog post "Weeks of Firmware Teardown" (mapping raw app code in a
  Ghidra/IDA rebase flow)
