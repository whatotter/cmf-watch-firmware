#!/usr/bin/env python3
"""
Full recursive extractor for the CMF Watch Pro 2 OTA firmware.

Handles the complete nested container chain:

  outer AOTA (.bin)
    ├─ ota.xml                      (raw, the FAT metadata)
    ├─ TEMP.bin   → inner AOTA      (AOTA magic again)
    │    ├─ ota.xml                 (raw inner FAT metadata)
    │    ├─ app.bin                 (raw ACTHHTCA executable ⇒ Cortex-M firmware)
    │    └─ sdfs.bin                (SDFS container ⇒ kernel/data files)
    ├─ res.bin    → SDFS container  (SVG, .font, watch faces ...)
    ├─ fonts.bin  → SDFS container  (.font, .wfc watch faces ...)
    ├─ res_e.bin  → SDFS container  (.ajs dynamic resources ...)
    └─ sdfs_k.bin → SDFS container  (.act rings, welcome ...)

Container formats (all little-endian):

  1) AOTA  -- file allocation table driven.
     header 0x000 .. 0x1FF; FAT at 0x200, 32-byte entries:
        [0:16] filename      [16:20] offset  [20:24] size
        [24:28] reserved     [28:32] crc32 of the (possibly compressed) region

  2) Each fat *file region* is either raw (ota.xml, app.bin, sdfs.bin) or a
     run of "LZMA blocks":
        block  = 16-byte header + one XZ stream
        hdr[0:4]='LZMA' hdr[4:8]=0x10 00 00 00
        hdr[8:12]= compressed size   hdr[12:16]= uncompressed size
     Decompress each XZ stream and concatenate to obtain the partition.

  3) SDFS (SD File System) -- the resource partitions (res/fonts/res_e/sdfs_k).
     Starts with a directory table of 32-byte entries:
        [0:12] name  [12:16] offset  [16:20] size  [20:28] padding  [28:32] crc
     First entry is always "sdfs.bin" (self reference, offset 0/8-ish).
     Subsequent entries point at raw file data (no compression).

Output tree (default ./partitions):

    partitions/
      ota.xml
      <partition>.bin            (decompressed outer partitions)
      <partition>/               (if SDFS: every file entry)
      TEMP-inner/                (files from inner AOTA)
        app.bin                  (the ACTHHTCA firmware image)
        sdfs.bin
        sdfs.bin/                (if sdfs.bin is itself SDFS)

Usage:
    python3 extract_partitions.py [bin] [outdir]
"""

import lzma
import os
import sys
import struct
import zlib

DEFAULT_BIN = os.path.join("..", "bins", "original 1724161837605-90.bin")
DEFAULT_OUT = os.path.join("..", "partitions")

FAT_OFFSET = 0x200
FAT_ENTRY = 0x20


# ---------------------------------------------------------------------------
# blobs
# ---------------------------------------------------------------------------

def decompress_region(data, offset, size, name):
    """Decompress a region that is a run of LZMA blocks. If the region does not
    start with the LZMA magic, return it verbatim (raw file)."""
    end = offset + size
    if data[offset:offset + 4] != b"LZMA":
        return data[offset:end]

    pos = offset
    out = bytearray()
    while pos + 16 <= end and data[pos:pos + 4] == b"LZMA":
        cs = struct.unpack_from("<I", data, pos + 8)[0]
        us = struct.unpack_from("<I", data, pos + 12)[0]
        xz = data[pos + 16:pos + 16 + cs]
        if len(xz) != cs:
            raise ValueError(f"truncated XZ in {name} @ {pos:#x}")
        block = lzma.decompress(xz)
        if len(block) != us:
            raise ValueError(
                f"size mismatch {name} @ {pos:#x}: hdr {us:#x} != actual {len(block):#x}")
        out += block
        pos += 16 + cs
    return bytes(out)


# ---------------------------------------------------------------------------
# AOTA container
# ---------------------------------------------------------------------------

def parse_aota(data, fat_offset, name):
    """Parse an AOTA FAT table. Returns list of (filename, offset, size, crc)."""
    entries = []
    off = fat_offset
    while off + FAT_ENTRY <= len(data):
        fn = data[off:off + 16].split(b"\x00")[0]
        if not fn:
            break
        o, s = struct.unpack_from("<II", data, off + 16)
        crc = struct.unpack_from("<I", data, off + 28)[0]
        entries.append((fn.decode("ascii", "replace"), o, s, crc))
        off += FAT_ENTRY
    return entries


def is_aota(data):
    return data[:4] == b"AOTA"


# ---------------------------------------------------------------------------
# SDFS container
# ---------------------------------------------------------------------------

def parse_sdfs(data):
    """Parse an SDFS directory. Returns list of (name, offset, size, crc).
    The first entry (sdfs.bin) is the self reference and is skipped by callers
    that only want real files. The directory's length equals the data offset of
    the first real entry divided by the entry size (32), exactly like an AOTA
    FAT.""" 
    entries = []
    off = 0
    # Limit the table using the offset reported by the first non-self entry.
    if len(data) >= 0x40:
        first_data_off = struct.unpack_from("<I", data, 12 + 0x20)[0]
        max_entries = max(0, first_data_off // 0x20)
    else:
        max_entries = 16
    while off + 0x20 <= len(data) and len(entries) < max_entries:
        fn = data[off:off + 12].split(b"\x00")[0]
        if not fn:
            break
        o = struct.unpack_from("<I", data, off + 12)[0]
        s = struct.unpack_from("<I", data, off + 16)[0]
        crc = struct.unpack_from("<I", data, off + 28)[0]
        entries.append((fn.decode("ascii", "replace"), o, s, crc))
        off += 0x20
    return entries


def is_sdfs(data):
    # sdfs containers start with a directory whose first entry is "sdfs.bin"
    return data[:12].split(b"\x00")[0] == b"sdfs.bin"


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------

def write(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def extract_aota(data, outdir, indent=""):
    print(f"{indent}[AOTA] parsing FAT at 0x{FAT_OFFSET:x}")
    for fn, o, s, crc in parse_aota(data, FAT_OFFSET, "aota"):
        payload = decompress_region(data, o, s, fn)
        # The FAT crc is computed over the raw (still-compressed) region data.
        ok = (zlib.crc32(data[o:o + s]) & 0xFFFFFFFF) == crc
        print(f"{indent}  {fn:<12} offset=0x{o:08x} size=0x{s:8x} "
              f"=> {len(payload):#x} bytes crc={'OK' if ok else 'MISMATCH'}")
        if fn.endswith(".bin") and is_aota(payload):
            sub = os.path.join(outdir, fn[:-4])
            extract_aota(payload, sub, indent + "    ")
        elif fn.endswith(".bin") and is_sdfs(payload):
            sub = os.path.join(outdir, fn[:-4])
            extract_sdfs(payload, sub, indent + "    ")
        else:
            write(os.path.join(outdir, fn), payload)


def extract_sdfs(data, outdir, indent=""):
    entries = parse_sdfs(data)
    print(f"{indent}[SDFS] {len(entries)} entries")
    # entry 0 is the self-reference (sdfs.bin)
    for fn, o, s, crc in entries[1:]:
        if not s or o + s > len(data):
            print(f"{indent}  {fn:<16} SKIP (offset 0x{o:x} size 0x{s:x})")
            continue
        payload = data[o:o + s]
        print(f"{indent}  {fn:<16} offset=0x{o:08x} size=0x{s:8x}")
        write(os.path.join(outdir, fn), payload)


def main():
    bin_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BIN
    outdir = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT
    with open(bin_path, "rb") as f:
        data = f.read()
    print(f"file: {bin_path} ({len(data):#x} bytes)\n")
    extract_aota(data, outdir)
    print("\ndone.")


if __name__ == "__main__":
    main()
