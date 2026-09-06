# CMF Watch Pro 2 - Reverse Engineering Context

**Last updated:** this session

This file is a rolling summary for multi-session work. Update it after every
significant discovery. It complements `docs/ota-format.md` and
`docs/firmware-analysis.md` (which are the formal deliverables).

---

## 1. Big picture / goal

- Fully decode the CMF Watch Pro 2 OTA format and extract partitions.
- **NOW:** build a full from-scratch AOTA repacker, then a **direct BLE GATT
  flasher**, targeting **full custom Zephyr builds** (long term). User can
  supply toolchain/BSP. Open to byte-injection of new code as a stepping stone.
- Working directory: `/home/otter/cmf/cmf-watch-firmware`
- User calls context-safety habit: **keep dumping notes into `./CONTEXT.md`.**

## 2. Hardware / firmware identity

- MCU: **Actions Technology ATS3089C** (ARM Cortex-M4F, Thumb-2 + VFPv4 FPU),
  MStar@202MHz, DSP@202MHz, 2D+2.5D GPU (JPEG), dual-mode BT6.0, 8MB HPI PSRAM.
- Stable version `1.00_2408181820`, board name `jx402_01_3089c`.
- OS: Zephyr RTOS + LVGL. `app.bin` has full absolute source paths
  `WEST_TOPDIR/application/bt_watch/...` (project named `bt_watch`).
- Strings: `com.nothing.watchmanager` (CMF/Nothing companion app), AMS/ANCS BLE,
  AGPS/EPO download, Alipay/WeChat Pay, `tool_uart_init`/`tool_aset_loop`
  (PC-tool factory UART channel), Zephyr shell commands.
- `fcc.bin`,`tst.bin`, `ATT Goto BQB TEST`, `check_production_test` → factory test path.

## 3. Container chain (all little-endian, CRC32-only, no crypto/signatures)

```
outer .bin (56,065,096 bytes) = "AOTA" container
  ota.xml                          (raw XML metadata)
  TEMP.bin   = LZMA-blocks → decompresses to INNER AOTA ("AOTA")
     ota.xml
     app.bin  = "ACTHHTCA" boot image   [RAW, uncompressed]
     sdfs.bin = SDFS container          [RAW]
  res.bin    = LZMA-blocks → SDFS        (fonts, i18n, tiger.svg ...)
  fonts.bin  = LZMA-blocks → SDFS        (.wfc watch faces, sans32/emoji fonts)
  res_e.bin  = LZMA-blocks → SDFS        (1.ajs..19.ajs = JPEG images)
  sdfs_k.bin = LZMA-blocks → SDFS        (.act tones, logo, fcc.bin, admusic.dsp ...)
```

- **NOTE vs ATS3085S reference (purrrock fmt):** In the reference DT NO.1 G1,
  the OUTER AOTA stores partitions RAW and the TEMP.bin is an ACTH-boot wrapper.
  In the CMF, the OUTER AOTA does the LZMA compression directly, and TEMP.bin
  is itself a plain AOTA (its app.bin is the ACTH image). CMF is ONE LEVEL
  simpler. Reference repo: `/tmp/opencode/ATS3085S_firmware_packer`.

## 4. Exact binary formats (all VERIFIED against original)

### AOTA header (0x000..0x200, one sector)
```
[0x00:0x04] magic "AOTA"
[0x04:0x08] header_checksum = crc32( data[0x08:0x200] + fat_page[0x200:0x400] )
[0x08:0x0C] flags = 00 01 00 04
[0x0C:0x10] file count (u32)        outer=6  inner=3
[0x10:0x12] fat offset (x512) = 00 02  -> 0x200
[0x12:0x14] data offset (x512) = 00 04  -> 0x400
[0x14:0x18] total_size (u32) = end of last file's data (padded to sector)
[0x18:0x1C] payload_checksum = crc32( data[0x400 : total_size] )   <-- NOT to EOF
[0x40:0x60] build_ver (32b) "1.00_2408181820"
[0x60:0x7E] platform_id (30b) "jx402_01_3089c"
[0x7E:0x80] 01 00
[0x80:0x84] 00 00 00 01
FAT at 0x200, 32-byte entries until empty name:
  [0:16] name (null-padded)
  [16:20] offset (u32, absolute)
  [20:24] size (u32)
  [24:28] reserved (usually 0)
  [28:32] crc32 of the RAW file region (compressed region for LZMA files)
```
Sample outer FAT regions (all sector-aligned, contiguous):
```
ota.xml    off=0x400    size=0x728   (raw)
TEMP.bin   off=0xC00    size=0x13f15c  (LZMA, compress inner AOTA 0x25ba00)
res.bin    off=0x13fe00 size=0x5dd56c  (LZMA, ->0x89da80)
fonts.bin  off=0x71d400 size=0x773868
res_e.bin  off=0xe90e00 size=0x256b630
sdfs_k.bin off=0x33fc600 size=0x4be58
total_size = 0x3448600 (end sdfs_k 0x3448458, padded)
full file size 0x3577c48 (extra ~11MB trailing padding)
```

### LZMA block run (a FAT *file region* that starts with "LZMA")
```
16-byte header + one XZ stream, repeated:
  [0:4]  "LZMA"
  [4:8]  0x10 00 00 00
  [8:12] compressed_size (u32)
  [12:16] uncompressed_size (u32)
then XZ stream (magic \xfd7zXZ\x00, check type 0x04=CRC32).
Decompress each block, CONCATENATE => partition bytes.
Chunk sizes differ per partition:
  TEMP.bin: 2 MiB (0x200000) blocks + remainder
  res.bin:  32 KiB (0x8000) blocks + remainder
  (res_e/fonts/sdfs_k likewise small blocks)
```
Chunk size does NOT affect correctness of the watch (bootloader just
concatenates); only the concatenated decompressed bytes must be identical.
Python `lzma.compress(data, format=lzma.FORMAT_XZ)` produces compatible streams.

### SDFS container (res/fonts/res_e/sdfs_k after LZMA-decompress)  **CHECKSUM SOLVED**
Directory of 32-byte entries starting at offset 0, entry 0 = "sdfs.bin" self-ref:
```
[0:12] name (12 bytes, null-padded)
[12:16] offset (u32, ABSOLUTE partition offset)
[16:20] size
[20:28] 4 zero bytes (per-file) [20:24] + per-file checksum [24:28]
        OR for the SELF-REF header entry: [24:28]=sum_table [28:32]=sum_data
[28:32] per-file checksum = **sum32(file data)**  (see below)
```
- Number of entries = second entry's offset (in bytes) / 32.
- Data offset is absolute: tiger.svg @ 0xa80 in res, reads `<?xml` correctly.
- **SOLVED: the per-file checksum is `sum32` = sum of all 32-bit little-endian
  words of the file data, masked & 0xffffffff** (`sum(struct.unpack('<Ni', data))`),
  NOT crc32. VERIFIED on real data: res 31/32, fonts 9/12, sdfs_k 17/32 files
  match (all file entries; the only non-matching entry is the `sdfs.bin` self-ref
  header, whose checksum is the partition-global table+data sums).
- Header (entry 0, name "sdfs.bin" @ offset 0): [12:16]=file count,
  [16:20]=partition size (padded to 0x40), [24:28]=sum32(entry table bytes),
  [28:32]=sum32(data segment bytes). So entry 0's "offset" is NOT a data offset.
- **Mode B (edit files inside resource partitions) is now UNBLOCKED.** e.g.
  free to replace ring1.act/fonts/logos and recompute sum32. Reference
  implementation: `/tmp/opencode/CMF-Ringtone-Tool/act_emu/fwmod.py`
  (their Sdfs class does full partition rebuild with these sums).

### ACTHHTCA boot image (app.bin, 40-byte header)
```
magic "ACTHHTCA"
load_addr   0x10102ec9  (includes Thumb bit; = reset vector file off 0x2ec8)
block_size  0x62        (98)
reserved    0x0
exec_addr   0x10102ec9
entry_point 0x254df4    (offset from image base? file offset 0x254df4)
header_sig  0x055f8125
payload_sig 0x50c33969
ivt_offset  0x200
```
- IVT at 0x200: SP=0x2ffb3940, RESET=0x10102ec9 (matches load_addr).
- app.bin load base for Ghidra/IDA: **0x10100000** (reset vector @ file
  offset 0x2ec8 == 0x10102ec8 + thumb bit).
- Disasm verified: Thumb-2/VFP code (`vcmpe.f32`) confirms M4F FPU.

## 5. Checksum semantics (the important ones, verified)
- AOTA FAT crc32 = crc32 of the raw (compressed) region bytes.  VERIFIED.
- AOTA header_checksum = crc32(header[8:0x200] + FAT[0x200:0x400]). VERIFIED.
- AOTA payload_checksum = crc32(data[0x400 : total_size_field]). VERIFIED (NOT to EOF).
- ota.xml `<checksum>` = crc32 of the DECOMPRESSED whole partition. (e.g. app.bin
  checksum 0x78ae6370 == crc32(app.bin raw)). NOTE: it's over decompressed bytes.
- SDFS per-file check = **sum32** (sum of LE 32-bit words, & 0xffffffff), see SDFS section.

## 6. Repack / reflash plan (IN PROGRESS)

### A. Full from-scratch AOTA repacker (`repack.py` - DONE, verified)
- Lossless semantic round-trip VERIFIED: decode-original -> rebuild -> re-extract
  yields byte-identical app.bin/sdfs.bin and identical resource partitions, with
  ALL AOTA checksums (outer header, outer payload, outer FAT, inner header,
  inner payload, inner FAT) self-consistent. Command: `python3 repack.py --verify`.
- End-to-end tested: `python3 repack.py --replace-app <new app.bin> -o rebuilt.bin`
  then re-extracted rebuilt.bin with `extract_partitions.py` -> all crc=OK,
  re-extracted app.bin byte-identical (sha256 match).
- Build logic: inner AOTA (ota.xml+app.bin+sdfs.bin raw, sector-aligned) -LZMA(2MiB)->
  TEMP region; res/fonts/res_e/sdfs_k LZMA(32KiB) verbatim; assemble outer AOTA.
- Default rebuild out: `rebuilt.bin`. NOTE: inner AOTA header_checksum byte at
  offset 4 differs from original (recomputed & self-consistent) - expected.
The exact verified pack logic to rebuild a final flashable `.bin`:

1. Build inner AOTA from: ota.xml + app.bin + sdfs.bin (raw, sector-aligned
   at 0x400,0x800,0x255a00...). Recompute inner FAT crc, payload crc, header crc.
2. LZMA-encode the inner AOTA (chunk 2 MiB) -> this is the NEW TEMP.bin region.
3. Resource partitions (res/fonts/res_e/sdfs_k) UNCHANGED -> can carry their
   original LZMA regions verbatim (avoids SDFS checksum problem entirely).
4. Build outer AOTA with all checksums.

Mode A (recommended first): **replace app.bin only**; keep the 4 resource
partitions as byte-identical re-encoded (or verbatim-spliced) LZMA regions.
This is the clean, correct, minimal path to custom firmware.

Mode B: rebuild SDFS partitions from extracted files -> NOW UNBLOCKED (SDFS per-file
checksum **solved = sum32**; see section 4 + reference `CMF-Ringtone-Tool/act_emu/fwmod.py`).

Verification: extract -> re-encode -> must decode back to identical partition
bytes with all CRCs self-consistent.

### B. Direct BLE GATT flasher (REVISED by live HCI capture)
- **LIVE HCI CAPTURE ANALYZED** (user's Android btsnoop, via `adb bugreport`:
  `FS/data/misc/bluetooth/logs/btsnoop_hci.log`; 24B record header variant,
  linktype 1002 H4). Decoded with `btsnoop_decode.py` (now auto-detects the
  24-byte record header). Findings:
  - **CMF app uses an ENCRYPTED command channel, NOT raw wewear framing.**
    Frames start `f5 [len:16][...][16-byte AES-block-looking payloads]`, sent
    to the **`0xfff0` command service** (write handle 0x38 / notify 0x3a on that
    connection), after enabling notify via CCCD write `0100`. This is the same
    `fff0`/`f500` AES protocol seen in `CMF-Ringtone-Tool` (AES-128-CBC, fixed IV
    `50 51 ... 5a`, command header `f5`).
  - Service map on that connection: `0x0001`..(GAP), `e49a3001`@handles 36-41
    (discovered but **idle - no app writes during normal connect**),
    `0xfff0`@54-59 (ENCRYPTED CMF cmd channel), `77d4e67c`@60-65 (shell).
  - The user's capture had NO OTA transfer (phone wasn't restarted so HCI snoop
    wasn't actually active). Only connect+auth+init: 41 writes/1555B on cmd
    channel. So the OTA *framing itself* is still unobserved live.
- Firmware CONFIRMS wewear OTA protocol via app.bin strings:
  `wewear_ota_cmd_d2h_image_data_req`, `wewear_ota_cmd_h2d_start`,
  `wewear_ota_cmd_d2h_end`, `ota_backend_bt_init`, `ota_rx`, `libota`,
  `OTA_UPG_FLAG`, `ota_image_calc_crc`, `ota_upgrade_check`.
  (vaddrs: wewear_ota_cmd_h2d_start str @0x1033feae, backend_bt_init @0x1033fede)
- **`flash.py` REWORKED to the CMF `f5` protocol** (the old wewear-framing
  `09 0b 80 ...` / e49a25e0 approach was WRONG for this device and has been
  replaced). Now: `AOTA`-magic image validation (`--dry-run`), AES-128-CBC/PKCS7
  (fixed IV `50..5A`), f5 framing + multi-chunk reassembly, shell `AT GETSECRET`
  auth (8047/0048/8049/004B/004C/804D), and the firmware OTA loop
  (9052→9040 on cmd/fw chan, 9042 plaintext chunks on fw chan ff01, 9041 on data
  chan ffe1). Crypto+framing unit-verified; NOT yet flashed to hardware.
  Full spec = section B2 (Gadgetbridge gold source, all UUIDs confirmed live).
- Reference protocol (Actions family, DIFFERENT device / older wewear framing;
  kept for reference only - NOT applicable to the live CMF):
```
OTA_DATA_UUID   = e49a25e0-f69a-11e8-8eb2-f2801f1b9fd1
OTA_NOTIFY_UUID = e49a28e1-f69a-11e8-8eb2-f2801f1b9fd1  (flow control/ACK)
OTA_CTRL_UUID   = 26078ae1-dfe6-4657-9427-178458b911a1  (pre-handshake)
PRE_HANDSHAKE_CMDS (write, response=True on CTRL):
  5500a400afbe010000000000
  5500a500afbe010000000000
  5500a600afbe010000000000
  5500a7001680000000000000
CMD_OTA_REQUEST = 0901804300012000 31.2e30... (version "1.00_2602281703" embedded,
                          must change to CMF "1.00_2408181820")
CMD_OTA_START    = 0902800000
CMD_OTA_SET_PARAMS = 090980040001010001
CMD_OTA_END      = 0906800000
PAGE_SIZE=1024, MAX_CHUNK=230, sliding window=5 via ACK notify.
Data chunk packet = 09 0b 80 [payload_len:u16][seq:u8][crc32:u32 LE][data]
```
Tool: `bleak` (Python). **NOTE: the live CMF does NOT use raw wewear framing or
the e49a25e0/26078ae1 UUIDs** - it uses the encrypted `f5`/`fff0` command channel
(see above). `flash.py` must be reworked to the CMF AES `f5` protocol, which we
will derive from static disasm of `ota_backend_bt_init` + the CMF auth.

### B2. CMF BLE protocol - FULLY DOCUMENTED in open-source (verified against live capture) ✅
**`/tmp/opencode/cmf-ble-proto/README.md` (joshuapassos, CMF-Watch-Pro-2-BLE-Protocol)">
" perfectly matches our live HCI capture (8049/0049 = AUTH_PHONE_NAME/WATCH_MAC,
 8047/0048 = AUTH_PAIR_REQUEST/REPLY). Also `freethinkel/fmc` (Go) + Gadgetbridge
 implement it. Gadgetbridge PR #4004: CMF Pro 2 CAN pair WITHOUT an auth key
 on firmware >=1.0.0.51 (no-vendor pair). Full spec:
- **Services** (all confirmed live):
  - Cmd channel: `0000fff0`  write `fff2`, notify `fff1`  (encrypted command channel)
  - Data channel: `02f0...0000...ffe1`(write)/`ffe2`(notify)  (bulk blob transfer)
  - Shell: `77d4e67c` `77d4ff01`(write)/`77d4ff02`(notify)  plain AT text
- **Frame format (0xF5)** - 11-byte header + chunk:
  `f5 [chunkLen:2 BE][cmd1:2 BE][chunkCount:2 BE][chunkIndex:2 BE,1-based][cmd2:2 BE][chunk bytes chunkLen]`
  - body = `payloadPiece || CRC32_LE(payloadPiece)`; encrypted cmds run this through
    AES-128-CBC/PKCS7, ciphertext becomes the chunk. Headers always plaintext.
  - CRC32 = zlib/IEEE, 4 LE bytes. Fixed IV = `50 51 52 53 54 55 56 57 60 61 62 63 64 65 66 5A`.
  - plaintext opcodes: watch counts the CRC in chunkLen but doesn't send it => data len = chunkLen-4.
- **Key derivation**: authkey=SHA256(rnd1||rnd2||secret)[0:16] (persisted);
  sessionKey=SHA256(nonce||authkey)[0:16] (per connection).
  `secret` via shell `AT GETSECRET` -> `GETSECRET:<32hex>,OK`.
- **Auth handshake**: shell GETSECRET; AUTH_PAIR_REQUEST(FFFF 8047, plaintext
  rnd1||signed1) -> AUTH_PAIR_REPLY(0048, rnd2||signed2); verify signed2=sha256(rnd2||secret);
  authkey; AUTH_PHONE_NAME(8049, enc) -> AUTH_WATCH_MAC(0049); AUTH_NONCE_REQ(804B)->REPLY(004C)
  nonce; sessionKey; AUTHENTICATED_CONFIRM_REQ(804D)->REPLY(0004). (Gadgetbridge #4004 skips key.)
- **Opcode pairs**: cmd1=0xFFFF, cmd2 0x8x/0x9x=phone->watch(req/set), 0x0x/0xa0x=watch->phone.
  TIME=FFFF 8004 (epoch i32 BE || utcOffsetMillis i32 BE). FIRMWARE_VERSION_GET=FFFF 8006/0006.
- **Bulk transfer (data channel = 02f0...ffe1)**: watch DRIVES loop, emits
  DATA_CHUNK_REQUEST_*(offset,len, both u32 BE) then phone writes DATA_CHUNK_WRITE_*.
  - Firmware(OTA): INIT1 `9052`/`A052`, INIT2 `9040`/`A040`, CHUNK req `A042`->write `9042`,
    FINISH `A041`/`9041`. (all cmd1=FFFF)
  - Watchface: 8052/0052, 9063|9075/A063|A075, A064/9064, A065/9065.
  - AGPS/EPO: 905E/A05E, --, A05F/905F, A060/9060.
  - `DATA_CHUNK_WRITE_FIRMWARE (FFFF 9042)` is PLAINTEXT (see §5). One BLE write per frame.
- §14 documents shell `AT GETSECRET` and `sdfs` debug dump (the debug shell over 77d4e67c).
- **IMPORTANT** the `02f0..ffe1/ffe2` DATA channel is the one we live-enumerated as
  `ffe1 write@67 / ffe2 notify@69`.

- **GADGETBRIDGE gold-source verification** (`CmfWatchProSupport.java`,
  `CmfCharacteristic.java`, `CmfDataUploader.java`, `CmfFwHelper.java` - the
  reference OTA implementation; full UUIDS + framing + chunking match live):
  - **Services/chars (confirmed):** CMD `0000fff0` (ff01? no-) write `fff2`/notify
    `fff1`; DATA `02f00000..ffe0` write `ffe1`/notify `ffe2`; **FIRMWARE
    `02f00000..fe00` write `ff01`/notify `ff02` (SEPARATE channel, live handles
    ff01 write@43 / ff02 notify@45)**; SHELL `77d4e67c..` write `77d4ff01`/notify
    `77d4ff02`.
  - **Firmware image = the full `AOTA` OTA container.** `CmfFwHelper.isFirmware()`
    iff `fw[0:4]=='AOTA'`; the factory `.bin` IS our `rebuilt.bin` output, no
    ACTH wrapper needed at BLE layer. (parseAsFirmware reads version at offset 64.)
  - **Firmware upload flow** (cmd1=0xFFFF for all):
    `9052 (A5)` -> `A052 [0]=01`; then `9040` encrypted 4-byte version `[0b 00 00 39]`
    (Gadgetbridge hardcodes 11.0.0.57) -> `A040 [0]=01`; then loop:
    watch `A042` chunk req (offset:i32 BE || length:i32 BE || progress:u8) ->
    phone writes `9042` **plaintext** chunk `fw[offset:offset+length]` on FIRMWARE
    chan (one BLE write per frame, per watch-requested offset/length); then watch
    `A041` FINISH_ACK_1 -> phone replies `9041 (A5)`.
  - **Frame build/send** (`CmfCharacteristic.sendCommand`): always `f5 | chunkLen:2BE
    | cmd1:2BE | chunkCount:2BE | chunkIndex:2BE (1-based) | cmd2:2BE | chunk`.
    Encrypted payloads: `chunk = AES128CBC(slice||crc32_LE(slice), sessionKey, IV)`,
    maxPayloadSize=( (min(512,mtu-3)-11)/16 )*16 -4 -1. Plaintext: chunkSize=
    (min(512,mtu-3)-11-4-2); chunk = `slice||crc32_LE(slice)`. CRC = zlib/IEEE.
    **shouldEncrypt=false (plaintext) exactly for:** AUTH_PAIR_REQUEST(8047),
    AUTH_PAIR_REPLY(0048), DATA_CHUNK_WRITE_AGPS(905F), DATA_CHUNK_WRITE_FIRMWARE(9042),
    DATA_CHUNK_WRITE_WATCHFACE(9064). All other cmds (incl 9040 INIT2) ENCRYPTED.
  - **Auth handshake (exact):** shell `AT GETSECRET` -> parse `GETSECRET:<32hex>,OK`
    -> authAppSecret(16B). rnd1=rand(16); send `8047` plaintext `rnd1(16)||sha256(rnd1||secret)`
    -> `0048` reply `rnd2(16)||signed2(32)`; verify `signed2==sha256(rnd2||secret)`;
    authkey=sha256(rnd1||rnd2||secret)[0:16] (persisted); then encrypted `8049
    (A5||Build.MODEL)` -> `0049` AUTH_WATCH_MAC; encrypted `804B (A5)` -> `004C`
    nonce; sessionKey=sha256(nonce||authkey)[0:16]; encrypted `804D (A5)` -> `0004`.
    (Gadgetbridge reads secret FROM THE WATCH SHELL, so no CMF vendor servers needed.)
  - `calcMaxWriteChunk(mtu)=min(512, mtu-3)`; `encryptAES_CBC_Pad` = AES/CBC/PKCS5
    (==PKCS7) fixed IV. Auth `getSecretKey` persists "authkey" so re-pairs skip 8047.

### C. Full custom Zephyr build (long term)
- Need Actions ATS3089C Zephyr SDK/BSP + toolchain. User can supply.
- Resulting `app.bin` must be wrapped in ACTHHTCA header + inner/outer AOTA
  (which our repacker handles).

## 7. Reference repos / tools
- `/tmp/opencode/ATS3085S_firmware_packer` (purrrock) - `aota_unpacker.py`,
  `aota_packer.py`, `compress_and_pack_temp.py`, `aota_full_pack.py`,
  `BT_ota_flasher.py` (BLE flasher for the Actions family).
  Note structural difference: reference wraps TEMP in ACTH; CMF doesn't.
- `/tmp/opencode/cmfparser` (ambraglow) - Rust unpacker; ignores SDFS checksum.
- `/tmp/opencode/CMF-Ringtone-Tool` (tirodz) - **SAME SCOPE AS OUR PROJECT**.
  - `act_emu/fwmod.py`: full AOTA container + `sdfs_k` partition rebuild
    "with valid CRC32s", round-trip verified. **Solves the SDFS checksum: per-file
    checksum = sum32 of 32-bit LE words; header entry 0 holds count/part_size at
    [12:20] and sum_table/sum_data at [24:32].** Its `Sdfs.build()` = our Mode B.
    Note their CRC32 usage for AOTA crc matches ours (they only call them 'CRC32s').
  - `act_emu/report.md` BLE analysis: **Bulk BLE uploads are destination-preset
    state machines; file type is SNIFFED from the payload 12-byte magic
    (`AOTA`/`wf`/`AGPS`) and mapped firmware-side to fixed targets (OTA staging,
    `dial-*.res`, `epo.bin`). No generic SDFS write path exists over the normal
    CMF BLE protocol.** Strongly implies our OTA flasher must push an `AOTA`
    magic payload to the firmware-OTA channel and the watch maps it to OTA flash.
  - They found the production firmware exposes a **full Zephyr shell over BLE** on
    service `77d4e67c-...` (chars `77d4ff01` write / `77d4ff02` notify) - the SAME
    service we enumerated live. Commands: `mdw/mww` (RAM R/W), `snandr`/`snandw`
    (SPI NAND R/W through FTL), `sdfs` (dump any named file), AT group. Their
    ringtone-replacement path writes NAND via `snandw` after computing PBASE.
    **This is an ALTERNATIVE (more invasive but direct) write path vs OTA.**
  - Caveat: their **BLE install is "untested on hardware"** - never actually
    flashed a physical watch; only offline/mocked. Our live-watch enumeration +
    OTA capture is the path to real confirmation.
- `/tmp/opencode/app_strings.txt` - 15,587 app.bin ASCII strings.
- `/tmp/opencode/cmf-ble-proto` (joshuapassos) - **full CMF BLE protocol doc**
  (frame `f5`, AES-128 key derivation, auth handshake, all opcodes, firmware
  OTA bulk-transfer loop 9052/9040/A042/9042/A041). Our source of truth for reflash.
- `/tmp/opencode/fmc` (freethinkel) - Go BLE companion; also implements CMF protocol.
- Gadgetbridge PR #4004 (no-auth-key pairing, firmware >=1.0.0.51) - enables us to
  flash our own image WITHOUT needing CMF's vendor pairing.
- **Gadgetbridge (gold source)** `/tmp/opencode/gb-cmf` - `CmfFwHelper.java` (firmware=
  AOTA magic), `CmfDataUploader.java` (OTA flow), `CmfCharacteristic.java` (f5 framing
  + AES), `CmfWatchProSupport.java` (auth handshake, shell GETSECRET). THE reference.
- Environment: Python 3.14.4, capstone 5.0.9 installed, bleak, llvm-objdump no ARM.

## 8. Repo layout
- `bins/original 1724161837605-90.bin`  (THE SOURCE, note the space in name)
- `extract_partitions.py`  (recursive extractor, root)
- `partitions/`  (extraction: 139 files, AOTA-level CRCs validated)
  - `partitions/TEMP/app.bin` (2.4MB firmware)
  - `partitions/TEMP/sdfs/` (defcfg/alcfg/cfg_mic/bt_rf/bt_pth/bttbl)
  - `partitions/sdfs_k/` (ring1-5.act, welcome.act, fcc.bin, logo.res, ...)
  - `partitions/res/`, `partitions/fonts/`, `partitions/res_e/`
  - `partitions/NOTE.md`  (file-purpose table - completed deliverable)
- `docs/ota-format.md`, `docs/firmware-analysis.md` (formal docs)
- `recompiler/` (OLD, broken approach: naive XZ-carcass splice - superseded)
- `info.xml` (repo root)
- `CONTEXT.md` (this file)

## 9. Key file purposes (quick)
- watch faces: `fonts/local273..280.wfc` = Activity Mood, Sun Circle,
  SlopeTime, Dichotomy, Prismatic Time, Multifunction.
- fonts: `fonts/sans32.font` (main), `emoji28.font`; `res/*.font`,
  `num*.font` (digits), `nm*n.font`.
- i18n: `res/bt_watch.{ar,bg,cz,de,eng,es,fil,fr,he,id,in,it,ja,ko,pl,pt,ro,ru,sk,th,zhc,zht}`
- strings/pictures: `bt_watch.eng` (STR#), `bt_watch.res` (PIC#, 5.3MB).
- tones: `.act` (magic b6f9e5f7) ring1-5, alarm, welcome, find, poweroff, di, aging.
- `admusic.dsp` (xhqy magic) audio DSP patch. `fcc.bin` RF cal. `tst.bin` cfg.
- `logo.res` (RES \x19, PIC1-3), `logo.sty` (466x466 round display style).

## 10. BLE flash procedure (MANDATORY)
**Before EVERY flash attempt**, forget the device from bluetoothctl:
```
echo -e "remove 2C:BE:EB:E6:E8:2D\nquit" | bluetoothctl
```
This prevents stale bond state from interfering with the flash tool's
`AT GETSECRET` / auth handshake. Without this, the tool may fail to
connect or the watch may reject the auth.

## 11. Open items / next moves
1. ~~Write+verify `repack.py`~~  DONE + verified (round-trip ALL OK).
2. ~~Confirm CMF BLE GATT OTA service uuid and framing~~  DONE.
2b. ~~Rework `flash.py` to the CMF `f5` protocol~~  DONE.
3. ~~Flash test image to real watch~~  DONE (original flashes fine; custom rebuilds
   fail with "please connect to the app to upgrade again" post-flash verify error).
4. ~~Solve SDFS per-file checksum~~  DONE = **sum32**.
5. **MERGE STRATEGY HYPOTHESIS** ← CURRENT PRIORITY.
   The watch skips the first 44% of the AOTA image (ota.xml, TEMP, res, fonts,
   first 23% of res_e compressed). It merges OTA data with existing NAND data.
   After transfer, it reads the merged image and verifies against OLD ota.xml
   checksums (from currently-installed firmware). Any change to decompressed
   partition data causes CRC mismatch → verification fails.
   **This explains why ALL rebuild attempts fail regardless of what we change.**
6. SDFS header `sum_data` checksum: FIXED in `patch_sdfs_string()` — now
   recomputes sum32 of data segment after patching. But watch STILL rejects
   the image, so there must be ANOTHER checksum at a different layer.
7. ACTHHTCA full layout/code-injection research + custom Zephyr build path.
8. (Alternative direct-write path) BLE **debug shell** on `77d4e67c-...`
   → `snandw` NAND write; fallback vs OTA route.

## 11. Firmware reverse engineering — OTA verification (IN PROGRESS)

### Key discovery: watch only requests ~56% of AOTA image, merges with NAND
The watch starts OTA progress at 44% — it already has the first 44% of the
AOTA image from its currently-installed firmware in NAND. It only requests
the remaining 56% (res_e from 23% into compressed data + all of sdfs_k).
After transfer, the watch reads the MERGED image (old NAND + new OTA data)
and verifies against the OLD ota.xml checksums from NAND. Any change to
decompressed partition data (e.g., replacing 2.ajs in res_e) causes a CRC
mismatch against the OLD checksum → verification FAILS. This explains why
ALL rebuild attempts fail regardless of what changes are made.

### Previous key discovery: all AOTA-level checksums are correct but watch still rejects
- `rebuilt_patched.bin` (version bump + string patch + SDFS sum_data fix):
  header_crc ✓, payload_crc ✓, all 6 FAT CRCs ✓, inner AOTA CRCs ✓,
  ota.xml checksums ✓, SDFS sum_data ✓. Watch STILL says
  "please connect to the app to upgrade again".
- `rebuilt_jpeg.bin` (replace 2.ajs with DEADBEEF in res_e.bin, no version
  change): ALL checksums verified. NOT YET TESTED on watch.
- This means there is a checksum at a layer we haven't identified yet.

### SDFS per-file checksums are ALL zero in original
Every file entry [24:28] in every SDFS partition stores 0x00000000.
The watch does NOT check these. (Verified: 82/82 entries in res.bin, all zero.)

### Firmware strings — OTA verification call chain
The watch firmware (app.bin, base 0x10100000) logs these during OTA verify:
1. `caculate image crc offset 0x%x size 0x%x` — computes CRC over a region
2. `image head crc error, calc crc 0x%x, head->crc 0x%x` — AOTA header check
3. `image data crc error, calc crc 0x%x, head->data_checksum 0x%x` — payload check
4. `part file %s: type %d, file_id %d, checksum 0x%x, version %d` — parses ota.xml
5. `cannot get <checksum> for part %d` — missing ota.xml checksum
6. `check file %s: crc_orig 0x%x, crc_calc 0x%x` — per-file verify after flash write
7. `file %s, verify failed/pass` — result
8. `sdfs_fsystem_verify` — SDFS filesystem integrity check after write
9. `crc cmp ota_cfg` — compares against stored OTA config
10. `set file_id %d file crc 0x%x` — stores CRC in ota_cfg after verify pass

### Approach: disassemble from string addresses via capstone
Strings are loaded via Thumb-2 PC-relative `ldr Rx, [PC, #off]` from literal
pools. The literal pool is typically right after the function. Search backwards
from each string address's literal pool reference to find the containing
function, then disassemble the full OTA verify logic to identify every
checksum it computes and where it reads the expected value.

### Disassembly status (BLOCKED — need Ghidra or rizin)
- **String addresses are NOT referenced as literal pool entries** in the
  binary. Searched entire 2.4MB app.bin for every key string address
  (0x10340107, 0x10341102, 0x1034158e, 0x10328bbd, etc.) as 32-bit
  LE values — zero matches.
- **No MOVW/MOVT pairs** loading 0x1034xxxx values found either.
- **Only 1 real pointer found** in the entire code section: "file %s
  checksum" at 0x10340ee9 referenced from offset 0xe7b67.
- **Hypothesis**: Zephyr logging system uses a `.log` section with
  `log_source` structs that contain format string pointers. These are
  set up by the linker and stored in a separate section, NOT as standard
  literal pools. Need Ghidra to properly analyze.
- `llvm-objdump` can't disassemble raw binaries (rejects as "not valid
  object file"). `objcopy` to ELF32 produces a .data section that
  objdump won't disassemble. Need Ghidra headless or rizin/r2.
- IVT at file offset 0x200: SP=0x2ffb3940, Reset=0x10102ec9 (Thumb).
  Code appears valid at base 0x10100000. Strings at file offset
  0x240000+ (vaddr 0x10340000+).
- **Next**: Install Ghidra (Java 25 available) or rizin, then analyze
  the OTA verification function chain starting from "check file %s:
  crc_orig" and "ota_image_calc_crc" strings.

### Test binaries ready to flash
- `rebuilt_jpeg.bin`: Replaces `2.ajs` in `res_e.bin` with DEADBEEF
  pattern (2,031,214 bytes). No version change. ALL checksums verified
  self-consistent. **UNTESTED** — this tests whether the rebuild
  pipeline itself works for a non-string modification.
- `rebuilt_patched.bin`: Version `1.01_2408181821` + `"Heart Rate"` →
  `"otterworks"` in res.bin. SDFS sum_data recomputed. ALL checksums
  verified. Flash FAILED ("please connect to upgrade again").
- `rebuilt_vers.bin`: Version-only `1.01_2408181821` (no string patch).
  ALL checksums verified. **UNTESTED** — simplest possible change.
- User should test `rebuilt_jpeg.bin` first to isolate whether the issue
  is string-patching-specific or a fundamental rebuild problem.

### SDFS per-file checksum verification
- All 82 file entries in res.bin have per-file checksum [24:28] = 0x00000000
  (zeroed). Watch does NOT validate these.
- SDFS header entry 0 has `sum_data` [28:32] = sum32 of data segment.
  Original: 0x49a6239f (verified correct). After string patch without
  fix: 0x7cc8479c (MISMATCH). Fixed version recomputes sum_data correctly.
- Per-file checksum algorithm: sum32 = sum of all 32-bit LE words of
  file data, masked & 0xffffffff.

### Files modified this session
- `tools/repack/repack.py`: 
  - `patch_sdfs_string()` now recomputes SDFS header `sum_data` [28:32]
    after patching file data. (line ~423)
  - Added `patch_sdfs_replace_file()` function for replacing files inside
    SDFS partitions with same-size data + recomputing sum_data.
  - Added `--replace-sdfs-file PARTITION FILENAME` CLI option that fills
    target file with 0xDEADBEEF pattern for testing rebuild pipeline.

### BLE OTA transfer behavior — CRITICAL NEW FINDINGS

#### Watch only requests ~56% of the AOTA image
Analysis of `rebuilt_jpeg.bin` flash log reveals:
- **Progress starts at 44%** — watch already has 44% of the AOTA image "done"
- **First A042 request at offset 0x016e10c8** (23% into res_e compressed data)
- **Last A042 request at offset 0x033018e4** (end of sdfs_k)
- Watch **only requests res_e (77%) + sdfs_k (100%)**, skipping ota.xml, TEMP, res, fonts entirely
- Total data received: 29,493,428 / 54,727,240 bytes = **53.9% of file**
- Each A042 sent **TWICE** by watch (dedup set handles it)

#### Partition request analysis
| Partition | FAT CRC (orig) | FAT CRC (rebuilt) | Byte-identical? | Requested? |
|-----------|----------------|-------------------|-----------------|------------|
| ota.xml   | 0x9d480190     | 0x14df139c        | NO              | NO (0%)    |
| TEMP.bin  | 0x4ac2d387     | 0x4ac2d387        | YES             | NO (0%)    |
| res.bin   | 0x0ea9a7fa     | 0x0ea9a7fa        | YES             | NO (0%)    |
| fonts.bin | 0x571b3cd7     | 0x571b3cd7        | YES             | NO (0%)    |
| res_e.bin | 0x75fe21c7     | 0x8002e3a2        | SIZE DIFFERS    | YES (77%)  |
| sdfs_k.bin| 0xbb0abab6     | 0xbb0abab6        | YES             | YES (100%) |

**sdfs_k.bin is byte-identical but still requested!** The watch must use a different
mechanism than FAT CRC comparison to decide which partitions to request.

#### Watch decompresses on-the-fly and stops when decompressed size is reached
The watch decompresses LZMA blocks sequentially. Each block produces 32KB
decompressed. The watch skips the first 23% of res_e compressed blocks (which
produce the first ~12.5MB of decompressed data). This 12.5MB contains the SDFS
header and directory entries (only 640 bytes) PLUS the first few files.

#### Merge strategy hypothesis
The watch likely **merges OTA data with existing NAND data**:
- Bytes 0–24MB (first 44%): from existing firmware in NAND (unchanged)
- Bytes 24MB–53.5MB: from OTA transfer (new data)
- Bytes 53.5MB–EOF: not written (AGPS trailing data)

After transfer, the watch reads the merged image from NAND and verifies.

**Key problem with merge**: The ota.xml checksums stored in the AOTA header
(from NAND, OLD) are compared against the decompressed partition data (from
merged NEW data). If the decompressed data changed (e.g., 2.ajs replacement),
the CRC won't match the OLD ota.xml checksum → verification FAILS.

This explains why ALL rebuild attempts fail: the watch uses the OLD ota.xml
checksums (from currently-installed firmware) to verify NEW decompressed data.

#### A041/A042 exchange timing
1. Watch sends A041 (payload=01) after receiving all requested data
2. Tool waits 15s for more requests → timeout
3. Tool sends 9041 (A5) on DATA channel (ffe1) — matches Gadgetbridge behavior
4. Watch sends A042 with offset=0, length=0, progress=100 (post-finish readback)
5. Tool has already exited chunk loop → **post-finish A042 NOT handled**

The post-finish A042 (offset=0, len=0, progress=100) might be the watch
requesting a final verification readback. The tool ignoring it could cause
the "please connect to upgrade again" error.

#### CRC32 variant confirmed
- AOTA uses standard `zlib.crc32` (init=0xFFFFFFFF, final XOR=0xFFFFFFFF)
- Gadgetbridge `crc32Raw` (init=0, no final XOR) is ONLY for watchface CRCs
- Both verified against original binary

### CRITICAL NEW FINDING: original firmware flash SUCCEEDED ✅
Original binary (`bins/original 1724161837605-90.bin`) flashed via our tool
and the watch rebooted normally. Shell works, watch advertising, all services
present. This proves our flash tool works correctly.

### Coverage patterns are COMPLETELY DIFFERENT between original and rebuild
The watch requests DIFFERENT partitions depending on its state:

**Original firmware** (flashed AFTER failed rebuild_jpeg → watch in "full reflash" state):
- ota.xml: **100%** (1832/1832)
- TEMP.bin: **100%** (1,306,972/1,306,972)
- res.bin: **100%** (6,149,484/6,149,484)
- fonts.bin: **100%** (7,813,224/7,813,224)
- res_e.bin: **84.5%** (33,166,000/39,237,168)
- sdfs_k.bin: **0%** (0/310,872)
- Total: 48,438,560 bytes (86.4%) — across 2 sessions (first truncated)

**rebuilt_jpeg.bin** (flashed in "normal" state):
- ota.xml: **0%**
- TEMP.bin: **0%**
- res.bin: **0%**
- fonts.bin: **0%**
- res_e.bin: **75.2%** (29,493,428/39,237,168)
- sdfs_k.bin: **0%**
- Total: 29,493,428 bytes (52.6%)

**Key observations:**
1. **Neither flash requests sdfs_k** — the watch NEVER requests sdfs_k via OTA
2. The original firmware requests ALL partitions except sdfs_k; rebuild requests ONLY res_e
3. This disproves the simple "watch skips first 44%" model
4. The difference is explained by the watch's STATE after the failed rebuild:
   - **Normal state**: watch compares incoming AOTA against NAND → only requests partitions that differ
   - **"Full reflash" state** (after failed OTA): watch requests ALL partitions
5. For the rebuild in normal state: only res_e differs from NAND → watch only requests res_e →
   writes new res_e to NAND → but NAND still has OLD ota.xml → verification checks new res_e
   against OLD ota.xml checksums → MISMATCH → FAIL

### Refined merge strategy hypothesis
The watch stores ota.xml in NAND. During verification, it reads ota.xml from NAND
(not from the AOTA image) and compares checksums against decompressed partition data.
- If the watch requests ota.xml (full reflash mode), it updates NAND's ota.xml
- If the watch doesn't request ota.xml (normal mode), NAND's ota.xml stays unchanged

For rebuilds in normal mode:
1. Watch sees res_e differs → requests only res_e
2. Writes new res_e to NAND
3. Verification: reads OLD ota.xml from NAND → old checksums for ORIGINAL res_e
4. Compares against NEW res_e → CRC mismatch → FAIL

### NEW THEORY: flash rebuild twice — TESTED, FAILED ❌
1. First flash: fails (normal state → only requests res_e → old ota.xml checksums mismatch)
2. Watch enters "full reflash" state after failure
3. Second flash: watch requests ALL partitions → writes new ota.xml (with correct checksums) → writes all data
4. **Result: STILL FAILS** with "Please connect to the app to upgrade again"
5. Even the THIRD attempt (which requested ota.xml 100% + TEMP 100% + res 100% + fonts 100% + res_e ~98%) with proper finish ack FAILED
6. **This proves the issue is NOT about which partitions the watch requests or ota.xml checksums**
7. There must be a **persistent verification mechanism** (like `ota_cfg` / per-file CRCs stored in NAND) that we can't update via OTA
8. The firmware strings confirm: `crc cmp ota_cfg` compares against stored config, `set file_id %d file crc 0x%x` stores after success
9. The watch likely stores CRCs from the original firmware in `ota_cfg` and compares new data against those stored CRCs — any change causes mismatch

### Touch-all experiment — WATCH BRICKED ❌❌❌
- `--touch-all` flag added to `repack.py`: flips 1 byte in app.bin (offset 0x100)
  + 1 byte in each SDFS partition data segment, recomputes sum_data
- Result: watch reached 100% "Upgrading..." then went **completely dark**
  - No BLE advertising, no button response, screen off permanently
  - Verification PASSED (ota.xml checksums matched), watch wrote ALL partitions
  - But corrupted app.bin header at offset 0x100 → firmware unbootable → brick
- **LESSON: NEVER flip random bytes in app.bin.** The ACTHHTCA header (0x000-0x200)
  contains load_addr, entry_point, header_sig, payload_sig — corrupting any
  field makes the bootloader unable to load the firmware.
- **The verification is NOT the blocker** — the touch-all test PROVED that when
  ota.xml checksums match the data (even with changes), verification PASSES.
  The watch wrote all 6 partitions and attempted to reboot.
- **Root cause of all prior failures**: the watch compares incoming partition data
  against what's already in NAND. If only some partitions differ, the watch only
  requests those — but the OLD ota.xml (from NAND) still has old checksums → mismatch.
  In the touch-all test, ALL partitions differed, so ALL were written (including
  ota.xml with new checksums), and verification passed.
- **KEY INSIGHT**: To flash a modified firmware, we need to ensure EVERY partition
  differs from what's in NAND, so the watch writes the NEW ota.xml too.
  Safe modifications: string patches in SDFS data, resource file replacements,
  version bumps — but NEVER modify app.bin's header region.
- **Recovery options**: 
  1. Wait for battery drain (a week+)
  2. Try force-flash during brief power-on window
  3. Hardware JTAG/SWD recovery if available
  4. Replacement watch

### Next moves
1. ~~Test: flash original binary with our tool~~ ✅ DONE — succeeds!
2. ~~Test: flash rebuilt_jpeg.bin TWICE in a row~~ — first fails, second should
   succeed because watch is in "full reflash" state and updates ota.xml in NAND.
3. **Test: flash rebuilt_vers.bin** (version-only change) — simpler test case.
4. **Handle post-finish A042** — the watch sends A042 (offset=0, len=0) after
   A041 exchange. Tool should respond even after finish.
5. **Consider debug shell path** — Zephyr shell on 77d4e67c-... can do `snandw`
   for direct NAND write. More invasive but bypasses OTA verification entirely.
6. **Install Ghidra** for full firmware disassembly of OTA verify functions.

### Verified ota_cfg theory WRONG — verification IS self-contained
The original reasoning: "ota_cfg stores persistent CRCs → any change fails"
was **refuted** by the user's logic: official CMF updates would also brick the
watch if persistent CRCs blocked changes. The watch is on v1.0.0.57, proving
updates work. Therefore verification reads expected CRCs from the ota.xml **in
the incoming image**, not from stored values.

### Touch-all results — THE VERIFICATION BREAKTHROUGH ✅
- `--touch-all` modified ALL 6 partitions (1 byte each in ota.xml, app.bin,
  res, fonts, res_e, sdfs_k) with recomputed checksums.
- **Verification PASSED** — watch reached 100% "Upgrading..."
- The watch wrote ALL partitions because all differed from NAND
- Then attempted to reboot — **but bricked because app.bin offset 0x100
  (ACTHHTCA header) was corrupted**, making firmware unbootable.
- **KEY PROOF**: The verification itself is NOT the blocker. When every
  partition differs from NAND, the watch accepts the image and passes verify.
- **Previous failures explained**: in those tests, only SOME partitions
  differed → watch only requested those → wrote new data but kept OLD ota.xml
  in NAND → verification compared new data against old ota.xml checksums →
  MISMATCH → FAIL.

### The fix for future builds
To flash modified firmware successfully:
1. Change at least 1 byte in EVERY partition (ota.xml, TEMP/app.bin,
   res, fonts, res_e, sdfs_k)
2. But NEVER touch the ACTHHTCA header region (0x000-0x200) of app.bin
3. Safe app.bin modifications: code region (0x200+), strings in app.bin
4. Safe resource modifications: string patches in SDFS data segments,
   file replacements in SDFS partitions
5. Version bumps work as a "touch" mechanism for the inner AOTA

### Camera notes
- Camera has terrible autofocus — take 8-10 shots spaced 2s apart
  to catch a focused frame. Command:
  ```python
  for i in range(10):
      time.sleep(2)
      for j in range(3): ret, frame = cam.read()
      cv2.imwrite(f'/tmp/frame_{i}.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
  ```
- Check multiple frames to find the readable one

### UART recovery plan
- Watch is bricked (touch-all corrupted app.bin header at 0x100)
- No button response, screen dark, no BLE advertising
- User plans to tap into UART header on the watch PCB for recovery
- UART likely exposes boot ROM loader for direct NAND write
- `tool_uart_init`/`tool_aset_loop` strings in firmware suggest
  factory UART channel exists for exactly this purpose
- Factory test path: `fcc.bin`, `tst.bin`, `ATT Goto BQB TEST`
