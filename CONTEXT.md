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

## 10. Open items / next moves
1. ~~Write+verify `repack.py`~~  DONE + verified (round-trip ALL OK).
2. ~~Confirm CMF BLE GATT OTA service uuid and framing~~  DONE: encrypted `f5`
   protocol on `fff0` cmd channel + `02f0...ffe1/ffe2` data channel + SEPARATE
   `02f0...fe00` firmware channel; fully documented & verified against Gadgetbridge
   gold source (see B2).
2b. **Rework `flash.py` to the CMF `f5` protocol** - DONE (see section 6.B / git).
   Auth (shell GETSECRET + 8047/0048/8049/004B/804D) + OTA loop
   (9052/9040 on cmd/fw chan, 9042 plaintext chunks on fw chan, 9041 on data chan),
   image = rebuilt `AOTA` container. Crypto+framing unit-verified offline;
   **NOT yet flashed to hardware** (needs a real watch + `--dry-run`/`--services` first).
3. Flash a test image to a real watch; confirm the CMF OTA index handshake holds.
4. ~~Solve SDFS per-file checksum~~  DONE = **sum32** (LE 32-bit word sum, & 0xffffffff);
   reference `CMF-Ringtone-Tool/act_emu/fwmod.py`. Mode B (edit files inside
   resource partitions) now doable.
5. ACTHHTCA full layout/code-injection research + custom Zephyr build path
   (needs Actions ATS3089C Zephyr SDK/BSP + toolchain from user).
6. Encode an executive: decide whether to keep `rebuilt.bin` artifacts staged.
7. (Alternative direct-write path, unvalidated) BLE **debug shell** on
   `77d4e67c-...` → `snandw` NAND write; riskier (needs PBASE/FTL), see
   `CMF-Ringtone-Tool/act_emu/REPORT.md`. Keep as fallback vs OTA route.
