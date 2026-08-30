# CMF Watch Pro 2 - Firmware Analysis (`app.bin`)

Static analysis of the decompressed `app.bin` (the executable firmware image
extracted from the inner AOTA container inside `TEMP.bin`).

## Fast facts

| | |
|---|---|
| File | `partitions/TEMP/app.bin` (0x255080 bytes ≈ 2.4 MB) |
| SoC | Actions Technology **ATS3089C** |
| CPU | ARM **Cortex-M4F** (Thumb-2 + VFPv4 FPU) @ 202 MHz |
| RTOS | **Zephyr** (`WEST_TOPDIR/zephyr/...` source paths in strings) |
| GUI | **LVGL** with Actions GPU port (VGLite / DMA2D / JPEG hw decoder) |
| Framework | JX ("jx402_01" project) `bt_watch` application |
| Companion app | `com.nothing.watchmanager` |
| Load base | `0x10100000` (reset vector `0x10102ec9` → file offset `0x2ec8`) |

## Container

`app.bin` is a raw `ACTHHTCA` Actions boot image:

- `0x000` Actions boot header (40 bytes), `load_addr/exec_addr = 0x10102ec8`,
  `block_size = 0x62`, `ivt_offset = 0x200`.
- `0x200` ARM Cortex-M vector table. Initial MSP = `0x2ffb3940`, Reset vector
  = `0x10102ec9` (Thumb).
- The remainder is the linked firmware image (code + rodata + init data),
  which is **not** compressed in this build - unlike the ATS3085S G1 watch
  where the equivalent stage is compressed, here the image loads directly.

## Loading it in Ghidra / IDA

Use **ARM Cortex-M (little-endian, Thumb)** with base address **`0x10100000`**.
The reset vector at `0x10102ec8` disassembles as valid Thumb-2/VFP code, so a
byte-for-byte rebase plus `import file as raw` and `Analyze → Auto Analysis`
yields good results. Vector table region is at `0x10100200`.

Note the image ships **without symbols**, but the embedded absolute source
paths (`WEST_TOPDIR/application/bt_watch/...`, `.../framework/...`,
`.../thirdparty/lib/gui/lvgl/...`) make module identification straightforward.

## Application layout (from embedded source paths)

```
application/bt_watch/src/
  main/system_app_shell.c         system shell / app launcher
  jx_project/jx402_01/            board-specific project
    launcher/launcher_app.c
    view_layout/alipay/…          Alipay + WeChat Pay views
    view_layout/call/btcall_…     BT call UI
    view_layout/m_effect/…        2D effects (wheel view)
    view_layout/three_dimensional/ cubebox/face_wheel watch faces
    view_layout/vitality/…        activity ring
  jx_src/ui/manager/…             JX msgbox / view creator
  jx_src/ui/watch_face/WFaceRes.c watch face resources
  jx_src/ui/wfc_manager/WFManager.c
  jx_src/ui/widgets/…             pic_anim, scroll_bar, snapshot, video
framework/
  bluetooth/bt_stack/…            BT stack (l2cap,gatt,smp,att,hci_core)
  bluetooth/bt_manager/…          bt_manager_sco
  display/libdisplay/lvgl/…       LVGL virtual display, input dispatcher
  ota/…                           OTA backend
  system/act_log/easyflash/…      easyflash logging
thirdparty/lib/gui/lvgl/porting/… LVGL port + Actions GPU (vglite/dma2d/jpg)
```

## Key functionality found in strings

- **Health algorithms** - the `R/A%d:` log prefix is the exercise/health
  module: swimming (`R/A%d: lap info: strokes=…, swolf=…`, `SWIM_CSS_OVERFLOW`),
  sleep staging (`R/A%d: [HSRF]…`, sleep quality), SpO2, HR STD, smart alarm,
  blood-pressure UI, sedentary alarms, VO2/activity-calorie metadata.
- **BLE services** - AMS (Apple Media Service, `BLE_AMS_*`), ANCS
  (Apple Notification service, `BLE_ANCS_EVENT_*`), HFP (btcall), notifications.
- **GPS / AGPS** - `MSG_GPS_DOWNLOAD_EVENT` with EPO / HDL download handling.
- **Payments** - Alipay + WeChat Pay views (`alipay_*`, `wxpay_*`).
- **OTA** - `ota_view`, `ota force reboot`, upgrade progress in many languages.
- **USB/UART "PC tool"** - `tool_init`, `tool_uart_init`, `tool_aset_loop`,
  `begin trying to connect pc tool`, `parse tool type:%s`, `UART_0`. A
  factory/UART command channel is present.
- **Factory test** - `check_production_test`, `ATT Goto BQB TEST`, `fcc.bin`
  in sdfs_k, `show entity info`, `dump fw version`.
- **Accessory config** - sdfs_k contains `bt_rf.bin`, `bt_pth.bin`,
  `cfg_mic.bin`, `bttbl.bin` (BT RF/path/table calibration), `logo.res`.

## Security posture

- **No** RSA/ECC signature on the container - integrity relies on **CRC32**
  (zlib) at each level (AOTA header/FAT/payload, SDFS entries).
- Firmware is **unencrypted** and shipped **with symbols path strings**; all
  app code is recoverable statically.
- This mirrors the findings of the ATS3085S G1 / ATS3089C community work
  (`purrrock/ATS3085S_firmware_packer`, `ambraglow/cmfparser`, Quarkslab blog).

## Reversing next steps

1. Rebase `app.bin` at `0x10100000` in Ghidra (ARM Cortex-M little-endian).
2. Locate `system_app_launch_init` / `system_app_shell` to map app startup.
3. Build FIDB signatures from the equivalent ATS3085S/Zephyr SDK to auto-name
   functions (as done in the Quarkslab teardown).
4. Hook `tool_*` / UART shell functions to discover the factory/debug protocol.
