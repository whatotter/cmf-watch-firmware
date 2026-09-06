# Partitions — File Reference

What each extracted file is and what it does. All files live under `./partitions`.
Sizes are the extracted (decompressed) sizes.

## Top level

| File | Size | What it is |
|------|------|-----------|
| `ota.xml` | 1.8 KB | Outer AOTA metadata: firmware version `1.00_2408181820`, board `jx402_01_3089c`, and the 5 partition entries (TEMP/res/fonts/res_e/sdfs_k) with checksums. |
| `TEMP/` | — | The inner AOTA container (boot + system image) — see below. |
| `res/` | — | Main resource SDFS image: text fonts, UI numbers, per-language strings, boot images, SVG. |
| `fonts/` | — | Font + built-in watch face SDFS image. |
| `res_e/` | — | "Extended" resource SDFS image: large bundled JPEG pictures. |
| `sdfs_k/` | — | System data SDFS image: alert tones, boot logo, FCC/RF data, DSP tables. |

---

## `TEMP/` — inner AOTA (system container)

| File | Size | What it is |
|------|------|-----------|
| `ota.xml` | 0.9 KB | Inner AOTA metadata; declares 2 partitions: `app.bin` (SYSTEM, the firmware) and `sdfs.bin` (DATA). |
| `app.bin` | 2.4 MB | **The firmware executable** — raw `ACTHHTCA` Actions boot image. ARM Cortex-M4F code, Zephyr RTOS + LVGL, `bt_watch` app. See `../docs/firmware-analysis.md`. |
| `sdfs/` | — | Inner system SDFS image with device configuration / BT calibration blobs. |

### `TEMP/sdfs/` — device config blobs

All config blobs start with a `CFG\0VER\x00\x00 ...` header (a key/value config container) except `cfg_mic.bin` (`MIC\x00...`).

| File | Size | What it is |
|------|------|-----------|
| `defcfg.bin` | 205 B | **Default config.** Contains board/product ID strings `ACTIONS_LEOPARD` and `S6_01010101`. |
| `alcfg.bin` | 1.8 KB | Alarm / general data config (CFG+VER blob). |
| `extcfg.bin` | 16 B | Extended config (empty shell, header only). |
| `usrcfg.bin` | 16 B | User config (empty shell, header only). |
| `cfg_mic.bin` | 528 B | **Microphone config** (`MIC\x00`): mic gain / audio capture params. |
| `bt_rf.bin` | 2.8 KB | **Bluetooth RF calibration** data (per-unit radio trim). |
| `bt_pth.bin` | 14 KB | **Bluetooth path/timing calibration** data. |
| `bttbl.bin` | 3.2 KB | Bluetooth calibration **table** (frequency/channel offsets). |
| `sdfs.txt` | 10 B | SDFS marker (contents `1234567890`) — filesystem version stamp. |

---

## `res/` — main resources

### Text fonts (`.font`)

Custom Actions font container (starts `0x30 0 0 0 "head" "cmap"`). Naming =
`{prefix}{size}{weight}.font` where size is in px and weight is
`m`=medium, `r`=regular, `l`=light, `n`=normal, `el`=extra-light, `b`=bold.

| Group | Example | What it is |
|-------|---------|-----------|
| `font*.font` | `font32m.font`, `font24m.font`, `font36r.font` … | General UI text fonts across sizes/weights (larger ones, e.g. `font32m`, are the main screen fonts). |
| `fnt56el.font` | `fnt56el.font` | 56 px extra-light text font. |
| `num*.font` | `num32m.font`, `num88e.font`, `num74b.font` … | **Numeric-only fonts** (digits) for sports / health readouts (HR, step count, time). |
| `nm*.font` | `nm104n.font`, `nm120nb.font`, `nm36n.font` | Numeric variants for large metric displays. |

### Per-language & resource databases (`bt_watch.*`)

| File | Size | What it is |
|------|------|-----------|
| `bt_watch.eng` | 30 KB | English **string table** (`RES\x19` container with `STR#` entries). |
| `bt_watch.res` | 5.3 MB | Main **picture resource database** (`RES\x19` with `PIC#` entries; shared images). |
| `bt_watch.sty` | 185 KB | UI **style** resource (borders, colors, shapes). |
| `bt_watch.{lang}` | ~30–60 KB | Localized **string tables** for each language: `ar ar bg cz de es fil fr he id in it ja ko pl pt ro ru sk th`, `zhc` (Chinese-simplified), `zht` (Chinese-traditional). |

### Misc

| File | Size | What it is |
|------|------|-----------|
| `tiger.svg` | 99 KB | A bundled **SVG vector** image (Logo/theme artwork). |

---

## `fonts/` — fonts & built-in watch faces

| File | Size | What it is |
|------|------|-----------|
| `sans32.font` | 5.1 MB | **Main system font** (large; the default text font). |
| `emoji28.font` | 138 KB | **Emoji font** (28 px). |
| `test.font` | 70 KB | Test font (labels a `local273` watch face "Activity Mood"). |
| `local273.wfc` | 70 KB | Built-in watch face **"Activity Mood"** |
| `local274.wfc` | 396 KB | Built-in watch face **"Sun Circle"** |
| `local275.wfc` | 209 KB | Built-in watch face **"SlopeTime"** |
| `local276.wfc` | 118 KB | Built-in watch face **"Dichotomy"** |
| `local277.wfc` | 2.9 MB | Built-in watch face **"Prismatic Time"** |
| `local280.wfc` | 142 KB | Built-in watch face **"Multifunction"** |

(`.wfc` = watch face container.)

---

## `res_e/` — extended resources (pictures)

| File | Size | What it is |
|------|------|-----------|
| `1.ajs` … `19.ajs` | 1.8–6.1 MB each | Bundled **JPEG picture** resources (each file contains JPEG/JFIF image data; numbered). Likely high-res app/theme/wallpaper artwork loaded on demand. |

---

## `sdfs_k/` — system data

### Alert / UI tones (`.act`)

`ACT` is an Actions audio container (magic `b6 f9 e5 f7`) holding encoded
tone/ring audio. Used for UI feedback and alerts (not full ringtones).

| File | Size | What it is |
|------|------|-----------|
| `welcome.act` | 3.1 KB | Boot **welcome** chime. |
| `alarm.act` | 22 KB | **Alarm** alert tone. |
| `ring1.act` … `ring5.act` | 1.1–15 KB | **Ring/notification tones** (5 variants, selectable). |
| `find.act` | 6.4 KB | **"Find my watch"** locating sound. |
| `aging.act` | 7.3 KB | Aging/burn-in test tone? (alongside FCC/test assets). |
| `poweroff.act` | 3.1 KB | **Power-off** sound. |
| `di.act` | 654 B | Small diagnostic/test chirp. |

### Test / RF / audio

| File | Size | What it is |
|------|------|-----------|
| `fcc.bin` | 37 KB | **FCC / RF factory test** data block (starts `0x80 0 0x10 0`); used in production/testing. |
| `tst.bin` | 4.1 KB | Test config block (starts `cfg\0...`); used by factory/test app. |
| `admusic.dsp` | 382 KB | **Audio DSP patch** (magic `xhqy`) — echo/noise-cancellation and audio pipeline tables. |
| `sdfs.txt` | 10 B | SDFS marker (`1234567890`) — filesystem version stamp. |

### Boot/logo

| File | Size | What it is |
|------|------|-----------|
| `logo.res` | 14.8 KB | **Boot logo image** resources (`RES\x19` container with `PIC1`/`PIC2`/`PIC3`). |
| `logo.sty` | 204 B | Boot logo **style** (e.g. `0x1d2 x 0x1d2` = 466×466 round-display canvas size). |

---

## Quick summary by purpose

- **Code / OS** → `TEMP/app.bin`
- **Config & BT calibration** → `TEMP/sdfs/*.bin`, `sdfs_k/fcc.bin`, `sdfs_k/tst.bin`
- **Fonts** → `fonts/sans32.font`, `fonts/emoji28.font`, `res/*.font`
- **Watch faces** → `fonts/local*.wfc` (named in-file)
- **Strings / i18n** → `res/bt_watch.{lang}`
- **Pictures / UI art** → `res/bt_watch.res`, `res_e/*.ajs` (JPEG), `res/tiger.svg`, `sdfs_k/logo.res`
- **Sounds** → `sdfs_k/*.act` (tones/rings) and `sdfs_k/admusic.dsp` (DSP)
