# CMF Watch Pro 2 Firmware Dump
a half-assed FW dump of the CMF watch pro 2

here you can find: 
- the original firmware.bin (firmware directly flashed to the watch)
- the dumped firmware.bin (extracted using `./extract.py`)
- ~~the folder named `extracted`, which contains all the files extracted from the dumped firmware~~ it was 700mb

i'd like to thank u/IndependenceSmall902 for finding the firmware.bin for the watch in the first place (https://www.reddit.com/r/CMFTech/comments/1eylsuo/finally_got_the_ota_url_of_wtch_pro_2/)

## todo list:
- pull all assets (videos, images, gifs)
- pull fonts
- find/make a good file carver

# autopsy
- .bin is filled with LZMA archives, each split by .xz's magic number (`0xfd377a585a00`)
- each LZMA archive usually ends in `00 00 00 00 04 59 5A` (ascii `.....YZ`), commonly followed by `4C 5A 4D 41` (ascii for 'LZMA')
- `info.xml` is an XML file to identify versions, checksums, board names, and some other stuff
- `info.xml` began at hex address `0x00000400` in the original firmware file
- from `0x0` to `0x00000083` there's ASCII text, probably indcating firmware version and target board version
- from `0x00000200` to `0x000002BF` there's some weird ASCII text, don't know what that's for
- a ton of images (100% .mp4s in there, binwalk extracted each frame though and it ballooned to 60gbs)
- i hate this thing
- binwalk LOVES ballooning the fuck out of the .bin file, extract was 700mb, mostly of repeated letters
    - ~~if someone knows why please let me know~~ need to use a file carver, duh

## strings autopsy
- has uart (uart0, uart1, uart2)
- uses FAT32 as it's filesystem
- ~~runs off of FreeRTOS~~ uses **Zephyr** (https://github.com/zephyrproject-rtos/zephyr) <sub>maybe you can recompile using this?</sub>
- uses cortex M4 core
- CPU is likely 'Airoha AG3352' (no datasheet?)
- seems to have a UART command line, so UART pads are likely present
- uses LVGL

# recompiling
FFFFFFFFFFFFFFFUUUUUUUUUUUUUUUUUUCCCCCCCCCCCCCKKKKKKKKKKKKKKKK NO  
<sub>probably possible but not my problem!</sub>
