# CMF Watch Pro 2 Firmware Dump
a half-assed FW dump of the CMF watch pro 2

here you can find: 
- the original firmware.bin (firmware directly flashed to the watch)
- the dumped firmware.bin (extracted using `./extract.py`)
- the folder named `extracted`, which contains all the files extracted from the dumped firmware

i'd like to thank u/IndependenceSmall902 for finding the firmware.bin for the watch in the first place (https://www.reddit.com/r/CMFTech/comments/1eylsuo/finally_got_the_ota_url_of_wtch_pro_2/)

## ascii flowchart
```
    extract.py    │  recompile.py 
         │        │        │      
         ▼        │  opens │ .xzs 
extract .xz files ◄────────┤      
from original bin │        ▼      
         │        │ recompile into
         ▼        │ one single bin
 decompile using  │        ▼      
 binwalk+carver   │     flash(?)    
```

# autopsy
- .bin is filled with LZMA archives, each split by .xz's magic number (`0xfd377a585a00`)
- each LZMA archive usually ends in `00 00 00 00 04 59 5A` (ascii `.....YZ`), commonly followed by `4C 5A 4D 41` (ascii for 'LZMA')
- `info.xml` is an XML file to identify versions, checksums, board names, and some other stuff
- `info.xml` began at hex address `0x00000400` in the original firmware file
- from `0x0` to `0x00000083` there's ASCII text, probably indcating firmware version and target board version
- from `0x00000200` to `0x000002BF` there's some weird ASCII text, don't know what that's for

## strings autopsy
- has uart (uart0, uart1, uart2)
- ~~uses FAT32 as it's filesystem~~ ~~still somewhat unknown, likely SDFS~~ uses FatFS, so yes it's fat32
- ~~runs off of FreeRTOS~~ uses **Zephyr** (https://github.com/zephyrproject-rtos/zephyr) <sub>maybe you can recompile new firmware using this?</sub>
- ~~uses cortex M4 core~~ unknown at the moment
- ~~CPU is likely 'Airoha AG3352' (no datasheet?)~~ MCU is actions technology ATS3089C (no datasheet)
- seems to have a UART command line, so UART pads are likely present
- uses LVGL

# recompiling
being worked on, need to order/get a donor watch 