# CMF Watch Pro 2 Firmware Dump
a firmware dump and other tools for the CMF Watch Pro 2

i'd like to thank `u/IndependenceSmall902` for finding the firmware.bin for the watch in the first place (https://www.reddit.com/r/CMFTech/comments/1eylsuo/finally_got_the_ota_url_of_wtch_pro_2/)

## what's been done
- partition unpacker
- repacker
- flashing .bin to watch via OTA
- identification

## what's missing
- flashing modified+repacked OTA bin successfully to the watch
    - i believe there's a checksum i can't find that's tripping the watch
- BSP/toolchain for ATS3089C chipset

## what's needed
- someone with determination to figure out how to flash a modified bin to the watch
- someone that can convince Actions Technology to send over their toolchain for this chipset

## what we know
- uses Zephyr + LVGL
- chinese firmware
- SDFS filesystem
- LZMA partitions
- UART debug supported

## todo
- fill this readme out more