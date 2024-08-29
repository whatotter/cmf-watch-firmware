# DON'T FLASH ANY RECOMPILED FIRMWARES UNLESS YOU WANT A POSSIBLY BROKEN WATCH

## what is this
the flash image 'recompiler', still in beta
technically recompiles, just need to test it (don't want to brick my watch, need to buy one)

## devnotes
1. carcass is the original bin file, just 0x00000C00 - 0x03448457 removed
2. any recompiled binfiles, even with the same data as the original bin file, will never match due to 'LZMA seperators' (need to figure this out, not sure if it's important though)