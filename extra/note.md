#### image assets are saved in `./img assets.7z`

# carver2.py
## explanation
in the `extracted.bin` file, there is blocks of data which start with `52 45 53 19 (ascii: 'RES.')`, followed by filenames (one can assume) in a special schema, then followed by data split by `0x00`

carver2.py leverages that and extracts images, strings, and etc.

## data block schema

### filename header
|hex column |00-01|02-03                    |04-05       |07-0F   |
|-----------|-----|-------------------------|------------|--------|
|description|???  |unknown, probably a split|file length (if column not in use, filled with `0x00`) (**IS FLIPPED/INVERTED**, E.G. `0x21 0x01` is actually `0x121`) |filename|

### file data
starts immediately after the filename header, no magic strings

file data is split by `0x00`, but i'd rather read from length from filename header since i don't trust `0x00`s