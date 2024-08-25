"""
Small script to extract .xz archives from a .bin file.

Originally made for the CMF Watch Pro 2's bin file.
Author: github.com/whatotter
8/25/24
"""

import argparse, os

try: # https://stackoverflow.com/a/42079784
    import lzma
except ImportError:
    from backports import lzma

parser = argparse.ArgumentParser()
parser.add_argument("bin", help="bin to attempt to extract from")
args = parser.parse_args()

# Both of these can be confirmed at http://fileformats.archiveteam.org/wiki/XZ
xzMagicNums = [b'\xfd', b'\x37', b'\x7a', b'\x58', b'\x5a'] 
xzEndings = [b'\x00', b'\x00', b'\x00', b'\x00', b'\x04', b'\x59', b'\x5a']

binData = b''
begin = False
counter = 1
addr = 0

if not os.path.exists("./xz dumps"):
    os.mkdir("xz dumps")

def write(byte):
    global counter
    with open("./xz dumps/dump {}.bin.xz".format(counter), "wb") as f:
        f.write(byte)
        f.flush()

    counter += 1

# Read .bin file.
with open(args.bin, "rb") as f:
    binData = f.read()

# Extract all .XZ archives from the bin file.
while True:
    start = binData.find(b''.join(xzMagicNums))
    end = binData.find(b''.join(xzEndings))+len(xzEndings)

    print("[{} / DUMP {}] writing from {} to {} | {} bytes left | last bytes: {}".format(
        hex(addr), counter, hex(addr+start), hex(addr+end), len(binData), binData[start:end][-16:]
        ), flush=True)

    if len(binData) == 0 or len(binData[start:end][-16:]) == 0:
        print("done: {}".format(len(binData)))
        break
    
    write(binData[start:end])

    part = binData.partition(b''.join(xzEndings))
    addr += len(part[0])
    binData = part[2]


# (painfully) Extract all .XZ archives, merge them all into one file.
xzs = os.listdir("./xz dumps")
mergeBin = open("merged.bin", "wb")

for x in range(1, counter):
    xz = "dump {}.bin.xz".format(x)
    with lzma.open("./xz dumps/{}".format(xz)) as f:
        
        print("\r[+] merging {} {}".format(xz, " "*25), end="", flush=True)

        try:
            mergeBin.write(f.read())
        except Exception as e: # for some reason some lzma archives are corrupted?
            print("\n{}: {}".format(xz, e))
            pass
        
        print("\r[+] merged {} {}".format(xz, " "*25), end="", flush=True)

print("\n[!] extracted all .xz files from bin, merged them to 'merged.bin'")