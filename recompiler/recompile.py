# not actually recompiling, just trying to get all xz files back together
"""
    extract.py    │  recompile.py 
         │        │        │      
         ▼        │  opens │ them 
extract .xz files ◄────────┤      
from original bin │        ▼      
         │        │ recompile into
         ▼        │ one single bin
 decompile using  │        ▼      
 binwalk+carver   │      flash    
"""

import json
import os, argparse, hashlib

parser = argparse.ArgumentParser()
parser.add_argument("--cmp", help="file to compare with after recompilation (using MD5 hashes)")
args = parser.parse_args()

def calculate_md5(filename):
    hash_md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

dumps = len(os.listdir("../xz dumps"))

# RECOMPILER MUST INPUT DATA AT 0x00000C00!!!

start = 0x00000C00
#seperator = b"\x4C\x5A\x4D\x41\x10\x00\x00\x00\xF0\x15\x02\x00\x00\xBA\x05\x00" # 'LZMA........'
#seperator = b"\x4C\x5A\x4D\x41\x10\x00\x00\x00\x4C\xDB\x11\x00\x00\x00\x20\x00"
seperator = b''

with open("carcass.bin", "rb") as f:
    carcass = f.read()

with open("recompile.json", "r") as f:
    lzmas = json.loads(f.read())

carcassStart = carcass[:start]
carcassEnd = carcass[start:]
xzData = b''
carcassStart += seperator

for x in range(1, dumps+1):
    print("\r[+] on XZ {}".format(x), end="", flush=True)

    if x != dumps:
        xzData += lzmas[str(x)].encode("latin-1")
    else:
        print("didnt add seperator to {}".format(x))

    with open("../xz dumps/{}.bin.xz".format(x), "rb") as f:
        xzData += f.read()


with open("recompiled.bin", "wb") as f:
    f.write(carcassStart+xzData+carcassEnd)
    f.flush()

if args.cmp != None:
    rcMD5 = calculate_md5("recompiled.bin")
    origMD5 = calculate_md5(args.cmp)

    print("[+] recompiled MD5: {}".format(rcMD5))
    print("[+] {} MD5: {}".format(args.cmp, origMD5))
    print("[+] match: {}".format(rcMD5 == origMD5))