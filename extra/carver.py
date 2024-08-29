"""
a basic file carver, different from 'carver2.py' as this one looks for magics - carver2 does not
this carver is more robust than carver2
"""

import os
import random
import json
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("bin")
parser.add_argument("--exfolder")
parser.add_argument("--negative",
                    action="store_true")
args = parser.parse_args()

if not os.path.exists(args.exfolder):
    os.mkdir(args.exfolder)

magics = json.loads(
        open("magics.json", "r").read()
        )

# 0x01198D2D

def randStr(amnt):
    return ''.join([random.choice("abcdef") for x in range(amnt)])

def mgcToByte(magic):
    if " " in magic:
        return b''.join([chr(int(x, 16)).encode('latin-1') for x in magic.split(" ")]) #yowza
     
    return chr(int(magic, 16)).encode('latin-1')

with open(args.bin, "rb") as f:
    data = f.read()

for ffmt, value in magics.items():
    magicfirst = mgcToByte(value["magicStart"])
    magicend = mgcToByte(value["magicEnd"])
    magicListChecks = value["magics"]
    minBytes = value["minBytes"]

    dataCopy = data

    if not os.path.exists(ffmt[1:]):
        os.mkdir(args.exfolder+"/"+ffmt[1:])

    zeros = 0
    while True:
        b4,sub,aftr = dataCopy.partition(magicfirst)
        subaftr = sub+aftr

        fdata,sub,eof = subaftr.partition(magicend)
        extracted = fdata+sub

        dataCopy = b4 + eof

        print("[+] [{}] extracted {} bytes | {} bytes left".format(ffmt, len(extracted), len(dataCopy)))

        if zeros >= len(data)/12:
            break

        if minBytes > len(extracted):
            print("| not enough bytes ({} > {})".format(minBytes, len(extracted)))
            zeros += 1
            continue

        if len(extracted) != 0:
            zeros = 0
            fileIsGood = True
            for check in magicListChecks:
                if len(extracted.partition(mgcToByte(check))[2]) == 0:
                    fileIsGood = False
                    break
                else:
                    print("| found string of bytes \"{}\"".format(mgcToByte(check)))

            if fileIsGood and args.negative == False:                
                print("\\ wrote")

                with open("{}/{}/{}-{}{}".format(args.exfolder, ffmt[1:], hex(len(extracted)), randStr(8), ffmt), "wb") as output:
                    output.write(extracted)
                    output.flush()

            elif not fileIsGood and args.negative == True:
                print("\\ wrote negative")
                with open("{}/{}{}".format(args.exfolder, hex(len(extracted)), ffmt), "wb") as output:
                    output.write(extracted)
                    output.flush() 

print(magics)
