"""
a file carver leveraging 'RES...' headers
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

filePointer = 0

def addFilePtr(add):
    global filePointer
    filePointer += add
    return filePointer

def subFilePtr(sub):
    global filePointer
    filePointer -= sub
    return filePointer

if args.exfolder != None and not os.path.exists(args.exfolder):
    os.mkdir(args.exfolder)

resMagic = b"\x52\x45\x53\x19"
knownStrings = [b"STR", b"PIC"]

def randStr(amnt):
    return ''.join([random.choice("abcdef") for x in range(amnt)])

with open(args.bin, "rb") as f:
    data = f.read()

if not os.path.exists("carver2-dump"): os.mkdir("carver2-dump")
while True: # iterate over whole .bin
    header = []
    fileData = b''
    fileDataDict = {}

    resStart = data.find(resMagic)
    filePointer = resStart

    if resStart != -1:
        if resMagic in data[filePointer:addFilePtr(16)]:
            print("[+] magic str found")
        else:
            print("[+] magic str not found")
            quit()
        
        while True: # iterate to find the whole header
            hexString = data[filePointer:addFilePtr(16)] # each filedata header row is 16bytes
            
            if knownStrings[0] in hexString or knownStrings[1] in hexString:
                header.append(hexString)
                print("[+] added {} to header".format(hexString))
            else:
                print("[!] did not find 0x0000 @ {} - instead found {} - assuming this is start of file data...".format(hex(filePointer-16), hexString))
                fileData += hexString
                break

        while True: # iterate to find the filedata
            hexString = data[filePointer:addFilePtr(16)] # 16bytes to be safe

            print("\r[PTR] @ {}".format(hex(filePointer)), end='', flush=True)

            fileData += hexString
            if resMagic in hexString or b'\x00'*16 in hexString:
                print("\r[+] EOF found @ {}".format(hex(filePointer-16)))
                break
    else:
        print("[!!!] couldn't find magic number - breaking..")
        break

    print('[+] reading data..')
    if not os.path.exists("./carver2-dump/"+hex(resStart)): os.mkdir("./carver2-dump/"+hex(resStart))
    for row in header:
        if type(row) == int: continue

        flen = int.from_bytes((row[4:6])[::-1]) # reversed? idk why
        fname = row[7:0x0F].replace(b'\x00', b'')

        print("[-] file length: {} | file name: {}/{}".format(flen, hex(resStart), fname))
        fileDataDict[fname] = fileData[:flen]

        with open("./carver2-dump/{}/{}".format(hex(resStart), fname.decode('ascii')), "wb") as f:
            f.write(fileDataDict[fname])
            f.flush()

        fileData = fileData[flen:] # remove file

    data = data[:resStart] + data[filePointer:]
    print("[+] {} bytes left\n\n".format(len(data)))
    

with open("leftover.bin", "wb") as f:
    f.write(data)
    f.flush()