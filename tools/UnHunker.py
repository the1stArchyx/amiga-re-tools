#!/bin/python3

import argparse
import struct


hunk_names = {0x3e7: "HUNK_UNIT",
              0x3e8: "HUNK_NAME",
              0x3e9: "HUNK_CODE",
              0x3ea: "HUNK_DATA",
              0x3eb: "HUNK_BSS",
              0x3ec: "HUNK_RELOC32",
              0x3ed: "HUNK_RELOC16",
              0x3ee: "HUNK_RELOC8",
              0x3ef: "HUNK_EXT",
              0x3f0: "HUNK_SYMBOL",
              0x3f1: "HUNK_DEBUG",
              0x3f2: "HUNK_END",
              0x3f3: "HUNK_HEADER",
              0x3f5: "HUNK_OVERLAY",
              0x3f6: "HUNK_BREAK",
              0x3f7: "HUNK_DREL32",
              0x3f8: "HUNK_DREL16",
              0x3f9: "HUNK_DREL8",
              0x3fa: "HUNK_LIB",
              0x3fb: "HUNK_INDEX",
              0x3fc: "HUNK_RELOC32SHORT",
              0x3fd: "HUNK_RELRELOC32",
              0x3fe: "HUNK_ABSRELOC16"}

# list of hunks, contains a list for each hunk:
# 0 - int  - memory type, chip/fast/any
# 1 - int  - pointer % 4 == 0 - below 1M for chip, between 1M to 10M for any, between 2M to 10M for fast
# 2 - int  - size in bytes % 4 == 0
# 3 - list - reloc tables - (target_hunk, (offsets))
hunks = []


parser = argparse.ArgumentParser(prog="UnHunker",
                                 description="A tool to decode a 'Hunk' executable into a statically addressed memory dump file")
parser.add_argument("filename")

args = parser.parse_args()

with open(args.filename, "rb") as hunkFile:
    fileBytes = hunkFile.read()

firstHunk = struct.unpack(">I", fileBytes[:4])[0]
if firstHunk in hunk_names:
    print(f"File starts with {hunk_names[firstHunk]}.")
    if firstHunk == 0x3f3:
        pointer = 4
        libNames = []
        while True:
            stringLen = struct.unpack(">I", fileBytes[pointer:pointer + 4])[0]
            pointer += 4
            if not stringLen:
                break
            byteLen = stringLen * 4
            libNames.append(fileBytes[pointer:pointer + byteLen].decode(encoding="latin_1"))
            pointer += byteLen
        if len(libNames):
            print(f"Following resident libraries are specified: {libNames}.")

        tableSize = struct.unpack(">I", fileBytes[pointer:pointer + 4])[0]
        firstHunk = struct.unpack(">I", fileBytes[pointer + 4:pointer + 8])[0]
        lastHunk = struct.unpack(">I", fileBytes[pointer + 8:pointer + 12])[0]
        pointer += 12

        if (lastHunk - firstHunk + 1) != tableSize:
            print("Error: Hunk table size mismatch!")
            exit(1)

        for i in range(tableSize):
            hunkSize = struct.unpack(">I", fileBytes[pointer:pointer + 4])[0]
            pointer += 4
            memFlags = (hunkSize & 0xC0000000) >> 30
            hunkSize = (hunkSize & 0x3FFFFFFF) * 4
            addMemFlags = 0
            if memFlags == 3:
                addMemFlags = struct.unpack(">I", fileBytes[pointer:pointer + 4])[0]
                pointer += 4
            match memFlags:
                case 0:
                    memFlags = "any memory"
                case 1:
                    memFlags = "chip memory"
                case 2:
                    memFlags = "fast memory"
                case 3:
                    memFlags = f"memory specified by additional flags: {addMemFlags:x}"
            hunks.append([memFlags, 0, hunkSize, []])

        hunkIndex = 0
        while hunkIndex < tableSize:
            hunkID = struct.unpack(">I", fileBytes[pointer:pointer + 4])[0]
            match hunkID:
                case 0x3e9: # HUNK_CODE
                    hunkLen = struct.unpack(">I", fileBytes[pointer + 4:pointer + 8])[0] * 4
                    pointer += 8
                    hunks[hunkIndex][1] = pointer
                    if not hunks[hunkIndex][2] == hunkLen:
                        print(f"Error: Hunk length mismatch!\n| Hunk . . . . . . : {hunkIndex}\n| Length in header : {hunks[hunkIndex][2]:d} bytes\n| Length in hunk . : {hunkLen})")
                        exit(1)
                    pointer += hunkLen
                case 0x3ec: # HUNK_RELOC32
                    pointer += 4
                    while True:
                        offsetCount = struct.unpack(">I", fileBytes[pointer:pointer + 4])[0]
                        if not offsetCount:
                            break
                        relocTarget = struct.unpack(">I", fileBytes[pointer + 4:pointer + 8])[0]
                        pointer += 8
                        relocTable = []
                        for i in range(offsetCount):
                            relocTable.append(struct.unpack(">I", fileBytes[pointer:pointer + 4])[0])
                            pointer += 4
                        hunks[hunkIndex][3].append((relocTarget, tuple(relocTable)))
                    pointer += 4
                case 0x3f2: # HUNK_END
                    pointer += 4
                    hunkIndex += 1
                case _:
                    print(f"This tool cannot process files with {hunk_names[hunkID]} ({hunkID:x}).")
                    exit(1)
    print("Hunk headers processed.")

    for hunk in hunks:
        print(f"Memory type is {hunk[0]}, pointer to data is {hunk[1]}, data size is {hunk[2]} bytes.")
        if len(hunk[3]):
            print("Reloc tables:")
            for table in hunk[3]:
                print(f"  Target hunk: {table[0]} - offsets: {table[1]}")
else:
    print(f"Unknown hunk {firstHunk:x}.")
