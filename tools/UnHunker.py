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
# 0 - int   - memory type, 0=any/1=chip/2=fast
# 1 - int   - pointer % 4 == 0 - pointer to data
# 2 - int   - size in bytes % 4 == 0
# 3 - list  - reloc tables - (target_hunk, (offsets))
# 4 - int   - target address - below 1M for chip, between 1M to 10M for any/fast
# 5 - bytes - relocated data
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
                case 3:
                    print(f"Error: This tool cannot process hunks with additional memory allocation flags. ({addMemFlags:x})")
                    exit(1)
            hunks.append([memFlags, 0, hunkSize, [], 0, b""])

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

    # map hunks into memory
    chip_pointer = 0x100000
    fast_pointer = 0x100000
    for i in range(len(hunks)):
        match hunks[i][0]:
            case 0 | 2:
                hunks[i][4] = fast_pointer
                fast_pointer += hunks[i][2]
                if fast_pointer > 0xA00000:
                    print("Error: hunks to be allocated above chip memory do not fit.")
                    exit(1)
            case 1:
                chip_pointer -= hunks[i][2]
                if chip_pointer < 0:
                    print("Error: hunks to be allocated into chip memory do not fit.")
                    exit(1)
                hunks[i][4] = chip_pointer

    entry_point = hunks[0][4]
    # apply reloc tables
    for i in range(len(hunks)):
        pointer = hunks[i][1]
        dataEnd = pointer + hunks[i][2]
        if len(hunks[i][3]):
            relocs = []  # list of tuples, (offset, reloc)
            for table in hunks[i][3]:
                targetAddr = hunks[table[0]][4]
                for offset in table[1]:
                    relocs.append((offset, targetAddr))
            relocs = sorted(relocs, key=lambda offs: offs[0])

        while len(relocs):
            (o, r) = relocs.pop(0)
            o += hunks[i][1]
            if o < pointer:
                print("Reloc table offset error.")
            hunks[i][5] += fileBytes[pointer:o]
            raw = struct.unpack(">I", fileBytes[o:o + 4])[0]
            hunks[i][5] += struct.pack(">I", raw + r)
            print(f"Relocated {raw:x} @ {o:x} to {(raw + r):x}")
            pointer = o + 4
        hunks[i][5] += fileBytes[pointer:dataEnd]

    for hunk in hunks:
        print(f"Actual data length {len(hunk[5])} vs. specified data length {hunk[2]}")

    hunks = sorted(hunks, key=lambda target: target[4])
    outBytes = b""
    for hunk in hunks:
        pointer = chip_pointer + len(outBytes)
        startpointer = hunk[4]
        if startpointer < pointer:
            print(f"Error: Data pointer collision - pointer = {pointer}; startpointer = {startpointer}")
            exit(1)
        if startpointer > pointer:
            outBytes += bytes(startpointer - pointer)
        outBytes += hunk[5]

    print(f"Output buffer length: {len(outBytes)}")

    with open(f"{args.filename}-0x{chip_pointer:x}.memdump", "wb") as outFile:
        outFile.write(outBytes)

    print(f"Load memory dump file to 0x{chip_pointer:x}. Entry point is at 0x{entry_point:x}")
else:
    print(f"Unknown hunk {firstHunk:x}.")
