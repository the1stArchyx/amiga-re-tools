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

        hunkSizes = []
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
            hunkSizes.append((hunkSize, memFlags))

        endOfHeader = pointer

        print("\nHunk size table:")
        for (i, j) in hunkSizes:
            print(f"{i:8x} ({i:10d}) – Loads to {j}.")

        print("\nHunks as discovered:")
        hunks = []
        hunkCount = tableSize
        while hunkCount:
            hunkID = struct.unpack(">I", fileBytes[pointer:pointer + 4])[0]
            match hunkID:
                case 0x3e9:
                    hunkLen = struct.unpack(">I", fileBytes[pointer + 4:pointer + 8])[0] * 4
                    pointer += 8
                    hunkPointer = pointer
                    hunks.append((hunkID, hunkPointer, hunkLen))
                    print(f"Found {hunk_names[hunkID]} – length {hunkLen:d} bytes. Code starts at {hunkPointer:x}.")
                    pointer += hunkLen
                case 0x3ec:
                    print(f"Found {hunk_names[hunkID]}.")
                    pointer += 4
                    hunkPointer = pointer
                    while True:
                        offsetCount = struct.unpack(">I", fileBytes[pointer:pointer + 4])[0]
                        if not offsetCount:
                            break
                        relocTable = [struct.unpack(">I", fileBytes[pointer + 4:pointer + 8])[0]]
                        pointer += 8
                        for i in range(offsetCount):
                            relocTable.append(struct.unpack(">I", fileBytes[pointer:pointer + 4])[0])
                            pointer += 4
                        print(f"– Target hunk: {relocTable[0]} – offsets to relocate: {relocTable[1:]}")
                    pointer += 4
                case 0x3f2:
                    pointer += 4
                    print(f"Found {hunk_names[hunkID]}.")
                    hunkCount -= 1
                case _:
                    print(f"{hunkID:x}")
                    break

else:
    print(f"Unknown hunk {firstHunk:x}.")
