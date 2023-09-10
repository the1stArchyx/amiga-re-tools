#!/bin/python3

import argparse
import struct

parser = argparse.ArgumentParser(description="A tool to extract files and raw blocks from ADF disk images.",
                                 epilog="This program is currently mostly in the non-functional deveplopment stage.")

parser.add_argument('filename')

args = parser.parse_args()

with open(args.filename, "rb") as inputFile:
    diskImage = inputFile.read()

diskTypes = (b"DOS\x00", b"DOS\x02", b"DOS\x04")
diskType = diskImage[0:4]

print(f"DiskType is {diskType}.")
if diskType not in diskTypes:
    print(f"DiskType {diskType} is unknown or not supported by this program.")
    exit(1)

if len(diskImage) != 901120:
    print(f"File length mismatch. Got {len(diskImage)} instead of expected 901120.")
    exit(1)

rootBlock = struct.unpack(">I", diskImage[8:12])[0] * 512
print(f"RootBlock ({rootBlock // 512}) is at {rootBlock}.")
volumeNamePointer = rootBlock + 512 - 79
volumeNameLength = diskImage[rootBlock + 512 - 80]
volumeName = diskImage[volumeNamePointer:volumeNamePointer + volumeNameLength].decode(encoding="Latin1")
print(f"Volume name is at {volumeNamePointer}. length is {volumeNameLength}: {volumeName}")
