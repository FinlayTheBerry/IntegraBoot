#!/bin/env python
import os
import subprocess
import sys

def WriteFile(filePath, contents, binary=False):
    filePath = os.path.realpath(os.path.expanduser(filePath))
    os.makedirs(os.path.dirname(filePath), exist_ok=True)
    with open(filePath, "wb" if binary else "w", encoding=(None if binary else "UTF-8")) as file:
        file.write(contents)
def ReadFile(filePath, defaultContents=None, binary=False):
    filePath = os.path.realpath(os.path.expanduser(filePath))
    if not os.path.exists(filePath):
        if defaultContents != None:
            return defaultContents
    with open(filePath, "rb" if binary else "r", encoding=(None if binary else "UTF-8")) as file:
        return file.read()
def RunCommand(command, echo=False, capture=False, input=None, check=True):
    result = subprocess.run(command, capture_output=(not echo), input=input, check=check, shell=True, text=True)
    if capture and not check:
        return (result.stdout + result.stderr).strip(), result.returncode
    elif capture:
        return (result.stdout + result.stderr).strip()
    elif not check:
        return result.returncode
    else:
        return
def PrintWarning(message):
    print(f"\033[93mWarning: {message}\033[0m")
def PrintError(message):
    print(f"\033[91mERROR: {message}\033[0m")

def HashEFIImage(efi_image):
    pe = pefile.PE(data=efi_image, fast_load=True)

    hasher = hashlib.new("sha256")

    checksum_offset = pe.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum")

    security_dir_entry_offset = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].get_field_absolute_offset("VirtualAddress")
    
    sig_pos = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress
    sig_len = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
    
    if sig_pos > 0 and sig_len > 0:
        file_end = sig_pos
        is_signed = True
    else:
        file_end = len(efi_image)
        is_signed = False

    hasher.update(efi_image[0:checksum_offset])
    hasher.update(efi_image[checksum_offset + 4:security_dir_entry_offset])
    hasher.update(efi_image[security_dir_entry_offset + 8:file_end])
    
    if not is_signed:
        remainder = file_end % 8
        if remainder > 0:
            padding_len = 8 - remainder
            hasher.update(b'\x00' * padding_len)

    return hasher.digest()

def Main():
    if len(sys.argv) != 2:
        print("USAGE: hash_efi_image /path/to/binary.efi")
        return 1
    print(f"{sys.argv[1]} -> {HashEFIImage(ReadFile(sys.argv[1], binary=True)).hex()}")
    return 0
sys.exit(Main())