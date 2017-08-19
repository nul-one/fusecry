"""
Encrypt or decrypt a single file.
"""

from fusecry import config, io
from fusecry.io import FusecryIO
import os

def encrypt(io, in_path, out_path, info=False):
    cs = config.enc.chunk_size
    size = os.path.getsize(in_path)
    with open(in_path, 'rb') as in_file:
        io.touch(out_path)
        io.truncate(out_path, 0)
        offset = 0
        while offset < size:
            io.write(out_path, in_file.read(cs), offset)
            offset += cs
    if info:
        print("-- '{}' encrypted as '{}'".format(in_path, out_path))

def decrypt(io, in_path, out_path, info=False):
    io.touch(out_path)
    cs = config.enc.chunk_size
    size = io.filesize(in_path)[0]
    with open(out_path, 'r+b') as out_file:
        out_file.truncate()
        offset = 0
        while offset < size:
            out_file.write(io.read(in_path, cs, offset))
            offset += cs
    if info:
        print("-- '{}' decrypted as '{}'".format(in_path, out_path))

