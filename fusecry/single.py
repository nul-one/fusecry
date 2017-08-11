"""
Encrypt or decrypt a single file.
"""

from fusecry import config, io
import os


def encrypt(cry, in_path, out_path):
    cs = config.enc.chunk_size
    size = os.path.getsize(in_path)
    with open(in_path, 'rb') as in_file:
        io.touch(out_path)
        io.truncate(cry, out_path, 0)
        offset = 0
        while offset < size:
            io.write(cry, out_path, in_file.read(cs), offset)
            offset += cs


def decrypt(cry, in_path, out_path):
    cs = config.enc.chunk_size
    size = io.filesize(in_path)
    io.touch(out_path)
    with open(out_path, 'r+b') as out_file:
        out_file.truncate()
        offset = 0
        while offset < size:
            out_file.write(io.read(cry, in_path, cs, offset))
            offset += cs

