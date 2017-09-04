"""
Encrypt or decrypt a single file.
"""

import os
import logging


def encrypt(io, in_path, out_path):
    size = os.path.getsize(in_path)
    with open(in_path, 'rb') as in_file:
        io.touch(out_path)
        io.truncate(out_path, 0)
        offset = 0
        while offset < size:
            io.write(out_path, in_file.read(io.cs), offset)
            offset += io.cs
    logging.info("File '%s' encrypted as '%s'",in_path, out_path)

def decrypt(io, in_path, out_path):
    io.touch(out_path)
    size = io.filesize(in_path)
    with open(out_path, 'w+b') as out_file:
        out_file.truncate()
        offset = 0
        while offset < size:
            out_file.write(io.read(in_path, io.cs, offset))
            offset += io.cs
    logging.info("File '%s' decrypted as '%s'", in_path, out_path)


