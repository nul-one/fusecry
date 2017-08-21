"""
Encrypt or decrypt a single file.
"""

from fusecry import config, io
from fusecry.io import FusecryIO
import os
import struct


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

def rsa_encrypt(cry_rsa, in_path, out_path, info=False):
    cs = config.enc.chunk_size
    size = os.path.getsize(in_path)
    with open(in_path, 'rb') as in_file:
        with open(out_path, 'w+b') as out_file:
            out_file.truncate()
            offset = 0
            while offset < size:
                out_file.write(cry_rsa.enc(in_file.read(cs)))
                offset += cs
            out_file.write(struct.pack('<Q', size))
    if info:
        print("-- '{}' encrypted as '{}' with rsa".format(in_path, out_path))

def rsa_decrypt(cry_rsa, in_path, out_path, info=False):
    cs = config.enc.chunk_size
    rsa_bs = 256
    hs = config.enc.hash_size
    size = 0
    with open(in_path, 'rb') as f:
        file_end = f.seek(0,os.SEEK_END)
        if file_end:
            f.seek(file_end-struct.calcsize('Q'))
            try:
                size = struct.unpack('<Q', f.read(struct.calcsize('Q')))[0]
            except struct.error as e:
                print("ERROR: problem reading file size.")
                return
    with open(out_path, 'w+b') as out_file:
        out_file.truncate()
        with open(in_path, 'rb') as in_file:
            offset = 0
            while offset < size:
                enc_chunk = in_file.read(rsa_bs + hs + cs)
                if len(enc_chunk) <= rsa_bs + hs:
                    break
                if len(enc_chunk) % 16:
                    enc_chunk = enc_chunk[:-(len(enc_chunk)%16)]
                out_file.write(cry_rsa.dec(enc_chunk)[0])
                offset += cs
        out_file.truncate(size)
    if info:
        print("-- '{}' decrypted as '{}' with rsa".format(in_path, out_path))


