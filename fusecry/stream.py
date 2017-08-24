"""
FuseCry stream encryption.
"""

import struct
from fusecry.io import IntegrityCheckException


def encrypt(io, stdin, stdout):
    stream_length = 0
    while True:
        data =  stdin.buffer.read(io.cs)
        length = len(data)
        if not length:
            break
        stream_length += length
        stdout.buffer.write(io.cry.enc(data))
    stdout.buffer.write(struct.pack('<Q', stream_length))

def decrypt(io, stdin, stdout):
    stream_length = 0
    data = stdin.buffer.read(io.cs+io.ms)
    while True:
        new_data = stdin.buffer.read(io.cs+io.ms)
        if len(new_data) < io.ss:
            data += new_data
            dec_data, ic_pass = io.cry.dec(data[:-(len(data)%16)])
            if not ic_pass:
                raise IntegrityCheckException("Stream integrity check fail.")
            stream_length += len(dec_data)
            length = struct.unpack('<Q', data[-io.ss:])[0]
            dec_data = dec_data[:-(stream_length - length)]
            stdout.buffer.write(dec_data)
            break
        dec_data, ic_pass = io.cry.dec(data)
        if not ic_pass:
            raise IntegrityCheckException("Stream integrity check fail.")
        stream_length += len(dec_data)
        stdout.buffer.write(dec_data)
        data = new_data

