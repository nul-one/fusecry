"""
FuseCry stream encryption.
"""

import struct
from fusecry.io import IntegrityCheckException


def encrypt(io, stdin, stdout):
    stream_length = 0
    while True:
        data =  stdin.buffer.read(io.cs)
        stream_length += len(data)
        stdout.buffer.write(io.cry.enc(data))
        if len(data) < io.cs:
            break
    stdout.buffer.write(struct.pack('<Q', stream_length))

def decrypt(io, stdin, stdout):
    stream_length = 0
    data = stdin.buffer.read(io.cs+io.ms)
    while True:
        new_data = stdin.buffer.read(io.cs+io.ms)
        if len(new_data) < io.cs+io.ms:
            dec_data, ic_pass = io.cry.dec(data)
            io.check_ic_pass('stdin', ic_pass)
            if len(new_data) > io.cry.vs:
                new_dec_data, ic_pass = io.cry.dec(
                    new_data[:-(len(new_data)%io.cry.vs)])
                io.check_ic_pass('stdin', ic_pass)
                dec_data += new_dec_data
            stream_length += len(dec_data)
            length = struct.unpack('<Q', new_data[-io.ss:])[0]
            dec_data = dec_data[:-(stream_length - length)]
            stdout.buffer.write(dec_data)
            break
        dec_data, ic_pass = io.cry.dec(data)
        io.check_ic_pass('stdin', ic_pass)
        stream_length += len(dec_data)
        stdout.buffer.write(dec_data)
        data = new_data

