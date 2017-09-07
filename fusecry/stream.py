"""
Encrypt and decrypt streams using FuseCry.

Create FuseCry io object and use it with `encrypt` and `decrypt` functions.
"""
import struct

def encrypt(io, stdin, stdout):
    """Encrypt stream.

    Args:
        io (FuseCry.io): FuseCry io object.
        stdin: Input raw data stream (e.g. sys.stdin)
        stdout: Output encrypted stream (e.g. sys.stdout)
    """
    stream_length = 0
    while True:
        data =  stdin.buffer.read(io.cs)
        stream_length += len(data)
        stdout.buffer.write(io.cry.enc(data))
        if len(data) < io.cs:
            break
    stdout.buffer.write(struct.pack('<Q', stream_length))

def decrypt(io, stdin, stdout):
    """Decrypt stream.

    Args:
        io (FuseCry.io): FuseCry io object.
        stdin: Input encrypted stream (e.g. sys.stdin)
        stdout: Output raw data stream (e.g. sys.stdout)
    """
    stream_length = 0
    data = stdin.buffer.read(io.ecs)
    while True:
        new_data = stdin.buffer.read(io.ecs)
        if len(new_data) < io.ecs:
            dec_data = b""
            new_dec_data = b""
            length = struct.unpack('<Q', (data+new_data)[-io.ss:])[0]
            if len(new_data) > io.ss:
                new_dec_data = io.cry.dec(
                    new_data[:-(len(new_data)%io.cry.vs)])
            else:
                data = data[:-(io.ss - len(new_data))]
            if len(data) % io.cry.vs:
                dec_data = io.cry.dec(data[:-(len(data) % io.cry.vs)])
            else:
                dec_data = io.cry.dec(data)
            stream_length += len(dec_data)
            stream_length += len(new_dec_data)
            full_dec_data = (dec_data + new_dec_data)[:-(stream_length - length)]
            stdout.buffer.write(full_dec_data)
            break
        dec_data = io.cry.dec(data)
        stream_length += len(dec_data)
        stdout.buffer.write(dec_data)
        data = new_data

