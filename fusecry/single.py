"""
Encrypt or decrypt a single file.

Create FuseCry io object and use it with `encrypt` and `decrypt` functions.
"""
import os
import logging


def encrypt(io, in_path, out_path):
    """Encrypt input file and save output file and FuseCry conf file.

    Two output files will be created::
        [out_path] - encrypted file and 
        [out_path].fcry - FuseCry conf file needed for decryption

    Args:
        io (FuseCry.io): FuseCry io object.
        in_path (str): Raw file path.
        out_path (str): Encrypted file output path.
    """
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
    """Decrypt input file (with .fcry file present) and save raw output file.

     Two input files will be needed in the same dir::
        [in_path] - encrypted file and
        [in_path].fcry - FuseCry conf file needed for decryption

    Args:
        io (FuseCry.io): FuseCry io object.
        in_path (str): Encrypted file path.
        out_path (str): Raw file output path.
    """
    io.touch(out_path)
    size = io.filesize(in_path)
    with open(out_path, 'w+b') as out_file:
        out_file.truncate()
        offset = 0
        while offset < size:
            out_file.write(io.read(in_path, io.cs, offset))
            offset += io.cs
    logging.info("File '%s' decrypted as '%s'", in_path, out_path)


