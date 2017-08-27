#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

"""
Main runnable.
"""

from fuse import FUSE
from fusecry import single, io, config, stream
from fusecry.filesystem import FuseCry
from fusecry.securedata import secure
from getpass import getpass
import argcomplete
import argparse
import os
import signal
import subprocess
import sys

def signal_handler(signal, frame):
    sys.stderr.write(
        "KeyboardInterrupt captured. Stopping FuseCry gracefully.\n")
    sys.exit(0)

def check_chunk_size(chunk_size):
    from Crypto.Cipher.AES import block_size
    chunk_size = int(chunk_size)
    if chunk_size % block_size:
        raise ValueError(
            "Chunk size should be multiple of {}.".format(block_size))
    return chunk_size

def parse_args():
    from Crypto.Cipher.AES import block_size
    parser = argparse.ArgumentParser(
        prog = "fuse",
        description="Encrypted filesystem based on FUSE."
        )
    parser.add_argument(
        "-d", "--debug", action="store_true",
        help="Enable debug mode with print output of each fs action.")
    subparsers = parser.add_subparsers(
        description="(use each command with -h for more help)",
        dest="cmd",
        )

    parser_mount = subparsers.add_parser(
        "mount",
        description="Mount source dir to local mountpoint."
        )
    parser_mount.add_argument(
        "root", type=str, action="store",
        help="Source directory with encrypted files.")
    parser_mount.add_argument(
        "mountpoint", type=str, action="store",
        help="Mountpoint.")
    parser_mount.add_argument(
        "-p", "--password", action="store",
        help="If not provided, will be asked for password in prompt.")
    parser_mount.add_argument(
        "-k", "--key", action="store",
        help="Specify RSA key file instead of using password for encryption.")
    parser_mount.add_argument(
        "-c", "--conf", type=str, action="store",
        help="Specify or create FuseCry configuration file.")
    parser_mount.add_argument(
        "--chunk-size", type=check_chunk_size, action="store",
        help="Set chunk size. Has to be multiple of {}.".format(block_size))
    parser_mount.set_defaults(
        password = None,
        key=None,
        conf = None,
        chunk_size = config.default_chunk_size,
    )

    parser_umount = subparsers.add_parser(
        "umount",
        description="Unmount the mountpoint."
        )
    parser_umount.add_argument(
        "mountpoint", type=str, action="store",
        help="Mountpoint.")

    parser_encrypt = subparsers.add_parser(
        "encrypt",
        description="Encrypt single file."
        )
    parser_encrypt.add_argument(
        "in_file", type=str, action="store",
        help="Input file for encryption.")
    parser_encrypt.add_argument(
        "out_file", type=str, action="store",
        help="Encrypted file output.")
    parser_encrypt.add_argument(
        "-p", "--password", action="store",
        help="If not provided, will be asked for password in prompt.")
    parser_encrypt.add_argument(
        "-k", "--key", type=str, action="store",
        help="Use RSA private key file instead of password.")
    parser_encrypt.add_argument(
        "-c", "--conf", type=str, action="store",
        help="Specify or create FuseCry configuration file.")
    parser_encrypt.set_defaults(
        root = None,
        password = None,
        key = None,
        conf = None,
        chunk_size = config.default_chunk_size,
    )

    parser_decrypt = subparsers.add_parser(
        "decrypt",
        description="Decrypt single file."
        )
    parser_decrypt.add_argument(
        "in_file", type=str, action="store",
        help="Input file for decryption.")
    parser_decrypt.add_argument(
        "out_file", type=str, action="store",
        help="Decrypted file output.")
    parser_decrypt.add_argument(
        "-p", "--password", action="store",
        help="If not provided, will be asked for password in prompt.")
    parser_decrypt.add_argument(
        "-k", "--key", type=str, action="store",
        help="Use RSA private key file instead of password.")
    parser_decrypt.add_argument(
        "-c", "--conf", type=str, action="store",
        help="Specify or create FuseCry configuration file.")
    parser_decrypt.set_defaults(
        root = None,
        password = None,
        key = None,
        conf = None,
        chunk_size = config.default_chunk_size,
    )

    parser_stream = subparsers.add_parser(
        "stream",
        description="Encrypt or decrypt pipe data."
        )
    parser_stream.add_argument(
        "action", type=str, action="store", choices=('encrypt','decrypt'),
        help="Choose encrypt or decrypt.")
    parser_stream.add_argument(
        "-c", "--conf", type=str, action="store", required=True,
        help="Specify or create FuseCry configuration file.")
    parser_stream.add_argument(
        "-p", "--password", action="store",
        help="If not provided, will be asked for password in prompt.")
    parser_stream.add_argument(
        "-k", "--key", type=str, action="store",
        help="Use RSA private key file instead of password.")
    parser_stream.add_argument(
        "--chunk-size", type=check_chunk_size, action="store",
        help="Set chunk size. Has to be multiple of {}.".format(block_size))
    parser_stream.set_defaults(
        root = os.path.abspath(os.path.curdir),
        chunk_size = config.default_chunk_size,
    )

    parser_fsck = subparsers.add_parser(
        "fsck",
        description="Perform integrity check on all files and print results."
        )
    parser_fsck.add_argument(
        "root", type=str, action="store",
        help="Root dir of fusecry fs that is not mounted.")
    parser_fsck.add_argument(
        "-p", "--password", action="store",
        help="If not provided, will be asked for password in prompt.")
    parser_fsck.add_argument(
        "-k", "--key", type=str, action="store",
        help="Use RSA private key file instead of password.")
    parser_fsck.add_argument(
        "-c", "--conf", type=str, action="store",
        help="Specify FuseCry configuration file.")
    parser_fsck.set_defaults(
        password = None,
        key = None,
        conf = None,
    )

    argcomplete.autocomplete(parser)
    return parser.parse_args()

def get_io(args):
    root = os.path.abspath(args.root) if args.root else None
    conf_path = None
    chunk_size = args.chunk_size
    if args.conf:
        conf_path = os.path.abspath(args.conf)
    elif root:
        conf_path = os.path.join(root, config.conf)
    elif os.path.isfile(os.path.abspath(args.in_file + config.extension)):
        conf_path = os.path.abspath(args.in_file + config.extension)
    else:
        conf_path = os.path.abspath(args.out_file + config.extension)
    fcio = None
    try:
        if args.key:
            key_path = os.path.abspath(args.key)
            fcio = io.RSAFuseCryIO(key_path, root, conf_path, chunk_size)
        else:
            password = get_secure_password(args.password) \
                if os.path.isfile(conf_path) \
                else get_secure_password_twice(args.password)
            del args.password # don't keep it plaintext in memory
            fcio = io.PasswordFuseCryIO(password, root, conf_path, chunk_size)
    except io.IntegrityCheckException as e:
        sys.stderr.write("Bad key.\n")
        sys.exit(1)
    except io.BadConfException as e:
        sys.stderr.write(str(e)+"\n")
        sys.exit(1)
    return fcio

def get_secure_password(password=None):
    if not password:
        password = getpass()
    return secure(password)

def get_secure_password_twice(password=None):
    while not password:
        password = get_secure_password(password)
        sys.stderr.write("Confirm...\n")
        if password != getpass():
            password = None
            sys.stderr.write("\nPasswords did not match. Try again...\n")
    return password
 
def main():
    args = parse_args()
    signal.signal(signal.SIGINT, signal_handler)
    if args.cmd == 'mount':
        root = os.path.abspath(args.root)
        mountpoint = os.path.abspath(args.mountpoint)
        fcio = get_io(args)
        sys.stderr.write("-- FuseCry mounting '{}' to '{}'\n".format(
            root, mountpoint))
        FUSE(
            FuseCry(
                root,
                fcio,
                args.debug,
                ),
            mountpoint,
            foreground=args.debug
            )
    elif args.cmd == 'umount':
        subprocess.call(('fusermount','-u', args.mountpoint))
    elif args.cmd == 'encrypt':
        fcio = get_io(args)
        single.encrypt(
            fcio,
            args.in_file,
            args.out_file,
            info = True,
            )
    elif args.cmd == 'decrypt':
        fcio = get_io(args)
        single.decrypt(
            fcio,
            args.in_file,
            args.out_file,
            info = True,
            )
    elif args.cmd == 'stream':
        fcio = get_io(args)
        if args.action == 'encrypt':
            stream.encrypt(fcio, sys.stdin, sys.stdout)
        elif args.action == 'decrypt':
            stream.decrypt(fcio, sys.stdin, sys.stdout)
    elif args.cmd == 'fsck':
        root = os.path.abspath(args.root)
        fcio = get_io(args)
        fcio.fsck(root)

if __name__ == '__main__':
    main()

