#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

"""
Main runnable.
"""

from fuse import FUSE
from fusecry import single, io, config
from fusecry.filesystem import Fusecry
from fusecry.securedata import secure
from getpass import getpass
import argcomplete
import argparse
import os
import signal
import subprocess
import sys

def signal_handler(signal, frame):
    print("KeyboardInterrupt captured. Stopping Fusecry gracefully.")
    sys.exit(0)

def parse_args():
    parser = argparse.ArgumentParser(
        prog = "fuse",
        description="Encrypted filesystem based on FUSE."
        )
    subparsers = parser.add_subparsers(
        description="(use each command with -h for more help)",
        dest="cmd",
        )

    parser_mount = subparsers.add_parser(
        "mount",
        description="Mount source dir to local directory."
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
        "--chunk-size", type=int, action="store",
        help="Set chunk size. Has to be multiple of 4096.")
    parser_mount.add_argument(
        "-d", "--debug", action="store_true",
        help="Enable debug mode with print output of each fs action.")
    parser_mount.set_defaults(
        password = None,
        key=None,
        conf = None,
        chunk_size = config.enc.default_chunk_size,
        debug=False,
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
        chunk_size = config.enc.default_chunk_size,
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
        chunk_size = config.enc.default_chunk_size,
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
        conf_path = os.path.join(root, config.enc.conf)
    elif os.path.isfile(os.path.abspath(args.in_file + config.enc.extension)):
        conf_path = os.path.abspath(args.in_file + config.enc.extension)
    else:
        conf_path = os.path.abspath(args.out_file + config.enc.extension)
    fcio = None
    if args.key:
        key_path = os.path.abspath(args.key)
        try:
            fcio = io.RSAFusecryIO(key_path, root, conf_path, chunk_size)
        except io.IntegrityCheckException as e:
            print("Bad key.")
            sys.exit(1)
        except io.BadConfException as e:
            print(e)
            sys.exit(1)
    else:
        password = get_secure_password(args.password) \
            if os.path.isfile(conf_path) \
            else get_secure_password_twice(args.password)
        del args.password # don't keep it plaintext in memory
        try:
            fcio = io.PasswordFusecryIO(password, root, conf_path, chunk_size)
        except io.IntegrityCheckException as e:
            print("Bad key.")
            sys.exit(1)
        except io.BadConfException as e:
            print(e)
            sys.exit(1)
    return fcio

def get_secure_password(password=None):
    if not password:
        password = getpass()
    return secure(password)

def get_secure_password_twice(password=None):
    while not password:
        password = get_secure_password(password)
        print("Confirm...")
        if password != getpass():
            password = None
            print("\nPasswords did not match. Try again...")
    return password
 
def main():
    args = parse_args()
    signal.signal(signal.SIGINT, signal_handler)
    if args.cmd == 'mount':
        if args.chunk_size % config.enc.default_chunk_size:
            print("Chunk size has to be a multiple of 4096.")
            sys.exit(1)
        root = os.path.abspath(args.root)
        mountpoint = os.path.abspath(args.mountpoint)
        fcio = get_io(args)
        print("-- FuseCry mounting '{}' to '{}'".format(root, mountpoint))
        FUSE(
            Fusecry(
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
    elif args.cmd == 'fsck':
        root = os.path.abspath(args.root)
        fcio = get_io(args)
        fcio.fsck(root)

if __name__ == '__main__':
    main()

