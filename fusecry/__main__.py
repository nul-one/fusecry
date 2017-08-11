#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

"""
Main runnable.
"""

from fuse import FUSE
from fusecry import single, cry
from fusecry.filesystem import Fusecry
from fusecry.securedata import secure
from getpass import getpass
import argparse
import signal
import sys

def signal_handler(signal, frame):
    print("KeyboardInterrupt captured. Stopping Fusecry gracefully...")
    sys.exit(0)

def parse_args():
    parser = argparse.ArgumentParser(
        prog = "fuse",
        description="Encrypted filesystem based on FUSE."
        )
    subparsers = parser.add_subparsers(
        description='(use each command with -h for more help)',
        dest='cmd',
        )
    parser_mount = subparsers.add_parser(
        'mount',
        description='Mount source dir to local directory.'
        )

    parser_mount.add_argument(
        'root', type=str, action="store",
        help='Source directory with encrypted files.')
    parser_mount.add_argument(
        'mountpoint', type=str, action="store",
        help='Mountpoint.')
    parser_mount.add_argument(
        '-p', '--password', action="store",
        help="If not provided, will be asked for password in prompt.")
    parser_mount.add_argument(
        '-d', '--debug', action="store_true",
        help="Enable debug mode with print output of each fs action.")
    parser_mount.set_defaults(
        debug=False,
    )

    parser_encrypt = subparsers.add_parser(
        'encrypt',
        description='Encrypt single file.'
        )
    parser_encrypt.add_argument(
        'in_file', type=str, action="store",
        help='Input file for encryption.')
    parser_encrypt.add_argument(
        'out_file', type=str, action="store",
        help='Encrypted file output.')
    parser_encrypt.add_argument(
        '-p', '--password', action="store",
        help="If not provided, will be asked for password in prompt.")

    parser_decrypt = subparsers.add_parser(
        'decrypt',
        description='Decrypt single file.'
        )
    parser_decrypt.add_argument(
        'in_file', type=str, action="store",
        help='Input file for decryption.')
    parser_decrypt.add_argument(
        'out_file', type=str, action="store",
        help='Decrypted file output.')
    parser_decrypt.add_argument(
        '-p', '--password', action="store",
        help="If not provided, will be asked for password in prompt.")
 
    return parser.parse_args()


def secure_password(password=None):
    while not password:
        password = secure(getpass())
        print("Confirm...")
        if password != getpass():
            password = None
            print("Passwords did not match. Try again...")
    return secure(password)
 

def main():
    signal.signal(signal.SIGINT, signal_handler)
    args = parse_args()
    if args.cmd == 'mount':
        password = secure_password(args.password)
        del args.password
        FUSE(
            Fusecry(
                args.root,
                secure(password),
                args.debug
                ),
            args.mountpoint,
            nothreads=True,
            foreground=True
            )
    elif args.cmd == 'encrypt':
        password = secure_password(args.password)
        single.encrypt(cry.Cry(password), args.in_file, args.out_file)
    elif args.cmd == 'decrypt':
        password = secure_password(args.password)
        single.decrypt(cry.Cry(password), args.in_file, args.out_file)


if __name__ == '__main__':
    main()

