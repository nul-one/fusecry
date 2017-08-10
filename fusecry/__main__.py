#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

"""
Main runnable.
"""

from fuse import FUSE
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
    parser_decrypt = subparsers.add_parser(
        'encrypt',
        description='Decrypt single file.'
        )
 
    return parser.parse_args()

def main():
    signal.signal(signal.SIGINT, signal_handler)
    args = parse_args()
    if args.cmd == 'mount':
        password = secure(args.password)
        del args.password
        while not password:
            password = secure(getpass())
            print("Confirm...")
            if password != getpass():
                password = None
                print("Passwords did not match. Try again...")
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

if __name__ == '__main__':
    main()

