#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

"""
Main runnable.
"""

from fuse import FUSE
from fusecry.fusecry import Fusecry as filesystem
from fusecry.securedata import secure
import fusecry
import argparse
import sys
from getpass import getpass

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
    return parser.parse_args()

#def main(root, mountpoint, password):
def main():
    args = parse_args()
    if args.cmd == 'mount':
        password = args.password or getpass()
        FUSE(
            filesystem(
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

