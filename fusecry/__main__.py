#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

"""
Main runnable.
"""

from fuse import FUSE
from fusecry import single, io, config
from fusecry.daemon import Daemon
from fusecry.filesystem import Fusecry
from fusecry.securedata import secure
from getpass import getpass
import argcomplete
import argparse
import os
import signal
import sys

def signal_handler(signal, frame):
    print("KeyboardInterrupt captured. Stopping Fusecry gracefully.")
    sys.exit(0)

class FuseDaemon(Daemon):
    """
    Daemonize fuse process.
    """
    def __init__(self, pidfile, root, mountpoint, password, ignore_ic, debug):
        self.pidfile = pidfile
        self.root = root
        self.mountpoint = mountpoint
        self.password = password
        self.ignore_ic = ignore_ic
        self.debug = debug

    def run(self):
        FUSE(
            Fusecry(
                self.root,
                self.password,
                self.ignore_ic,
                self.debug
                ),
            self.mountpoint,
            foreground=True
            )

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
        "-i", "--ignore-ic", action="store_true",
        help="Don't fail on integrity check error.")
    parser_mount.add_argument(
        "-d", "--debug", action="store_true",
        help="Enable debug mode with print output of each fs action.")
    parser_mount.set_defaults(
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
        "-c", "--conf", type=str, action="store",
        help="Specify or create FuseCry configuration file.")
    parser_encrypt.add_argument(
        "-p", "--password", action="store",
        help="If not provided, will be asked for password in prompt.")
    parser_encrypt.set_defaults(
        conf = None,
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
        "-c", "--conf", type=str, action="store",
        help="Specify or create FuseCry configuration file.")
    parser_decrypt.add_argument(
        "-i", "--ignore-ic", action="store_true",
        help="Don't fail on integrity check error.")
    parser_decrypt.add_argument(
        "-p", "--password", action="store",
        help="If not provided, will be asked for password in prompt.")
    parser_decrypt.set_defaults(
        conf = None,
    )

    parser_fsck = subparsers.add_parser(
        "fsck",
        description="Perform integrity check on all files and print results."
        )
    parser_fsck.add_argument(
        "root", type=str, action="store",
        help="Root dir of fusecry fs that is not mounted.")
    parser_fsck.add_argument(
        "-i", "--ignore-ic", action="store_true",
        help="Don't fail on integrity check error.")
    parser_fsck.add_argument(
        "-p", "--password", action="store",
        help="If not provided, will be asked for password in prompt.")

    argcomplete.autocomplete(parser)
    return parser.parse_args()


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
        password = get_secure_password_twice(args.password)
        del args.password # don't keep it plaintext in memory
        mountpoint = os.path.abspath(args.mountpoint)
        root = os.path.abspath(args.root)
        print("-- mounting '{}' to '{}' with encryption{}".format(
            root, mountpoint,
            ' and file integrity check' if not args.ignore_ic else ''
            ))
        if args.debug:
            FUSE(
                Fusecry(
                    root,
                    password,
                    args.ignore_ic,
                    args.debug
                    ),
                mountpoint,
                foreground=True
                )
        else:
            pidfile = os.path.join(
                os.path.dirname(mountpoint),
                '.'+os.path.basename(os.path.abspath(mountpoint))+'.fcry.pid'
                )
            fuse_daemon = FuseDaemon(
                pidfile, root, mountpoint, password, args.ignore_ic,
                args.debug
                )
            fuse_daemon.start()
    elif args.cmd == 'umount':
        mountpoint = os.path.abspath(args.mountpoint)
        pidfile = os.path.join(
            os.path.dirname(mountpoint),
            '.'+os.path.basename(mountpoint)+'.fcry.pid'
            )
        fuse_daemon = FuseDaemon(pidfile, None, mountpoint, None, None, None)
        fuse_daemon.stop()
        print("-- '{}' has been unmounted".format(mountpoint))
    elif args.cmd == 'encrypt':
        password = get_secure_password_twice(args.password)
        conf = os.path.abspath(args.conf) if args.conf else None
        single.encrypt(
            io.make_io(password, conf, False),
            args.in_file,
            args.out_file
            )
    elif args.cmd == 'decrypt':
        password = get_secure_password(args.password)
        conf = os.path.abspath(args.conf) if args.conf else None
        single.decrypt(
            io.make_io(password, conf, args.ignore_ic),
            args.in_file,
            args.out_file
            )
    elif args.cmd == 'fsck':
        password = get_secure_password(args.password)
        root = os.path.abspath(args.root)
        conf = os.path.join(root, config.enc.conf)
        io.make_io(password, conf, args.ignore_ic).fsck(root)

if __name__ == '__main__':
    main()

