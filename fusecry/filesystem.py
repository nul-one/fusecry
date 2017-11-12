"""
FuseCry implementation of fuse.Operations class and helper functions.
"""
from datetime import datetime
from fuse import FuseOSError, Operations
from fusecry import config
import errno
import logging
import os
import stat

__printables = lambda x: str(len(x)) if type(x) is bytes else str(x)
"""Used in debug_log to filter out long bytes and print only their length."""

def debug_log(func):
    """Function wrapper for logging fuse method calls and errors."""
    def function_wrapper(*args, **kwargs):
        if args[0].debug:
            el = map(__printables, args)
            logging.debug('{} {}'.format(func.__name__, list(el)[1:]))
        try:
            return func(*args, **kwargs)
        except FileNotFoundError as e:
            el = map(__printables, args)
            logging.debug("{} - {} {}".format(e, func.__name__, list(el)[1:]))
            raise e
        except Exception as e:
            el = map(__printables, args)
            logging.error("{} - {} {}".format(e, func.__name__, list(el)[1:]))
            raise e
    return function_wrapper


class FuseCry(Operations):
    """
    FuseCry implementation of fuse.Operations class.
    """
    def __path_to_dict(self, path, enc_name=None):
        """Represent file and directory structure as dict."""
        st = None
        try:
            st = os.stat(path)
        except FileNotFoundError:
            pass
        result = {}
        result['enc_name'] = enc_name
        if st and stat.S_ISDIR(st.st_mode):
            result['items'] = {}
            for enc_name in os.listdir(path):
                if enc_name != config._conf:
                    try:
                        dec_filename = self.io.cry.dec_filename(enc_name)
                        result['items'][dec_filename] = self.__path_to_dict(
                            os.path.join(path,enc_name),
                            enc_name
                            )
                    except Exception as e:
                        logging.error("{}, {}".format(e, enc_name))
        return result

    def __enc_path_delete(self, path):
        if path.startswith(os.path.sep):
            path = path[len(os.path.sep):]
        path_parent = self.fs_map
        for name in path.split(os.path.sep)[:-1]:
            path_parent = path_parent['items'][name]
        del path_parent['items'][path.split(os.path.sep)[-1]]

    def __enc_path_rename(self, old, new):
        if old.startswith(os.path.sep):
            old = old[len(os.path.sep):]
        if new.startswith(os.path.sep):
            new = new[len(os.path.sep):]
        old_fs_map = self.fs_map
        new_fs_map = self.fs_map
        for name in old.split(os.path.sep):
            old_fs_map = old_fs_map['items'][name]
        for name in new.split(os.path.sep):
            new_fs_map = new_fs_map['items'][name]
        if 'items' in old_fs_map:
            new_fs_map['items'] = old_fs_map['items']
        self.__enc_path_delete(old)

    def __init__(self, root, io, debug=False):

        self.root = root
        self.io = io
        if config.enc_path:
            self.real_path = self.__crypto_real_path
            self.fs_map = self.__path_to_dict(root)
        else:
            self.real_path = self.__real_path
            self.fs_map = None
        self.conf_path = os.path.join(self.root, config._conf)
        self.debug = debug

    def __crypto_real_path(self, path):
        path_split = filter(bool, path.split(os.path.sep))
        fs_map = self.fs_map
        real_path = self.root
        for name in path_split:
            if 'items' not in fs_map:
                fs_map['items'] = {}
            if name not in fs_map['items']:
                fs_map['items'][name] = {
                    'enc_name': self.io.cry.enc_filename(name)
                }
            real_path = os.path.join(
                real_path, fs_map['items'][name]['enc_name'])
            fs_map = fs_map['items'][name]
        return real_path

    def __real_path(self, path):
        if path.startswith(os.path.sep):
            path = path[len(os.path.sep):]
        return os.path.join(self.root, path)

    # Filesystem methods
    # ==================

    @debug_log
    def access(self, path, mode):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        if not os.access(real_path, mode):
            raise FuseOSError(errno.EACCES)

    @debug_log
    def chmod(self, path, mode):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        return os.chmod(real_path, mode)

    @debug_log
    def chown(self, path, uid, gid):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        return os.chown(real_path, uid, gid)

    @debug_log
    def getattr(self, path, fh=None):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        return self.io.attr(real_path)

    @debug_log
    def readdir(self, path, fh):
        real_path = self.real_path(path)
        dirents = ['.', '..']
        if os.path.isdir(real_path):
            dirents.extend(os.listdir(real_path))
            if os.path.abspath(real_path) == os.path.abspath(self.root):
                if config._conf in dirents:
                    dirents.remove(config._conf)
        if config.enc_path:
            for r in dirents:
                if r in ('.','..'):
                    yield r
                else:
                    try:
                        yield self.io.cry.dec_filename(r)
                    except Exception as e:
                        logging.error("{}, {}".format(e, r))
        else:
            for r in dirents:
                yield r

    @debug_log
    def readlink(self, path):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        pathname = os.readlink(real_path)
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    @debug_log
    def mknod(self, path, mode, dev):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        return os.mknod(real_path, mode, dev)

    @debug_log
    def rmdir(self, path):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        result = os.rmdir(real_path)
        self.__enc_path_delete(path)
        return result

    @debug_log
    def mkdir(self, path, mode):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        return os.mkdir(real_path, mode)

    @debug_log
    def statfs(self, path):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        stv = os.statvfs(real_path)
        stat = dict((key, getattr(stv, key)) for key in (
            'f_bavail', 'f_bfree', 'f_blocks', 'f_bsize', 'f_favail',
            'f_ffree', 'f_files', 'f_flag', 'f_frsize', 'f_namemax'))
        size_ratio = self.io.cs / (self.io.cs + self.io.ms)
        block_ratio = stat['f_bsize'] / self.io.cs
        stat['f_bsize']     = self.io.cs
        stat['f_frsize']    = self.io.cs
        stat['f_blocks']    = int(stat['f_blocks'] * size_ratio * block_ratio)
        stat['f_bfree']     = int(stat['f_bfree'] * size_ratio * block_ratio)
        stat['f_bavail']    = int(stat['f_bavail'] * size_ratio * block_ratio)
        return stat

    @debug_log
    def unlink(self, path):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        result = os.unlink(real_path)
        self.__enc_path_delete(path)
        return result

    @debug_log
    def symlink(self, name, target):
        real_name = self.real_path(name)
        real_target = target
        if real_name == self.conf_path: return None
        return os.symlink(target, real_name)

    @debug_log
    def rename(self, old, new):
        real_old = self.real_path(old)
        real_new = self.real_path(new)
        if real_old == self.conf_path: return None
        if real_new == self.conf_path: return None
        result = os.rename(real_old, real_new)
        if config.enc_path:
            self.__enc_path_rename(old, new)
        return result

    @debug_log
    def link(self, target, name):
        real_target = self.real_path(target)
        real_name = self.real_path(name)
        if real_target == self.conf_path: return None
        if real_name == self.conf_path: return None
        return os.link(real_name, real_target)

    @debug_log
    def utimens(self, path, times=None):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        return os.utime(real_path, times)

    # File methods
    # ============

    @debug_log
    def open(self, path, flags):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        return os.open(real_path, flags)

    @debug_log
    def create(self, path, mode, fi=None):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        return os.open(real_path, os.O_WRONLY | os.O_CREAT, mode)

    @debug_log
    def read(self, path, length, offset, fh):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None, False
        return self.io.read(real_path, length, offset)

    @debug_log
    def write(self, path, buf, offset, fh):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        return self.io.write(real_path, buf, offset)

    @debug_log
    def truncate(self, path, length, fh=None):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        return self.io.truncate(real_path, length)

    @debug_log
    def flush(self, path, fh):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        return os.fsync(fh)

    @debug_log
    def release(self, path, fh):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        return os.close(fh)

    @debug_log
    def fsync(self, path, fdatasync, fh):
        real_path = self.real_path(path)
        if real_path == self.conf_path: return None
        return self.flush(path, fh)


