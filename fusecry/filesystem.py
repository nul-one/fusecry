"""
FuseCry FUSE operations.
"""

from datetime import datetime
from fuse import FuseOSError, Operations
from fusecry import config
import errno
import os


def debug_log(func):
    def function_wrapper(*args, **kwargs):
        if args[0].debug:
            arguments = locals()
            print('{:.6f} -- {} {}'.format(
                datetime.timestamp(datetime.now()),
                func.__name__,
                [ x for x in args
                    if type(x) not in (bytes,object) ][1:]
                ))
        return func(*args, **kwargs)
    return function_wrapper

class FuseCry(Operations):
    def __init__(self, root, io, debug=False):
        self.root = root
        self.debug = debug
        self.conf = os.path.join(self.root, config.enc.conf)
        self.io = io

    def __real_path(self, path):
        if path.startswith(os.path.sep):
            path = path[len(os.path.sep):]
        return os.path.join(self.root, path)

    # Filesystem methods
    # ==================
    
    @debug_log
    def access(self, path, mode):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        if not os.access(real_path, mode):
            raise FuseOSError(errno.EACCES)
    
    @debug_log
    def chmod(self, path, mode):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        return os.chmod(real_path, mode)
    
    @debug_log
    def chown(self, path, uid, gid):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        return os.chown(real_path, uid, gid)
    
    @debug_log
    def getattr(self, path, fh=None):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        return self.io.attr(real_path)
    
    @debug_log
    def readdir(self, path, fh):
        real_path = self.__real_path(path)
        dirents = ['.', '..']
        if os.path.isdir(real_path):
            dirents.extend(os.listdir(real_path))
            if os.path.abspath(real_path) == os.path.abspath(self.root):
                if config.enc.conf in dirents:
                    dirents.remove(config.enc.conf)
        for r in dirents:
            yield r
    
    @debug_log
    def readlink(self, path):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        pathname = os.readlink(real_path)
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname
    
    @debug_log
    def mknod(self, path, mode, dev):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        return os.mknod(self.real_path, mode, dev)
    
    @debug_log
    def rmdir(self, path):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        return os.rmdir(real_path)
    
    @debug_log
    def mkdir(self, path, mode):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        return os.mkdir(real_path, mode)
    
    @debug_log
    def statfs(self, path):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        stv = os.statvfs(real_path)
        stat = dict((key, getattr(stv, key)) for key in (
            'f_bavail', 'f_bfree', 'f_blocks', 'f_bsize', 'f_favail',
            'f_ffree', 'f_files', 'f_flag', 'f_frsize', 'f_namemax'))
        chunk_size = self.io.cs
        block_ratio = self.io.cs / (self.io.cs + self.io.ms)
        stat['f_bsize']     = chunk_size 
        stat['f_frsize']    = chunk_size
        stat['f_blocks']    = int(stat['f_blocks'] * block_ratio)
        stat['f_bfree']     = int(stat['f_bfree'] * block_ratio)
        stat['f_bavail']    = int(stat['f_bavail'] * block_ratio)
        return stat
    
    @debug_log
    def unlink(self, path):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        return os.unlink(real_path)
    
    @debug_log
    def symlink(self, name, target):
        real_name = self.__real_path(name)
        real_target = self.__real_path(target)
        if real_name == self.conf: return None
        if real_target == self.conf: return None
        return os.symlink(real_target, real_name)
    
    @debug_log
    def rename(self, old, new):
        real_old = self.__real_path(old)
        real_new = self.__real_path(new)
        if real_old == self.conf: return None
        if real_new == self.conf: return None
        return os.rename(real_old, real_new)
    
    @debug_log
    def link(self, target, name):
        real_target = self.__real_path(target)
        real_name = self.__real_path(name)
        if real_target == self.conf: return None
        if real_name == self.conf: return None
        return os.link(real_name, real_target)
    
    @debug_log
    def utimens(self, path, times=None):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        return os.utime(real_path, times)

    # File methods
    # ============
    
    @debug_log
    def open(self, path, flags):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        return os.open(real_path, flags)
    
    @debug_log
    def create(self, path, mode, fi=None):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        return os.open(real_path, os.O_WRONLY | os.O_CREAT, mode)

    @debug_log
    def read(self, path, length, offset, fh):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None, False
        return self.io.read(real_path, length, offset)

    @debug_log
    def write(self, path, buf, offset, fh):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        return self.io.write(real_path, buf, offset)
    
    @debug_log
    def truncate(self, path, length, fh=None):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        return self.io.truncate(real_path, length)
    
    @debug_log
    def flush(self, path, fh):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        return os.fsync(fh)
    
    @debug_log
    def release(self, path, fh):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        return os.close(fh)
    
    @debug_log
    def fsync(self, path, fdatasync, fh):
        real_path = self.__real_path(path)
        if real_path == self.conf: return None
        return self.flush(path, fh)


