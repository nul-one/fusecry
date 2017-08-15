"""
Fusecry FUSE operations.
"""

from datetime import datetime
from fuse import FuseOSError, Operations
from fusecry import cry
from fusecry.io import FusecryIO
import errno
import fusecry.config as config
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

class Fusecry(Operations):
    def __init__(self, root, password, ignore_ic=False, debug=False):
        self.root = root
        self.debug = debug
        self.io = FusecryIO(cry.Cry(password), ignore_ic)

    def __real_path(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    # Filesystem methods
    # ==================
    
    @debug_log
    def access(self, path, mode):
        if not os.access(self.__real_path(path), mode):
            raise FuseOSError(errno.EACCES)
    
    @debug_log
    def chmod(self, path, mode):
        return os.chmod(self.__real_path(path), mode)
    
    @debug_log
    def chown(self, path, uid, gid):
        return os.chown(self.__real_path(path), uid, gid)
    
    @debug_log
    def getattr(self, path, fh=None):
        return self.io.attr(self.__real_path(path))
    
    @debug_log
    def readdir(self, path, fh):
        real_path = self.__real_path(path)
        dirents = ['.', '..']
        if os.path.isdir(real_path):
            dirents.extend(os.listdir(real_path))
        for r in dirents:
            yield r
    
    @debug_log
    def readlink(self, path):
        real_path = self.__real_path(path)
        pathname = os.readlink(real_path)
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname
    
    @debug_log
    def mknod(self, path, mode, dev):
        real_path = self.__real_path(path)
        return os.mknod(self.real_path, mode, dev)
    
    @debug_log
    def rmdir(self, path):
        real_path = self.__real_path(path)
        return os.rmdir(real_path)
    
    @debug_log
    def mkdir(self, path, mode):
        real_path = self.__real_path(path)
        return os.mkdir(real_path, mode)
    
    @debug_log
    def statfs(self, path):
        real_path = self.__real_path(path)
        stv = os.statvfs(real_path)
        stat = dict((key, getattr(stv, key)) for key in (
            'f_bavail', 'f_bfree', 'f_blocks', 'f_bsize', 'f_favail',
            'f_ffree', 'f_files', 'f_flag', 'f_frsize', 'f_namemax'))
        chunk_size = config.enc.chunk_size
        block_ratio = chunk_size / stat['f_bsize']
        stat['f_bsize']     = chunk_size 
        stat['f_frsize']    = chunk_size
        stat['f_blocks']    = int(stat['f_blocks'] / block_ratio)
        stat['f_bfree']     = int(stat['f_bfree'] / block_ratio)
        stat['f_bavail']    = int(stat['f_bavail'] / block_ratio)
        return stat
    
    @debug_log
    def unlink(self, path):
        real_path = self.__real_path(path)
        return os.unlink(real_path)
    
    @debug_log
    def symlink(self, name, target):
        self.__real_path(path)
        return os.symlink(target, real_path)
    
    @debug_log
    def rename(self, old, new):
        return os.rename(self.__real_path(old), self.__real_path(new))
    
    @debug_log
    def link(self, target, name):
        return os.link(self.__real_path(name), self.__real_path(target))
    
    @debug_log
    def utimens(self, path, times=None):
        return os.utime(self.__real_path(path), times)

    # File methods
    # ============
    
    @debug_log
    def open(self, path, flags):
        return os.open(self.__real_path(path), flags)
    
    @debug_log
    def create(self, path, mode, fi=None):
        return os.open(self.__real_path(path), os.O_WRONLY | os.O_CREAT, mode)

    @debug_log
    def read(self, path, length, offset, fh):
        return self.io.read(self.__real_path(path), length, offset)

    @debug_log
    def write(self, path, buf, offset, fh):
        return self.io.write(self.__real_path(path), buf, offset)
    
    @debug_log
    def truncate(self, path, length, fh=None):
        return self.io.truncate(self.__real_path(path), length)
    
    @debug_log
    def flush(self, path, fh):
        return os.fsync(fh)
    
    @debug_log
    def release(self, path, fh):
        return os.close(fh)
    
    @debug_log
    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)


