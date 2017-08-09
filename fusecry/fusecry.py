"""
Fusecry FUSE operations.
"""

from Crypto import Random
from Crypto.Cipher import AES 
from Crypto.Hash import SHA256, MD5 
from fuse import FuseOSError, Operations
from math import ceil, floor
import errno
import fusecry.config as config
import os
import struct
from datetime import datetime

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
    def __init__(self, root, password, debug=True):
        self.password = password
        self.root = root
        self.debug = debug
        self.chunk_size = config.encryption.chunk_blocks * AES.block_size
        self.key_size = config.encryption.key_size
        self.iv_size = config.encryption.iv_size
        self.meta_size = self.key_size + 2 * self.iv_size
        self.ratio = self.chunk_size / (self.chunk_size + self.meta_size)

    # Crypto and non-fuse helpers
    # ===========================

    def __encrypt_chunk(self, chunk):
        ks = self.key_size
        vs = self.iv_size
        if len(chunk) % AES.block_size != 0:
            chunk += bytes(AES.block_size - len(chunk) % AES.block_size)
        random_key = Random.get_random_bytes(ks)
        random_iv = Random.get_random_bytes(vs)
        random_encryptor = AES.new(random_key, AES.MODE_CBC, random_iv)
        secret_key = SHA256.new(bytes(str(self.password), 'utf-8')).digest()
        secret_iv = Random.get_random_bytes(vs)
        secret_encryptor = AES.new(secret_key, AES.MODE_CBC, secret_iv)
        encrypted_random_key = secret_encryptor.encrypt(random_key)
        encrypted_random_iv = secret_encryptor.encrypt(random_iv)
        return secret_iv \
            + encrypted_random_key \
            + encrypted_random_iv \
            + random_encryptor.encrypt(chunk)

    def __decrypt_chunk(self, enc_chunk):
        poz = 0
        ks = self.key_size
        vs = self.iv_size
        secret_iv = enc_chunk[poz:poz+vs]; poz+=vs
        encrypted_random_key = enc_chunk[poz:poz+ks]; poz+=ks
        encrypted_random_iv = enc_chunk[poz:poz+vs]; poz+=vs
        secret_key = SHA256.new(bytes(str(self.password), 'utf-8')).digest()
        secret_decryptor = AES.new(secret_key, AES.MODE_CBC, secret_iv)
        random_key = secret_decryptor.decrypt(encrypted_random_key)
        random_iv = secret_decryptor.decrypt(encrypted_random_iv)
        random_decryptor = AES.new(random_key, AES.MODE_CBC, random_iv)
        return random_decryptor.decrypt(
                enc_chunk[poz:]
            )

    def __read(self, path, length, offset):
        buf = b''
        real_path = self.__real_path(path)
        length = min(length, self.__get_filesize(path) - offset)
        if length <= 0:
            return buf
        cs = self.chunk_size
        ms = self.meta_size
        ncc = floor(offset / cs) # number of untouched chunks
        sb = offset % cs # skip bytes in first crypto chunk
        with open(real_path,'rb') as f:
            f.seek(ncc*(ms+cs))
            while len(buf) < (sb+length):
                data = f.read(ms+cs)
                data_len = len(data)-ms
                if data_len <= struct.calcsize('Q'):
                    break
                if data_len % AES.block_size:
                    data = data[:-(data_len%AES.block_size)]
                buf += self.__decrypt_chunk(data)
        return buf[sb:sb+length]
 
    def __get_filesize(self, path):
        with open(self.__real_path(path), 'rb') as f:
            file_end = f.seek(0,os.SEEK_END)
            size = 0
            if file_end:
                f.seek(file_end-struct.calcsize('Q'))
                size = struct.unpack('<Q', f.read(struct.calcsize('Q')))[0]
            return size
        
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
        real_path = self.__real_path(path)
        st = os.lstat(real_path)
        attr = dict((key, getattr(st, key)) for key in (
            'st_atime', 'st_ctime', 'st_gid', 'st_mode',
            'st_mtime', 'st_nlink', 'st_size', 'st_uid'))
        if os.path.isfile(real_path):
            if attr['st_size']:
                if os.access(real_path, os.R_OK):
                    attr['st_size'] = self.__get_filesize(path)
                else:
                    attr['st_size'] = \
                        int((attr['st_size']-struct.calcsize('Q'))*self.ratio)
        return attr
    
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
        block_ratio = self.chunk_size / stat['f_bsize']
        stat['f_bsize']     = self.chunk_size 
        stat['f_frsize']    = self.chunk_size
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
        #self._log('-- read {} {} {}'.format(path, length, offset))
        return self.__read(path, length, offset)

    @debug_log
    def write(self, path, buf, offset, fh):
        real_path = self.__real_path(path)
        cs = self.chunk_size
        ms = self.meta_size
        xbuf = b''
        old_crypto=b''
        ncc = floor(offset / cs) # number of untouched chunks
        if offset > self.__get_filesize(path):
            return 0
        if offset % cs:
            # Decrypt last block and prepend it to xbuf
            #xbuf = self.__read(path, offset%cs, ncc*cs) + buf
            with open(real_path,'rb') as f:
                f.seek(ncc*(ms+cs))
                data = f.read(ms+cs)
                data_len = len(data)-ms
                if data_len > struct.calcsize('Q'):
                    if data_len % AES.block_size:
                        data = data[:-(data_len%AES.block_size)]
                    xbuf = self.__decrypt_chunk(data)[:offset%cs] + buf
        else:
            # just right block size
            xbuf = buf
        with open(real_path,'r+b') as f:
            # Drop file data after crypto offset and add new data
            s = f.truncate(ncc*(ms+cs))
            f.seek(s)
            done_length = 0
            while done_length < len(xbuf):
                chunk = xbuf[done_length:cs]
                done_length += cs
                if not chunk:
                    break
                f.write(self.__encrypt_chunk(chunk))
            f.write(struct.pack('<Q', offset + len(buf)))
        return len(buf)
    
    @debug_log
    def truncate(self, path, length, fh=None):
        if length:
            cs = self.chunk_size
            ms = self.meta_size
            ncc = floor(length/cs) # number of untouched chunks
            data = self.__read(path, length%cs, ncc*cs)
            with open(self.__real_path(path), 'r+b') as f:
                s = f.truncate(ncc*(ms+cs))
                f.seek(s)
                f.write(self.__encrypt_chunk(data))
                #s = f.truncate(ncc*ms+length)
                #f.seek(s)
                f.write(struct.pack('<Q', length))
        else:
            with open(self.__real_path(path), 'r+b') as f:
                f.truncate(0)
    
    @debug_log
    def flush(self, path, fh):
        return os.fsync(fh)
    
    @debug_log
    def release(self, path, fh):
        return os.close(fh)
    
    @debug_log
    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)


