"""
Fusecry IO functions.
"""

import fusecry.config as config
import os
import struct

class FusecryException(Exception):
    pass

class IntegrityCheckException(FusecryException):
    pass

class FileSizeException(FusecryException):
    pass

class FusecryIO(object):

    def __init__(self, cry, ignore_ic=False):
        self.cry = cry
        self.ignore_ic = ignore_ic
        self.cs = config.enc.chunk_size
        self.ms = config.enc.key_size+2*config.enc.iv_size+config.enc.hash_size

    def check_ic_pass(self, path, check):
        if not self.ignore_ic:
            if not check:
                raise IntegrityCheckException("file: '{}'".format(path))

    def read(self, path, length, offset):
        buf = b''
        length = min(length, self.filesize(path) - offset)
        if length <= 0:
            return buf
        ncc = int(offset / self.cs) # number of untouched chunks
        sb = offset % self.cs # skip bytes in first crypto chunk
        with open(path,'rb') as f:
            f.seek(ncc*(self.ms+self.cs))
            while len(buf) < (sb+length):
                data = f.read(self.ms+self.cs)
                data_len = len(data)-self.ms
                if data_len <= struct.calcsize('Q'):
                    break
                if data_len % config.enc.aes_block:
                    data = data[:-(data_len%config.enc.aes_block)]
                dec, ic_pass = self.cry.dec(data)
                self.check_ic_pass(path, ic_pass)
                buf += dec
        return buf[sb:sb+length]
        
    def write(self, path, buf, offset):
        xbuf = b''
        old_crypto=b''
        ncc = int(offset / self.cs) # number of untouched chunks
        if offset > self.filesize(path):
            return 0
        if offset % self.cs:
            # Decrypt last block and prepend it to xbuf
            with open(path,'rb') as f:
                f.seek(ncc*(self.ms+self.cs))
                data = f.read(self.ms+self.cs)
                data_len = len(data)-self.ms
                if data_len > struct.calcsize('Q'):
                    if data_len % config.enc.aes_block:
                        data = data[:-(data_len%config.enc.aes_block)]
                    dec, ic_pass = self.cry.dec(data)
                    self.check_ic_pass(path, ic_pass)
                    xbuf = dec[:offset%self.cs] + buf
        else:
            # just right block size
            xbuf = buf
        with open(path,'r+b') as f:
            # Drop file data after crypto offset and add new data
            s = f.truncate(ncc*(self.ms+self.cs))
            f.seek(s)
            done_length = 0
            while done_length < len(xbuf):
                chunk = xbuf[done_length:self.cs]
                done_length += self.cs
                if not chunk:
                    break
                f.write(self.cry.enc(chunk))
            f.write(struct.pack('<Q', offset + len(buf)))
        return len(buf)
        
    def truncate(self, path, length):
        if length:
            ncc = int(length/self.cs) # number of untouched chunks
            data = self.read(path, length%self.cs, ncc*self.cs)
            with open(path, 'r+b') as f:
                s = f.truncate(ncc*(self.ms+self.cs))
                f.seek(s)
                f.write(self.cry.enc(data))
                f.write(struct.pack('<Q', length))
        else:
            with open(path, 'r+b') as f:
                f.truncate(0)
    
    def filesize(self, path):
        with open(path, 'rb') as f:
            file_end = f.seek(0,os.SEEK_END)
            size = 0
            if file_end:
                f.seek(file_end-struct.calcsize('Q'))
                size = struct.unpack('<Q', f.read(struct.calcsize('Q')))[0]
            if size < 0 or size > os.stat(path).st_size:
                raise FileSizeException("file: '{}'".format(path))
            return size
    
    def attr(self, path):
        st = os.lstat(path)
        attr = dict((key, getattr(st, key)) for key in (
            'st_atime', 'st_ctime', 'st_gid', 'st_mode',
            'st_mtime', 'st_nlink', 'st_size', 'st_uid'))
        if os.path.isfile(path):
            if attr['st_size']:
                if os.access(path, os.R_OK):
                    attr['st_size'] = self.filesize(path)
                else:
                    ratio = self.cs / (self.ms+self.cs)
                    attr['st_size'] = \
                        int((attr['st_size']-struct.calcsize('Q'))*ratio)
        return attr
    
    def touch(self, fname, mode=0o644, dir_fd=None, **kwargs):
        flags = os.O_CREAT | os.O_APPEND
        with os.fdopen(os.open(fname, flags=flags, mode=mode, dir_fd=dir_fd)) as f:
            os.utime(f.fileno() if os.utime in os.supports_fd else fname,
                dir_fd=None if os.supports_fd else dir_fd, **kwargs)

