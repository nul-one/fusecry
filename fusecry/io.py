"""
Fusecry IO functions.
"""

from Crypto import Random
from fusecry import config, cry
from random import randint
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
        self.ms = ( config.enc.key_size
                    + 2 * config.enc.iv_size
                    + config.enc.hash_size )
        self.ss = struct.calcsize('Q')

    def check_ic_pass(self, path, check):
        if not self.ignore_ic:
            if not check:
                raise IntegrityCheckException("file: '{}'".format(path))

    def read(self, path, length, offset):
        buf = b''
        size, _ = self.filesize(path)
        st_size = os.stat(path).st_size
        rlen = min(length, size - offset)
        if rlen <= 0:
            return buf
        ncc = int(offset / self.cs) # number of untouched chunks
        sb = offset % self.cs # skip bytes in first crypto chunk
        with open(path,'rb') as f:
            f.seek(ncc*(self.ms+self.cs))
            while len(buf) < (sb+rlen) and f.tell() < st_size - self.ss:
                cdata = f.read(self.ms+self.cs)
                cdata_len = len(cdata)-self.ms
                if cdata_len % config.enc.aes_block:
                    cdata = cdata[:-(cdata_len % config.enc.aes_block)]
                dec, ic_pass = self.cry.dec(cdata)
                self.check_ic_pass(path, ic_pass)
                buf += dec
        return buf[sb:sb+rlen]
        
    def write(self, path, buf, offset):
        xbuf = b''
        ncc = int(offset / self.cs) # number of untouched chunks
        if offset > self.filesize(path)[0]:
            return 0
        if offset % self.cs:
            dec = self.read(path, offset % self.cs, ncc * self.cs)
            xbuf = dec + buf
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
                done_length += len(chunk)
                if not len(chunk):
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
        def calc_max_size(st_size):
            size = st_size - self.ss
            if size < 0:
                return 0
            max_size = int(size/(self.ms+self.cs))*self.cs
            last_chunk = size%(self.ms+self.cs) - self.ms
            if last_chunk > 0:
                max_size += last_chunk
            return max_size
        def create_exception(path, size, st_size):
            return FileSizeException(
                "file: '{}' size: {} st_size: {}".format(
                    path, size, st_size))
        st_size = os.stat(path).st_size
        max_size = calc_max_size(st_size)
        min_size = max_size - config.enc.aes_block + 1
        exception = None
        with open(path, 'rb') as f:
            file_end = f.seek(0,os.SEEK_END)
            size = 0
            if file_end:
                f.seek(file_end-self.ss)
                try:
                    size = struct.unpack('<Q', f.read(self.ss))[0]
                except struct.error as e:
                    exception = create_exception(path, size, st_size)
                    size = -1
            if size < min_size or size > max_size:
                exception = create_exception(path, size, st_size)
                size = min_size
            return size, exception
    
    def attr(self, path):
        st = os.lstat(path)
        attr = dict((key, getattr(st, key)) for key in (
            'st_atime', 'st_ctime', 'st_gid', 'st_mode',
            'st_mtime', 'st_nlink', 'st_size', 'st_uid'))
        if os.path.isfile(path):
            if attr['st_size']:
                if os.access(path, os.R_OK):
                    attr['st_size'], _ = self.filesize(path)
                else:
                    ratio = self.cs / (self.ms+self.cs)
                    attr['st_size'] = int((attr['st_size']-self.ss)*ratio)
        return attr
    
    def touch(self, path, mode=0o644, dir_fd=None, **kwargs):
        flags = os.O_CREAT | os.O_APPEND
        with os.fdopen(
                os.open(path, flags=flags, mode=mode, dir_fd=dir_fd) ) as f:
            os.utime(
                f.fileno() if os.utime in os.supports_fd else path,
                dir_fd=None if os.supports_fd else dir_fd,
                **kwargs )

    def fsck_file(self, path):
        size = 0
        size, exception = self.filesize(path)
        if exception:
            return "{}: {}".format(type(exception), exception)
        if not self.ignore_ic:
            try:
                offset = 0
                while offset < size:
                    self.read(path, self.cs, offset)
                    offset += self.cs
            except:
                return "{}: {}".format(type(e), e)
        return None

    def fsck(self, path):
        errors = []
        total_files = sum([ len(f) for r,d,f in os.walk(path) ])
        files_checked = 0
        for r,d,f in os.walk(path):
            for file_name in f:
                files_checked += 1
                print("Fusecry FSCK: checking {}/{} files. {}".format(
                    files_checked,
                    total_files,
                    ( "Errors so far: " + str(len(errors))
                        if len(errors) else "No errors so far." ),
                    ))
                if os.path.join(r,file_name) !=\
                        os.path.join(path,config.enc.conf):
                    error = self.fsck_file(os.path.join(r,file_name))
                    if error:
                        errors.append(error)
        if len(errors):
            print("\nFSCK completed with errors:\n")
            for error in errors:
                print(error)
        else:
            print("\nFSCK complete. No errors detected.\n")
        return bool(len(errors))


class PasswordFusecryIO(FusecryIO):
    def __init__(self, password, conf_path=None, ignore_ic=False):
        salt_size = config.enc.kdf_salt_size
        kdf_salt = None
        kdf_iters = None
        if os.path.isfile(conf_path):
            with open(conf_path, 'rb') as f:
                kdf_salt = f.read(config.enc.kdf_salt_size)
                kdf_iters = struct.unpack('<Q', f.read(self.ss))[0]
        else:
            kdf_salt = Random.get_random_bytes(config.enc.kdf_salt_size)
            kdf_iters = randint(*config.enc.kdf_iter_range)
            with open(conf_path, 'w+b') as f:
                print("Generating new conf: {}".format(conf_path))
                print("It's safe to be shared. Decryption won't work if lost.")
                f.write(kdf_salt)
                f.write(struct.pack('<Q', kdf_iters))
        crypto = cry.PasswordCrypto(password, kdf_salt, kdf_iters)
        super().__init__(crypto, ignore_ic)


class RSAFusecryIO(FusecryIO):
    def __init__(self, key_path, conf_path=None, ignore_ic=False):
        crypto = None
        rsa_key = None
        with open(key_path, 'rb') as f:
            rsa_key = f.read()
        if os.path.isfile(conf_path):
            with open(conf_path, 'rb') as f:
                enc_aes = f.read()
                crypto, _ = cry.get_rsa_cry(rsa_key, enc_aes)
        else:
            crypto, enc_aes = cry.get_rsa_cry(rsa_key)
            self.touch(conf_path)
            with open(conf_path, 'w+b') as f:
                print("Generating new conf: {}".format(conf_path))
                print("It's safe to be shared. Decryption won't work if lost.")
                f.write(enc_aes)
        super().__init__(crypto, ignore_ic)

