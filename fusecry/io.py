"""
FuseCry IO functions.
"""

from fusecry import config, cry
import os
import struct


class FuseCryException(Exception):
    pass

class IntegrityCheckException(FuseCryException):
    pass

class FileSizeException(FuseCryException):
    pass

class BadConfException(FuseCryException):
    pass

meta_size = ( config.enc.key_size
            + 2 * config.enc.iv_size
            + config.enc.hash_size )

class ConfData(object):

    def save(self, path=None):
        if path: self.path = path
        print("-- generating new conf: {}".format(self.path))
        print("   chunk size: {}".format(self.chunk_size))
        print("   It's safe to be shared. Decryption won't work if lost.")
        if self.type == 'password':
            fmt = '< 8s I {}s I {}s'.format(
                config.enc.kdf_salt_size,
                self.chunk_size + meta_size,
                )
            with open(self.path, 'w+b') as f:
                f.write(struct.pack(
                    fmt,
                    self.type.encode(),
                    self.chunk_size,
                    self.kdf_salt,
                    self.kdf_iters,
                    self.enc_chunk,
                    ))
        elif self.type == 'rsakey':
            fmt = '< 8s I I {}s {}s'.format(
                self.rsa_key_size,
                self.chunk_size + meta_size,
                )
            with open(self.path, 'w+b') as f:
                f.write(struct.pack(
                    fmt,
                    self.type.encode(),
                    self.chunk_size,
                    self.rsa_key_size,
                    self.enc_aes,
                    self.enc_chunk,
                    ))

    def load(self, path=None):
        if path: self.path = path
        if not os.path.isfile(self.path):
            self.type = None
            return self.type
        path_data = b''
        with open(self.path, 'rb') as f:
            path_data = f.read()
        self.type, self.chunk_size = struct.unpack(
            '< 8s I', path_data[:struct.calcsize('< 8s I')])
        self.type = self.type.split(b'\0')[0].decode()
        if self.type == 'password':
            # type, chunk_size, kdf_salt, kdf_iters, enc_chunk
            fmt = '< 8s I {}s I {}s'.format(
                config.enc.kdf_salt_size,
                self.chunk_size + meta_size,
                )
            s = struct.Struct(fmt)
            _, self.chunk_size, self.kdf_salt, self.kdf_iters, self.enc_chunk=\
                s.unpack(path_data)
        elif self.type == 'rsakey':
            _, _, self.rsa_key_size = struct.unpack(
                '< 8s I I', path_data[:struct.calcsize('< 8s I I')])
            # type, chunk_size, rsa_key_size, enc_aes, enc_chunk
            fmt = '< 8s I I {}s {}s'.format(
                self.rsa_key_size,
                self.chunk_size + meta_size,
                )
            s = struct.Struct(fmt)
            _, self.chunk_size, _, self.enc_aes, self.enc_chunk =\
                s.unpack(path_data)
        return self.type


class FuseCryIO(object):
    def __init__(self, cry, chunk_size):
        self.cry = cry
        self.ms = meta_size
        self.ss = struct.calcsize('<Q')
        self.cs = chunk_size

    def check_ic_pass(self, path, check):
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
                print("FuseCry FSCK: checking {}/{} files. {}".format(
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


class PasswordFuseCryIO(FuseCryIO):
    def __init__(self, password, root, conf_path=None, chunk_size=None):
        conf_data = ConfData()
        crypto = None
        if conf_data.load(conf_path):
            if conf_data.type != 'password':
                raise BadConfException(
                    "Expected conf type: 'password', but found: '{}'".format(
                        conf_data.type))
            crypto, _, _, _ = cry.get_password_cry(
                password, conf_data.chunk_size, conf_data.kdf_salt,
                conf_data.kdf_iters
                )
            _, ic_pass = crypto.dec(conf_data.enc_chunk)
            self.check_ic_pass(conf_path, ic_pass)
        else:
            conf_data.chunk_size = chunk_size if chunk_size \
                else os.statvfs(root).f_bsize
            if conf_data.chunk_size % config.enc.default_chunk_size:
                raise BadConfException(
                    "Chunk size must be multiple of {}, but got {}.".format(
                        config.enc.default_chunk_size, conf_data.chunk_size))
            crypto, conf_data.kdf_salt, conf_data.kdf_iters, \
                conf_data.enc_chunk = cry.get_password_cry(
                    password, conf_data.chunk_size)
            conf_data.type = 'password'
            conf_data.save(conf_path)
        super().__init__(crypto, conf_data.chunk_size)


class RSAFuseCryIO(FuseCryIO):
    def __init__(self, key_path, root, conf_path=None, chunk_size=None):
        conf_data = ConfData()
        rsa_key = None
        crypto = None
        with open(key_path, 'rb') as f:
            rsa_key = f.read()
        if conf_data.load(conf_path):
            if conf_data.type != 'rsakey':
                raise BadConfException(
                    "Expected conf type: 'rsakey', but found: '{}'".format(
                        conf_data.type))
            try:
                crypto, _, _, _ = cry.get_rsa_cry(
                    rsa_key, conf_data.chunk_size, conf_data.enc_aes)
            except ValueError:
                raise BadConfException("RSA key did not match.")
            _, ic_pass = crypto.dec(conf_data.enc_chunk)
            self.check_ic_pass(conf_path, ic_pass)
        else:
            conf_data.chunk_size = chunk_size if chunk_size \
                else os.statvfs(root).f_bsize
            if conf_data.chunk_size % config.enc.default_chunk_size:
                raise BadConfException(
                    "Chunk size must be multiple of {}, but got {}.".format(
                        config.enc.default_chunk_size, conf_data.chunk_size))
            crypto, conf_data.rsa_key_size, conf_data.enc_aes, \
                conf_data.enc_chunk = cry.get_rsa_cry(
                    rsa_key, conf_data.chunk_size)
            conf_data.type = 'rsakey'
            conf_data.save(conf_path)
        super().__init__(crypto, conf_data.chunk_size)

