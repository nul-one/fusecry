"""
FuseCry IO functions.

Use `PasswordFuseCryIO` or `RSAFuseCryIO` (subclasses of `FuseCryIO`) to read
and write encrypted files.
Use `ConfData` to load and save FuseCry conf file.
"""
from fusecry import config, cry, BadConfException, FileSizeException
import logging
import os
import struct
import sys


class ConfData(object):
    """Used to load and save FuseCry conf file.

    FuseCry conf file contains data needed for encryption and decryption. Below
    is the structure of the conf file in case of password or RSA key encryption
    methods.

    Password encryption conf file::

        8 bytes::       string `password`
        4 bytes::       unsigned int chunk_size
        8 bytes::       string cipher (e.g. `AES_CBC`)
        8 bytes::       string hashmod (e.g. `SHA256`)
        32 bytes::      kdf_salt
        4 bytes::       unsigned int kdf_iters
        1024 bytes::    encrypted chunk sample

    RSA key encryption conf file::

        8 bytes::               string `rsakey`
        4 bytes::               unsigned int chunk_size
        8 bytes::               string cipher (e.g. `AES_CBC`)
        8 bytes::               string hashmod (e.g. `SHA256`)
        4 bytes::               unsigned int rsa_key_size
        rsa_key_size bytes::    RSA encrypted AES key
        1024 bytes::            encrypted chunk sample
    """

    def __str__(self):
        """Descriptive string representation of the object."""
        from textwrap import dedent
        from Crypto.Hash import MD5
        if self.type == 'password':
            md5 = MD5.new()
            md5.update(self.sample)
            sample_md5 = md5.digest()
            return dedent("""
                type       :{}
                chunk_size :{}
                cipher     :{}
                hashmod    :{}
                kdf_salt   :{}
                kdf_iters  :{}
                sample_md5 :{}
            """).format(
                self.type,
                self.chunk_size,
                self.cipher,
                self.hashmod,
                self.kdf_salt,
                self.kdf_iters,
                sample_md5,
                )
        elif self.type == 'rsakey':
            md5 = MD5.new()
            md5.update(self.sample)
            sample_md5 = md5.digest()
            return dedent("""
                type         :{}
                chunk_size   :{}
                cipher       :{}
                hashmod      :{}
                rsa_key_size :{}
                enc_key      :{}
                sample_md5   :{}
            """).format(
                self.type,
                self.chunk_size,
                self.cipher,
                self.hashmod,
                self.rsa_key_size,
                self.enc_key,
                sample_md5,
                )
        else:
            return "error ConfData to str."

    def _zstring(self, zbytes):
        return zbytes.split(b'\0')[0].decode()

    def save(self, path, info=False):
        """Save FuseCry conf to a file.

        Object needs to have the following attributes set based on encryption
        type prior to saving conf file.

        Password encryption conf file::
            (
                type (str): `password`,
                chunk_size (int): multiple of 16; best use your FS block size,
                cipher (str): `AES_CBC`,
                hashmod (str): `SHA256`,
                kdf_salt (bytes): 32 random bytes,
                kdf_iters (int): number of KDF iterations (best to be 60K+),
                sample (bytes): encrypt (1024 - Metasize) random bytes,
            )

        RSA key encryption conf file::
            (
                type (str): `rsakey`,
                chunk_size (int): multiple of 16; best use your FS block size,
                cipher (str): `AES_CBC`,
                hashmod (str): `SHA256`,
                rsa_key_size (int): byte size of your RSA key,
                enc_key (bytes): encrypt your AES key with RSA and store it,
                sample (bytes): encrypt (1024 - Metasize) random bytes,
            )

        Args:
            path (str): Output file path.
            info (:obj:`bool`, optional): Prints descriptive info about conf
                file if set to True. Defaults to False.
        """
        if path: self.path = path
        logging.info("Generated new conf: {}\n".format(self.path))
        sys.stderr.write("-- generating new conf: {}\n".format(self.path))
        sys.stderr.write(
            "   It's safe to be shared. Decryption wont work if lost.\n")
        if self.type == 'password':
            fmt = '< 8s I 8s 8s {}s I 1024s'.format(config.kdf_salt_size)
            with open(self.path, 'w+b') as f:
                f.write(struct.pack(
                    fmt,
                    self.type.encode(),
                    self.chunk_size,
                    self.cipher.encode(),
                    self.hashmod.encode(),
                    self.kdf_salt,
                    self.kdf_iters,
                    self.sample,
                    ))
        elif self.type == 'rsakey':
            fmt = '< 8s I 8s 8s I {}s 1024s'.format(self.rsa_key_size)
            with open(self.path, 'w+b') as f:
                f.write(struct.pack(
                    fmt,
                    self.type.encode(),
                    self.chunk_size,
                    self.cipher.encode(),
                    self.hashmod.encode(),
                    self.rsa_key_size,
                    self.enc_key,
                    self.sample,
                    ))
        if info: sys.stderr.write(str(self))

    def load(self, path, info=False):
        """Load FuseCry conf from a file.

        Loaded object will get the following attributes based on encryption
        type. Look at the `save` functiom for more detailed explanation of
        each of them.

        Password encryption conf file::
            (
                type,
                chunk_size,
                cipher,
                hashmod,
                kdf_salt,
                kdf_iters,
                sample,
            )

        RSA key encryption conf file::
            (
                type,
                chunk_size,
                cipher,
                hashmod,
                rsa_key_size,
                enc_key,
                sample,
            )

        Args:
            path (str): Input file path.
            info (:obj:`bool`, optional): Prints descriptive info about conf
                file if set to True. Defaults to False.

        Returns:
            str: `password` or `rsakey` based on encryption tipe found.
        """
        if path: self.path = path
        if not os.path.isfile(self.path):
            self.type = None
            return self.type
        path_data = b''
        with open(self.path, 'rb') as f:
            path_data = f.read()
        self.type, self.chunk_size = struct.unpack(
            '< 8s I', path_data[:struct.calcsize('< 8s I')])
        self.type = self._zstring(self.type)
        if self.type == 'password':
            # type, chunk_size, cipher, hashmod, kdf_salt, kdf_iters, sample
            fmt = '< 8s I 8s 8s {}s I 1024s'.format(config.kdf_salt_size)
            s = struct.Struct(fmt)
            _, self.chunk_size, self.cipher, self.hashmod, self.kdf_salt, \
                self.kdf_iters, self.sample = s.unpack(path_data)
            self.cipher = self._zstring(self.cipher)
            self.hashmod = self._zstring(self.hashmod)
        elif self.type == 'rsakey':
            _, _, _, _, self.rsa_key_size = struct.unpack(
                '< 8s I 8s 8s I',path_data[:struct.calcsize('< 8s I 8s 8s I')])
            # type, chunk_size, cipher, hashmod, rsa_key_size, enc_key, sample
            fmt = '< 8s I 8s 8s I {}s 1024s'.format(self.rsa_key_size)
            s = struct.Struct(fmt)
            _, self.chunk_size, self.cipher, self.hashmod, _, self.enc_key, \
                self.sample = s.unpack(path_data)
            self.cipher = self._zstring(self.cipher)
            self.hashmod = self._zstring(self.hashmod)
        if info: sys.stderr.write(str(self))
        return self.type


class FuseCryIO(object):
    """Object used for transparent raw-data IO on FuseCry encrypted files.

    Simply call `read` and `write` methods to manipulate data in encrypted
    files. Data will always remain encrypted in the files but you will be
    accessing using raw data.

    Attributes:
        cry (Cry): FuseCry encryption class object.
        ms (int): Meta-size (total size of AES IV and HMAC hash) of a block.
        ss (int): Struct size - size of struct object bytes at the end of files
            containing information about total file size. We use this instead
            of byte padding on blocks.
        cs (int): Chunk size - size of raw data block.
        ecs (int): Encrypted chunk size - size of encrypted block (encrypted
            data size plus meta-size).
    """

    def __init__(self, cry, chunk_size):
        """Constructor.

        Args:
            cry (Cry): FuseCry encryption class object.
            chunk_size (int): Set size of every raw data block.
        """
        self.cry = cry
        self.ms = self.cry.ms
        self.ss = struct.calcsize('<Q')
        self.cs = chunk_size
        self.ecs = self.ms + self.cs

    def read(self, path, length, offset):
        """Read bytes from file.

        Args:
            path (str): File path.
            length (int): Number of bytes to read.
            offset (int): Start reading after offset bytes.

        Returns:
            bytes: File contents.
        """
        buf = b''
        size = self.filesize(path)
        rlen = min(length, size - offset)
        if rlen <= 0:
            return buf
        uc = int(offset / self.cs) # number of untouched chunks
        sb = offset % self.cs # skip bytes in first crypto chunk
        max_buf_len = sb+rlen
        with open(path,'rb') as f:
            f.seek(uc * self.ecs)
            while len(buf) < max_buf_len:
                cdata = f.read(self.ecs)
                if len(cdata) % self.cry.vs:
                    cdata = cdata[:-(len(cdata) % self.cry.vs)]
                if not len(cdata):
                    break
                dec = self.cry.dec(cdata)
                buf += dec
        return buf[sb:sb+rlen]

    def write(self, path, buf, offset):
        """Write bytes to file.

        Args:
            path (str): File path.
            buf (bytes): Bytes to write.
            offset (int): Start writing after offset bytes.

        Returns:
            int: Number of bytes successfully written.
        """
        xbuf = buf
        current_size = self.filesize(path)
        uc = int(offset / self.cs) # number of chunks before first modified
        lmc = int((offset + len(buf)) / self.cs) # last modified chunk
        if offset > current_size:
            return 0
        if offset % self.cs:
            dec = self.read(path, offset % self.cs, uc * self.cs)
            xbuf = dec + xbuf
        if (offset + len(buf)) % self.cs:
            dec = self.read(
                path,
                self.cs - ((offset+len(buf)) % self.cs),
                offset+len(buf)
                )
            xbuf = xbuf + dec
        done_length = 0
        with open(path,'r+b') as f:
            f.seek(uc * self.ecs)
            while done_length < len(xbuf):
                chunk = xbuf[done_length:done_length+self.cs]
                if not len(chunk):
                    break
                f.write(self.cry.enc(chunk))
                done_length += len(chunk)
            new_size = offset + len(buf)
            if new_size > current_size:
                f.write(struct.pack('<Q', new_size))
        return done_length

    def truncate(self, path, length):
        """Truncate file.

        Args:
            path (str): File path.
            length (int): New file size.
        """
        if length:
            uc = int(length/self.cs) # number of untouched chunks
            data = self.read(path, length%self.cs, uc*self.cs)
            with open(path, 'r+b') as f:
                s = f.truncate(uc * self.ecs)
                f.seek(s)
                f.write(self.cry.enc(data))
                f.write(struct.pack('<Q', length))
        else:
            with open(path, 'r+b') as f:
                f.truncate(0)

    def filesize(self, path):
        """Return file size.

        Args:
            path (str): File path.

        Returns:
            int: Length of raw data in the file.

        Raises:
            FileSizeException: When size could not be read from file or if it
                looks corrupted.
        """
        def calc_max_size(st_size):
            size = st_size - self.ss
            if size < 0:
                return 0
            max_size = int(size / self.ecs) * self.cs
            last_chunk = size % self.ecs - self.ms
            if last_chunk > 0:
                max_size += last_chunk
            return max_size
        def raise_exception(path, size, st_size):
            raise FileSizeException(
                "file: '{}' size: {} st_size: {}".format(path, size, st_size))
        st_size = os.stat(path).st_size
        max_size = calc_max_size(st_size)
        min_size = max_size - self.cry.vs + 1
        with open(path, 'rb') as f:
            file_end = f.seek(0,os.SEEK_END)
            size = 0
            if file_end:
                f.seek(file_end-self.ss)
                try:
                    size = struct.unpack('<Q', f.read(self.ss))[0]
                except struct.error as e:
                    raise_exception(path, size, st_size)
            if size < min_size or size > max_size:
                raise_exception(path, size, st_size)
            return size

    def attr(self, path):
        """Get file or directory attributes.

        Args:
            path (str): File path.

        Returns:
            dict: Containing these attributes:: st_atime, st_ctime, st_gid,
                st_mode, st_mtime, st_nlink, st_size, st_uid.
        """
        st = os.lstat(path)
        attr = dict((key, getattr(st, key)) for key in (
            'st_atime', 'st_ctime', 'st_gid', 'st_mode',
            'st_mtime', 'st_nlink', 'st_size', 'st_uid'))
        if os.path.isfile(path):
            if attr['st_size']:
                if os.access(path, os.R_OK):
                    attr['st_size'] = self.filesize(path)
                else:
                    ratio = self.cs / self.ecs
                    attr['st_size'] = int((attr['st_size']-self.ss)*ratio)
        return attr

    def touch(self, path, mode=0o644, dir_fd=None, **kwargs):
        """Create an empty file with selected permissions.

        Args:
            path (str): File path.
            mode (:obj:`int`, optional): File access mode. Defaults to 0o644.
            dir_fd (optional): If set, it should be a file descriptor open to a
                directory and path should then be relative to that directory.
                Defaults to None.
            **kwargs: Arbitrary keyword arguments.
        """
        flags = os.O_CREAT | os.O_APPEND
        with os.fdopen(
                os.open(path, flags=flags, mode=mode, dir_fd=dir_fd) ) as f:
            os.utime(
                f.fileno() if os.utime in os.supports_fd else path,
                dir_fd=None if os.supports_fd else dir_fd,
                **kwargs )

    def fsck_file(self, path):
        """Read whole file and return first error string or None.

        Args:
            path (str): File path.

        Returns:
            str: Error string of first encountered error while reading.
            None: If no errors were encountered.
        """
        size = 0
        try:
            size = self.filesize(path)
            offset = 0
            while offset < size:
                self.read(path, self.cs, offset)
                offset += self.cs
        except:
            return "{}: {}".format(type(e), e)
        return None

    def fsck(self, path):
        """Read all files in directory recursively and print any errors.

        Args:
            path (str): Dir path.

        Returns:
            int: Number of files that produced at least one read error.
        """
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
                        os.path.join(path, config.conf):
                    error = self.fsck_file(os.path.join(r, file_name))
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
    """FuseCryIO subclass, specialized for password encryption."""

    def __init__(self, password, root, conf_path, chunk_size=None):
        """Constructor.

        Args:
            password (str): User password.
            root (str): Path of root dir of encrypted file system.
            conf_path (str): Path of FuseCry conf file.
            chunk_size (:obj:`int`, optional): Set chunk size. Defaults to
                file system chunk size of root directory or whatever is set in
                existing conf_path.
        """
        conf_data = ConfData()
        crypto = None
        if conf_data.load(conf_path):
            if conf_data.type != 'password':
                raise BadConfException(
                    "Expected conf type: 'password', but found: '{}'".format(
                        conf_data.type))
            crypto, _, _ = cry.get_password_cry(
                password,
                conf_data.kdf_salt,
                conf_data.kdf_iters
                )
            _ = crypto.dec(conf_data.sample)
        else:
            conf_data.chunk_size = chunk_size if chunk_size \
                else os.statvfs(root).f_bsize
            crypto, conf_data.kdf_salt, conf_data.kdf_iters \
                = cry.get_password_cry(password)
            conf_data.sample = crypto.enc(
                os.urandom(config.sample_size - crypto.ms))
            conf_data.type = 'password'
            conf_data.cipher = 'AES_CBC'
            conf_data.hashmod = 'SHA256'
            conf_data.save(conf_path)
        super().__init__(crypto, conf_data.chunk_size)


class RSAFuseCryIO(FuseCryIO):
    """FuseCryIO subclass, specialized for RSA key encryption."""

    def __init__(self, key_path, root, conf_path, chunk_size=None):
        """Constructor.

        Args:
            key_path (str): Path to public or private RSA key. If public key is
                used, only encryption operations will be available.
            root (str): Path of root dir of encrypted file system.
            conf_path (str): Path of FuseCry conf file.
            chunk_size (:obj:`int`, optional): Set chunk size. Defaults to
                file system chunk size of root directory or whatever is set in
                existing conf_path.
        """
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
                crypto, _, _ = cry.get_rsa_cry(rsa_key, conf_data.enc_key)
            except ValueError:
                raise BadConfException("RSA key did not match.")
            _ = crypto.dec(conf_data.sample)
        else:
            conf_data.chunk_size = chunk_size if chunk_size \
                else os.statvfs(root).f_bsize
            crypto, conf_data.rsa_key_size, conf_data.enc_key \
                = cry.get_rsa_cry(rsa_key)
            conf_data.sample = crypto.enc(
                os.urandom(config.sample_size - crypto.ms))
            conf_data.type = 'rsakey'
            conf_data.cipher = 'AES_CBC'
            conf_data.hashmod = 'SHA256'
            conf_data.save(conf_path)
        super().__init__(crypto, conf_data.chunk_size)

