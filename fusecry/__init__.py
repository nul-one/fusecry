"""
Encrypted filesystem and encryption tool based on FUSE and AES.
"""
import base64
import json
import os

__version__ = "0.11.2"
__licence__ = "BSD"
__year__ = "2017"
__author__ = "Predrag Mandic"
__author_email__ = "github@phlogisto.com"


class FuseCryException(Exception):
    """Generic FuseCry exception."""
    pass


class IntegrityCheckFail(FuseCryException):
    """Raised when data integity check fails during decryption."""
    pass


class FileSizeException(FuseCryException):
    """Raised when encrypted files are of undefined decrypted size."""
    pass


class BadConfException(FuseCryException):
    """Raised when FuseCry conf is not valid or not matching."""
    pass


class FuseCryConf(object):
    fusecry_conf_file_name = 'fusecry.conf'

    def __init__(self, d):
        self.__dict__ = d

    def __str__(self):
        info = { key: value for key, value in self.__dict__.items() \
                if key[0] is not "_" }
        s = ""
        for key, value in self.__dict__.items():
            if key[0] is not "_":
                s += key.replace("_", " ") + ": " + str(value) + "\n"
        return s

    @property
    def enc_key(self):
        return base64.b64decode(self.__enc_key.encode())

    @enc_key.setter
    def enc_key(self, enc_key):
        self.__enc_key = base64.b64encode(enc_key).decode()

    @property
    def kdf_salt(self):
        return base64.b64decode(self.__kdf_salt.encode())

    @kdf_salt.setter
    def kdf_salt(self, kdf_salt):
        self.__kdf_salt = base64.b64encode(kdf_salt).decode()

    @property
    def sample(self):
        return base64.b64decode(self.__sample.encode())

    @sample.setter
    def sample(self, sample):
        self.__sample = base64.b64encode(sample).decode()

    def save(self, path):
        with open(path, 'w+b') as f:
            f.write(json.dumps(self.__dict__).encode())

    def load(self, path):
        if os.path.isdir(path):
            path = os.path.join(path, self.fusecry_conf_file_name)
        if not os.path.isfile(path):
            self.type = None
            return self.type
        with open(path, 'rb') as f:
            self.__dict__ = json.loads(f.read().decode())
            comp_msg = "FuseCry version {} incompatible with conf version {}."
            if ((self.version.split('.')[0] == "0" and
                __version__.split('.')[:2] != self.version.split('.')[:2]) or
                __version__.split('.')[0] != self.version.split('.')[0]):
                raise BadConfException(comp_msg.format(
                    __version__, self.version))
            return self.type


config = FuseCryConf(
    {
        "version": __version__,
        "_kdf_iter_range": (60000,80000),
        "kdf_salt_size": 32,
        "extension": '.fcry',
        "_conf": FuseCryConf.fusecry_conf_file_name,
        "sample_size": 1024,
        "_default_chunk_size": 4096,
        "enc_path": False,
    }
)
"""Configuration options used throughout the package."""

