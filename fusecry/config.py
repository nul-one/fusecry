"""
FuseCry config.
"""

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from random import randint
import os
import struct

class Objectview(object):
    def __init__(self, d):
        self.__dict__ = d

enc = Objectview(
    {
        "hash_size": MD5.digest_size,
        "key_size": AES.key_size[2],
        "iv_size": 16,
        "kdf_iter_range": (60000,80000),
        "kdf_salt_size": 32,
        "aes_block": AES.block_size,
        "chunk_size": 256 * AES.block_size, # 256*16 = 4096 FS_B
        "extension": '.fcry',
        "conf": '.fusecry',
    }
)

def configure(conf):
    kdf_salt = None
    kdf_iters = None
    if os.path.isfile(conf):
        with open(conf, 'rb') as f:
            kdf_salt = f.read(enc.kdf_salt_size)
            kdf_iters = struct.unpack(
                '<Q', f.read(struct.calcsize('Q')))[0]
    else:
        kdf_salt = Random.get_random_bytes(enc.kdf_salt_size)
        kdf_iters = randint(*enc.kdf_iter_range)
        with open(conf, 'w+b') as f:
            f.write(kdf_salt)
            f.write(struct.pack('<Q', kdf_iters))
    return kdf_salt, kdf_iters

