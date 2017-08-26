"""
FuseCry encryption functions.
"""

from Crypto.Cipher import AES 
from Crypto.Hash import MD5 
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from fusecry import config
from random import randint
import os


def get_password_cry(password, chunk_size, kdf_salt=None, kdf_iters=None):
    key_size = AES.key_size[2]
    kdf_salt = kdf_salt or os.urandom(config.kdf_salt_size)
    kdf_iters = kdf_iters or randint(*config.kdf_iter_range)
    aes_key = PBKDF2(str(password), kdf_salt, key_size, kdf_iters)
    crypto = Cry(aes_key)
    sample = crypto.enc(os.urandom(config.sample_size-crypto.ms))
    return crypto, kdf_salt, kdf_iters, sample

def get_rsa_cry(rsa_key, chunk_size, enc_aes=None):
    key_size = AES.key_size[2]
    rsa = RSA.importKey(rsa_key)
    rsa_size = int((rsa.size()+1)/8)
    aes_key = None
    if enc_aes:
        aes_key = rsa.decrypt(enc_aes)
        aes_key = b'\x00' * (AES.block_size - len(aes_key)) + aes_key
    else:
        aes_key = os.urandom(key_size)
        enc_aes = rsa.encrypt(aes_key, 'K')[0]
        enc_aes = b'\x00' * (rsa_size - len(enc_aes)) + enc_aes
    crypto = Cry(aes_key)
    sample = crypto.enc(os.urandom(config.sample_size-crypto.ms))
    return Cry(aes_key), rsa_size, enc_aes, sample


class Cry(object):
    def __init__(self, aes_key):
        self.ks = len(aes_key)
        self.vs = AES.block_size
        self.hs = MD5.digest_size
        self.aes_key = aes_key
        self.ms = self.vs + MD5.digest_size

    def enc(self, chunk):
        checksum = MD5.new()
        if not chunk:
            return bytes(0)
        chunk += bytes((AES.block_size - len(chunk)) % AES.block_size)
        checksum.update(chunk)
        iv = os.urandom(self.vs)
        aes = AES.new(self.aes_key, AES.MODE_CBC, iv)
        return iv + aes.encrypt(checksum.digest() + chunk)

    def dec(self, enc_chunk):
        if not enc_chunk:
            return b'', False
        iv = enc_chunk[:self.vs]
        aes = AES.new(self.aes_key, AES.MODE_CBC, iv)
        chunk = aes.decrypt(enc_chunk[self.vs:])
        checksum = MD5.new()
        checksum.update(chunk[MD5.digest_size:])
        old_checksum = chunk[:MD5.digest_size]
        return chunk[MD5.digest_size:], old_checksum == checksum.digest()

