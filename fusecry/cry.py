"""
FuseCry encryption functions.
"""

from Crypto.Cipher import AES 
from Crypto.Hash import MD5 
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from random import randint
import fusecry.config as config
import os


def get_password_cry(password, chunk_size, kdf_salt=None, kdf_iters=None):
    kdf_salt = kdf_salt or os.urandom(config.enc.kdf_salt_size)
    kdf_iters = kdf_iters or randint(*config.enc.kdf_iter_range)
    aes_key = PBKDF2(str(password), kdf_salt, config.enc.key_size, kdf_iters)
    crypto = Cry(aes_key)
    enc_chunk = crypto.enc(os.urandom(chunk_size))
    return crypto, kdf_salt, kdf_iters, enc_chunk

def get_rsa_cry(rsa_key, chunk_size, enc_aes=None):
    rsa = RSA.importKey(rsa_key)
    rsa_size = int((rsa.size()+1)/8)
    aes_key = None
    if enc_aes:
        aes_key = rsa.decrypt(enc_aes)
        aes_key = b'\x00' * (AES.block_size - len(aes_key)) + aes_key
    else:
        aes_key = os.urandom(config.enc.key_size)
        enc_aes = rsa.encrypt(aes_key, 'K')[0]
        enc_aes = b'\x00' * (rsa_size - len(enc_aes)) + enc_aes
    crypto = Cry(aes_key)
    enc_chunk = crypto.enc(os.urandom(chunk_size))
    return Cry(aes_key), rsa_size, enc_aes, enc_chunk


class Cry(object):
    def __init__(self, aes_key):
        self.ks = config.enc.key_size
        self.vs = config.enc.iv_size
        self.aes_key = aes_key

    def enc(self, chunk):
        checksum = MD5.new()
        if not chunk:
            return b''
        if len(chunk) % AES.block_size != 0:
            chunk += bytes(AES.block_size - len(chunk) % AES.block_size)
        checksum.update(chunk)
        chunk = checksum.digest() + chunk
        random_key = os.urandom(self.ks)
        random_iv = os.urandom(self.vs)
        random_encryptor = AES.new(random_key, AES.MODE_CBC, random_iv)
        secret_iv = os.urandom(self.vs)
        secret_key = self.aes_key
        secret_encryptor = AES.new(secret_key, AES.MODE_CBC, secret_iv)
        encrypted_random_key = secret_encryptor.encrypt(random_key)
        encrypted_random_iv = secret_encryptor.encrypt(random_iv)
        return secret_iv \
            + encrypted_random_key \
            + encrypted_random_iv \
            + random_encryptor.encrypt(chunk)

    def dec(self, enc_chunk):
        poz = 0
        if not enc_chunk:
            return b'', False
        secret_iv = enc_chunk[poz:poz+self.vs]; poz+=self.vs
        encrypted_random_key = enc_chunk[poz:poz+self.ks]; poz+=self.ks
        encrypted_random_iv = enc_chunk[poz:poz+self.vs]; poz+=self.vs
        secret_key = self.aes_key
        secret_decryptor = AES.new(secret_key, AES.MODE_CBC, secret_iv)
        random_key = secret_decryptor.decrypt(encrypted_random_key)
        random_iv = secret_decryptor.decrypt(encrypted_random_iv)
        random_decryptor = AES.new(random_key, AES.MODE_CBC, random_iv)
        chunk = random_decryptor.decrypt(enc_chunk[poz:])
        checksum = MD5.new()
        checksum.update(chunk[MD5.digest_size:])
        old_checksum = chunk[:MD5.digest_size]
        return chunk[MD5.digest_size:], old_checksum == checksum.digest()

