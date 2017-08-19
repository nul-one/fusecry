"""
Fusecry encryption functions.
"""

from Crypto import Random
from Crypto.Cipher import AES 
from Crypto.Hash import MD5 
from Crypto.Protocol.KDF import PBKDF2
from fusecry.securedata import secure
import fusecry.config as config

class Cry(object):
    def __init__(self, password, kdf_salt, kdf_iters):
        self.ks = config.enc.key_size
        self.vs = config.enc.iv_size
        self.aes_key = PBKDF2(str(password), kdf_salt, self.ks, kdf_iters)

    def enc(self, chunk):
        checksum = MD5.new()
        if not chunk:
            return b''
        if len(chunk) % AES.block_size != 0:
            chunk += bytes(AES.block_size - len(chunk) % AES.block_size)
        checksum.update(chunk)
        chunk = checksum.digest() + chunk
        random_key = Random.get_random_bytes(self.ks)
        random_iv = Random.get_random_bytes(self.vs)
        random_encryptor = AES.new(random_key, AES.MODE_CBC, random_iv)
        secret_iv = Random.get_random_bytes(self.vs)
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

