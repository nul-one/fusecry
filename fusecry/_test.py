from Crypto.PublicKey import RSA
from fusecry import config, cry
import os
import random
import string

## helpers

def random_string(length):
    return ''.join(random.choice(
        string.ascii_letters + 
        string.digits + 
        string.punctuation + 
        string.whitespace ) for i in range(length))


## cry tests

def test_cry_password_enc():
    c, kdf_size, kdf_iters, enc_chunk = cry.get_password_cry(
        os.urandom(config.enc.key_size), config.enc.default_chunk_size)
    data = os.urandom(5000)
    assert len(c.enc(data)) % config.enc.aes_block == 0
    assert data != c.enc(data)[:len(data)]
    assert c.enc(data) != c.enc(data)

def test_cry_password_dec():
    c, kdf_size, kdf_iters, enc_chunk = cry.get_password_cry(
        os.urandom(config.enc.key_size), config.enc.default_chunk_size)
    data = os.urandom(5000)
    dec_data, ic_check = c.dec(c.enc(data))
    assert ic_check
    assert data == dec_data[:len(data)]

def test_cry_password_bad_ic():
    c, kdf_size, kdf_iters, enc_chunk = cry.get_password_cry(
        os.urandom(config.enc.key_size), config.enc.default_chunk_size)
    data = os.urandom(5000)
    enc_data = c.enc(data)
    bad_enc_data = enc_data[:1000] + b'x' + enc_data[1001:]
    dec_data, ic_check = c.dec(enc_data)
    bad_dec_data, bad_ic_check = c.dec(bad_enc_data)
    assert ic_check == True
    assert bad_ic_check == False


def test_cry_rsa_enc():
    rsa_key = RSA.generate(2048).exportKey()
    c, rsa_size, enc_aes, enc_chunk = cry.get_password_cry(
        rsa_key, config.enc.default_chunk_size)
    data = os.urandom(5000)
    assert len(c.enc(data)) % config.enc.aes_block == 0
    assert data != c.enc(data)[:len(data)]
    assert c.enc(data) != c.enc(data)

def test_cry_rsa_dec():
    c, ks, ki, ec = cry.get_password_cry(
        os.urandom(config.enc.key_size), config.enc.default_chunk_size)
    data = os.urandom(5000)
    dec_data, ic_check = c.dec(c.enc(data))
    assert ic_check
    assert data == dec_data[:len(data)]

def test_cry_rsa_bad_ic():
    c, ks, ki, ec = cry.get_password_cry(
        os.urandom(config.enc.key_size), config.enc.default_chunk_size)
    data = os.urandom(5000)
    enc_data = c.enc(data)
    bad_enc_data = enc_data[:1000] + b'x' + enc_data[1001:]
    dec_data, ic_check = c.dec(enc_data)
    bad_dec_data, bad_ic_check = c.dec(bad_enc_data)
    assert ic_check == True
    assert bad_ic_check == False


## usecase tests


