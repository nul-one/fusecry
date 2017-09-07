from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from fusecry import config, cry, IntegrityCheckFail
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
    c, kdf_size, kdf_iters = cry.get_password_cry(os.urandom(AES.key_size[2]))
    data = os.urandom(5000)
    assert len(c.enc(data)) % c.vs == 0
    assert data != c.enc(data)[:len(data)]
    assert c.enc(data) != c.enc(data)

def test_cry_password_dec():
    c, kdf_size, kdf_iters = cry.get_password_cry(os.urandom(AES.key_size[2]))
    data = os.urandom(5000)
    dec_data = c.dec(c.enc(data))
    assert data == dec_data[:len(data)]

def test_cry_password_bad_ic():
    c, kdf_size, kdf_iters = cry.get_password_cry(os.urandom(AES.key_size[2]))
    data = os.urandom(5000)
    enc_data = c.enc(data)
    bad_enc_data = enc_data[:1000] + bytes(100) + enc_data[1100:]
    dec_data = c.dec(enc_data)
    error = None
    try:
        bad_dec_data = c.dec(bad_enc_data)
    except Exception as e:
        error = e
    assert type(error) == IntegrityCheckFail


def test_cry_rsa_enc():
    rsa_key = RSA.generate(2048).exportKey()
    c, rsa_size, enc_aes = cry.get_password_cry(rsa_key)
    data = os.urandom(5000)
    assert len(c.enc(data)) % c.vs == 0
    assert data != c.enc(data)[:len(data)]
    assert c.enc(data) != c.enc(data)

def test_cry_rsa_dec():
    c, ks, ki = cry.get_password_cry(os.urandom(AES.key_size[2]))
    data = os.urandom(5000)
    dec_data = c.dec(c.enc(data))
    assert data == dec_data[:len(data)]

def test_cry_rsa_bad_ic():
    c, ks, ki = cry.get_password_cry(os.urandom(AES.key_size[2]))
    data = os.urandom(5000)
    enc_data = c.enc(data)
    bad_enc_data = enc_data[:1000] + bytes(100) + enc_data[1100:]
    dec_data = c.dec(enc_data)
    error = None
    try:
        bad_dec_data = c.dec(bad_enc_data)
    except Exception as e:
        error = e
    assert type(error) == IntegrityCheckFail


## usecase tests


