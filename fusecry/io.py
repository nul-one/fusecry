"""
Fusecry IO functions.
"""

import fusecry.config as config
import os
import struct

def read(cry, path, length, offset):
    buf = b''
    length = min(length, filesize(path) - offset)
    if length <= 0:
        return buf
    cs = config.enc.chunk_size
    ms = config.enc.key_size + 2*config.enc.iv_size \
        + (config.enc.hash_size if cry.integrity_check else 0)
    ncc = int(offset / cs) # number of untouched chunks
    sb = offset % cs # skip bytes in first crypto chunk
    with open(path,'rb') as f:
        f.seek(ncc*(ms+cs))
        while len(buf) < (sb+length):
            data = f.read(ms+cs)
            data_len = len(data)-ms
            if data_len <= struct.calcsize('Q'):
                break
            if data_len % config.enc.aes_block:
                data = data[:-(data_len%config.enc.aes_block)]
            buf += cry.dec(data)
    return buf[sb:sb+length]
    
def write(cry, path, buf, offset):
    cs = config.enc.chunk_size
    ms = config.enc.key_size + 2*config.enc.iv_size \
        + (config.enc.hash_size if cry.integrity_check else 0)
    xbuf = b''
    old_crypto=b''
    ncc = int(offset / cs) # number of untouched chunks
    if offset > filesize(path):
        return 0
    if offset % cs:
        # Decrypt last block and prepend it to xbuf
        with open(path,'rb') as f:
            f.seek(ncc*(ms+cs))
            data = f.read(ms+cs)
            data_len = len(data)-ms
            if data_len > struct.calcsize('Q'):
                if data_len % config.enc.aes_block:
                    data = data[:-(data_len%config.enc.aes_block)]
                xbuf = cry.dec(data)[:offset%cs] + buf
    else:
        # just right block size
        xbuf = buf
    with open(path,'r+b') as f:
        # Drop file data after crypto offset and add new data
        s = f.truncate(ncc*(ms+cs))
        f.seek(s)
        done_length = 0
        while done_length < len(xbuf):
            chunk = xbuf[done_length:cs]
            done_length += cs
            if not chunk:
                break
            f.write(cry.enc(chunk))
        f.write(struct.pack('<Q', offset + len(buf)))
    return len(buf)
    
def truncate(cry, path, length):
    if length:
        cs = config.enc.chunk_size
        ms = config.enc.key_size + 2*config.enc.iv_size \
            + (config.enc.hash_size if cry.integrity_check else 0)
        ncc = int(length/cs) # number of untouched chunks
        data = read(path, length%cs, ncc*cs)
        with open(path, 'r+b') as f:
            s = f.truncate(ncc*(ms+cs))
            f.seek(s)
            f.write(cry.enc(data))
            f.write(struct.pack('<Q', length))
    else:
        with open(path, 'r+b') as f:
            f.truncate(0)

def filesize(path):
    with open(path, 'rb') as f:
        file_end = f.seek(0,os.SEEK_END)
        size = 0
        if file_end:
            f.seek(file_end-struct.calcsize('Q'))
            size = struct.unpack('<Q', f.read(struct.calcsize('Q')))[0]
        return size

def attr(path):
    st = os.lstat(path)
    attr = dict((key, getattr(st, key)) for key in (
        'st_atime', 'st_ctime', 'st_gid', 'st_mode',
        'st_mtime', 'st_nlink', 'st_size', 'st_uid'))
    if os.path.isfile(path):
        if attr['st_size']:
            if os.access(path, os.R_OK):
                attr['st_size'] = filesize(path)
            else:
                cs = config.enc.chunk_size
                ms = config.enc.key_size + 2*config.enc.iv_size \
                    + (config.enc.hash_size if cry.integrity_check else 0)
                ratio = cs / (ms+cs)
                attr['st_size'] = \
                    int((attr['st_size']-struct.calcsize('Q'))*ratio)
    return attr

def touch(fname, mode=0o644, dir_fd=None, **kwargs):
    flags = os.O_CREAT | os.O_APPEND
    with os.fdopen(os.open(fname, flags=flags, mode=mode, dir_fd=dir_fd)) as f:
        os.utime(f.fileno() if os.utime in os.supports_fd else fname,
            dir_fd=None if os.supports_fd else dir_fd, **kwargs)

