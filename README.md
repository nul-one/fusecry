
fusecry 
==================================================
[![Build Status](https://travis-ci.org/nul-one/fusecry.png)](https://travis-ci.org/nul-one/fusecry)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/fusecry/Lobby)

FUSE based encrypted (AES.MODE\_CBC) filesystem and encryption tool

requirements
-------------------------

- Linux
- python >= 3.4

install
-------------------------

### install from pypi
`pip3 install fusecry`  

### install from github
`pip3 install -U git+https://github.com/nul-one/fusecry.git`  

### autocompletion
In addition, add the following to your `.bashrc` to enable autocompletion:  
`eval "$(register-python-argcomplete fusecry)"`

features
-------------------------

- mount any subdirectory of encrypted structure
- encrypt with password or RSA key
- encrypt/decrypt single files
- encrypt/decrypt streams
- real time integrity check
- filesystem check
- check if password/RSA key is valid before mounting
- detect local FS block size for best performance
- option to choose chunk size to optimize for READ or WRITE
- encrypted files keep same file names and directory structure (good for backup
solutions like DropBox where you have option to roll-back previous versions of
individual files)

compatibility
-------------------------

There will be no backwards compatibility guarantee before version 1.0

- Versions 0.7.0 and above are not backwards compatible with previous versions
- Versions 0.6.0 and above are not backwards compatible with previous versions
- Versions 0.4.0 and above are not backwards compatible with previous versions
- Versions 0.5.0 and above are not backwards compatible with previous versions

usage
-------------------------

### mount/umount

`fusecry mount SOURCE_DIR MOUNT_POINT [--key RSA_KEY_PATH]`
`fusecry umount MOUNT_POINT` or `fusermount -u MOUNT_POINT`
Data copied to mount point will remain encrypted in source directory.  

### mount subdirectory

`fusecry mount SOURCE_DIR/subdir MOUNT_POINT --conf SOURCE_DIR/.fusecry [--key RSA_KEY_PATH]`

### single file encryption

`fusecry encrypt INPUT_FILE OUTPUT_FILE [-c FCRY_CONF_FILE] [--key PUB_OR_PVT_RSA_KEY_PATH]`  
`fusecry decrypt INPUT_FILE OUTPUT_FILE [-c FCRY_CONF_FILE] [--key PVT_RSA_KEY_PATH]`  
`FCRY_CONF_FILE` is stored in ROOT directory of existing FuseCry filesystem.  
If you call the command without existing settings file, it will be created in
case of encryption or default will be used `INPUT_FILE.fcry` in case of
decryption.

### stream encryption

`<DATA fusecry stream encrypt -c FCRY_CONF_FILE [--key PUB_OR_PVT_RSA_KEY_PATH]`  
`<DATA fusecry stream decrypt -c FCRY_CONF_FILE [--key PVT_RSA_KEY_PATH]`  

### fsck

`fusecry fsck ROOT [--key RSA_KEY_PATH]`
ROOT is the source dir that is to be mounted. Make sure it is not mounted
during fsck or you might get false-positive errors detected.

### info

Use this to show info about encryption:  
`fusecry info CONF` where `CONF` is the FuseCry config file (e.g. `.fusecry`).

FuseCry conf file
-------------------------

This is a file where FuseCry stores information about encryption for particular
ROOT or single encrypted file. It will default to `.fusecry` when mounting or
`FILE_NAME.fusecry` when encrypting single file.  
Decryption won't work without this file, so it must be kept safe. It is safe to
share this file, it won't help attackers in any way.  
When mounting ROOT to MOUNTPOINT, this file will not be accessible on the
mountpoint side.

### contents

Depending on encryption type (password or rsa key) there are 2 possible formats
of Fusecry conf file.

#### password

- 8 bytes: string `password`
- 4 bytes: unsigned int chunk\_size
- 8 bytes: string cipher (e.g. `AES_CBC `)
- 8 bytes: string hashmod (e.g. `SHA256  `)
- 32 bytes: kdf\_salt
- 4 bytes: unsigned int kdf\_iters
- 1024 bytes: encrypted chunk sample

#### rsa key

- 8 bytes: string `rsakey  `
- 4 bytes: unsigned int chunk\_size
- 8 bytes: string cipher (e.g. `AES_CBC `)
- 8 bytes: string hashmod (e.g. `SHA256  `)
- 4 bytes: unsigned int rsa\_key\_size
- rsa\_key\_size bytes: rsa encrypted key
- 1024 bytes: encrypted chunk sample

how does it work?
-------------------------

### encryption

1. Raw files are split into chunks of N bytes (best speeds are achieved when N
is equal to your local filesystem block size and defaults to 4096).
2. Each chunk is hashed with HMAC SHA256.
3. Hash and chunk data are encrypted with 256bit AES key and random IV
generated for each chunk.
4. Random IV and encrypted hash and chunk data are stored in the file.
5. Repeat 2-4 for each chunk.
6. Store file size as additional 8 bytes at the end of a file. This way there
is no need of additional padding bytes for each chunk.

### decryption

1. Read chunk IV and encrypted chunk hash and data for each chunk.
2. Decrypt hash and data using IV and AES key.
3. Hash decrypted data and compare with existing decrypted hash.
4. If hash comparison is ok, store data in raw file, raise error otherwise.
5. Repeat 1-5 for each chunk.
6. Read last 8 bytes of encrypted file to determine file size. Truncate raw
file to fit into this size.


known deficiencies and limitations
-------------------------

- file names are not being encrypted by design
- chunk size has to be a multiple of 16

future plans and missing features (in no particular order)
-------------------------

- RAM file system (for fast file access)
- password change (bulk re-encryption)
- choice of AES key size
- choice of hmac digest algorithm

