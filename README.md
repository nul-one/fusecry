
fusecry 
==================================================
[![Build Status](https://travis-ci.org/nul-one/fusecry.png)](https://travis-ci.org/nul-one/fusecry)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/fusecry/Lobby)

FUSE based AES encrypted filesystem and encryption tool

requirements
-------------------------

- Linux (kernel 2.6.14 or above) or OS X (10.11 or above)
- python >= 3.5

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
- use password or RSA key
- encrypt single files
- encrypt streams
- real time integrity check
- filesystem check
- detect local FS block size for best overall performance or set manually
- encrypt file and directory names
- encrypted files keep same directory structure
- option to have file and path names encrypted

usage
-------------------------

### mount/umount

`fusecry mount SOURCE_DIR MOUNT_POINT [--key RSA_KEY_PATH] [-n]`  
`fusecry umount MOUNT_POINT` or `fusermount -u MOUNT_POINT`  
Data copied to mount point will remain encrypted in source directory.  
Use `-n` or `--encrypt-filenames` to also have file and directory names
encrypted. This option is really needed only on the first mount when
fusecry.conf file is being generated.  
**Watch out**: if `-n` is used, actual file and directory names on disk will be
60%+ longer than originals and thus some long names won't be valid! Check what
maximum filename and path length values are on your system.

### mount subdirectory

`fusecry mount SOURCE_DIR/subdir MOUNT_POINT --conf SOURCE_DIR/fusecry.conf [--key RSA_KEY_PATH]`

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
`fusecry info CONF` where `CONF` is the FuseCry config file or
`fusecry info SOURCE_DIR` if `SOURCE_DIR` contains default-named config file
`fusecry.conf`.

FuseCry conf file
-------------------------

This is a json file where FuseCry stores information about encryption for
particular ROOT or single encrypted file. It will default to `fusecry.conf`
when mounting or `FILE_NAME.fusecry` when encrypting single file.  
**Important**: Decryption won't work without this file, so it must not be lost.
It is safe to share this file, it won't help attackers in any way.  
When mounting ROOT to MOUNTPOINT, this file will not be accessible (visible) on
the mountpoint side.

how does it work?
-------------------------

### encryption

1. Raw files are split into chunks of N bytes (best speeds are achieved when N
is equal to your local filesystem block size and defaults to 4096).
2. Each chunk is encrypted with 256bit AES key and random IV.
3. IV and encrypted chunk are hashed with HMAC SHA256 using SHA256 hash of AES
key as HMAC key.
4. HMAC hash, IV and encypted chunk data are stored in encrypted file.
5. Repeat 2-4 for each chunk.
6. Store file size as additional 8 bytes at the end of a file. This way there
is no need of additional padding bytes for each chunk.

### decryption

1. Read HMAC hash and ciphertext of each block. Compare newly created HMAC hash
with recorded one and raise error if they don't match.
2. Read IV and encrypted chunk data from ciphertext.
3. Decrypt data using IV and AES key and store in decrypted file (or return as
file read output).
4. Repeat 1-3 for each block.
6. Read last 8 bytes of encrypted file to determine file size. Truncate raw
file to fit into this size (or truncate last read block before returning as
file read output).

### file and directory name encryption

Raw names are converted to bytes and zero padded and then encrypted as a
single chunk with random IV for each file/dir. Output is then encrypted and
encoded with base32 with `=` padding stripped from the end.  
There is no integrity check when decrypting file names.

backward compatibility
-------------------------

There will be no backwards compatibility guarantee before version 1.0.0  
Minor versions before version 1.0.0 are incompatible between each other (e.g.
version 0.**8**.0 and 0.**7**.0 are incompatible), while patch versions of the
same minor versions are compatible (e.g. 0.7.**1** and 0.7.**2**)  
After 1.0.0 release, all future releases of the same major versions will have
guaranteed backward and forward compatibility.

known limitations and deficiencies
-------------------------

- no options for AES keysize (has to be 256bit)
- chunk size has to be a multiple of 16
- no integrity check of file and directory names and structure
- in case of encrypted file/dir names, whole directory structure is loaded in
RAM

future plans and missing features (in no particular order)
-------------------------

- dinamyc directory structure loading for encrypted file/dir names to preserve
RAM
- <strike>RAM file system option for fast file access</strike> Not going to be
implemented. You can create ramfs and put encrypted data in it on your own.
Also, bottleneck seems to be CPU and not disk I/O (at least on SSD).
- <strike>password change (bulk re-encryption)</strike> Not going to be
implemented. You can mount additional empty FuseCry fs with new password and
move files over. Let's keep it simple.

