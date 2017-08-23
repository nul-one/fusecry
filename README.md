
fusecry 
==================================================
[![Build Status](https://travis-ci.org/phlogisto/fusecry.png)](https://travis-ci.org/phlogisto/fusecry)
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
`pip3 install -U git+https://github.com/phlogisto/fusecry.git`  

### autocompletion
In addition, add the following to your `.bashrc` to enable autocompletion:  
`eval "$(register-python-argcomplete fusecry)"`

features
-------------------------

- mount
- encrypt with password or RSA key
- encrypt/decrypt single files
- real time integrity check
- filesystem check
- check if password/RSA key is valid before mounting
- detect local FS block size for best performance
- option to choose chunk size to optimize for READ or WRITE
- encrypted files keep same file names and directory structure (good for backup
solutions like DropBox where you have option to roll-back previous versions of
individual files)

backwards compatibility
-------------------------

Versions 0.4.0 and above are not backwards compatible with previous versions.

usage
-------------------------

### mount/umount

`fusecry mount SOURCE_DIR MOUNT_POINT [--key RSA_KEY_PATH]`
`fusecry umount MOUNT_POINT` or `fusermount -u MOUNT_POINT`
Data copied to mount point will remain encrypted in source directory.  

### single file encryption

`fusecry encrypt INPUT_FILE OUTPUT_FILE [-c FCRY_CONF_FILE] [--key PUB_OR_PVT_RSA_KEY_PATH]`  
`fusecry decrypt INPUT_FILE OUTPUT_FILE [-c FCRY_CONF_FILE] [--key PVT_RSA_KEY_PATH]`  
`FCRY_CONF_FILE` is stored in ROOT directory of existing FuseCry filesystem.  
If you call the command without existing settings file, it will be created in
case of encryption or default will be used `INPUT_FILE.fcry` in case of
decryption.

### fsck

`fusecry fsck ROOT [--key RSA_KEY_PATH]`
ROOT is the source dir that is to be mounted. Make sure it is not mounted
during fsck or you might get false-positive errors detected.

known deficiencies and limitations
-------------------------

- file names are not being encrypted by design
- chunk size has to be a multiple of 4096

future plans and missing features (in no particular order)
-------------------------

- password change (bulk re-encryption)

