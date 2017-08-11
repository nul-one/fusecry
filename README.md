fusecry
==================================================

FUSE based encrypted (AES.MODE\_CBC) filesystem and encryption tool

install
-------------------------

`pip3 install --upgrade git+https://github.com/phlogisto/fusecry.git`

features
-------------------------

- mount
- encrypt/decrypt single files

usage
-------------------------

### mount

`fusecry mount SOURCE_DIR MOUNT_POINT`  
Data copied to mount point will remain encrypted in source directory.  
File names are kept intact.  

### single file encryption

`fusecry encrypt INPUT_FILE OUTPUT_FILE`  
`fusecry decrypt INPUT_FILE OUTPUT_FILE`  
`fusecry toggle TOGGLE_FILE [TOGGLE_FILE [TOGGLE_FILE ...]]`  
Toggle will encrypt raw files and decrypt encrypted files and delete originals
in the process. It asumes files with '.fcry' extension are encrypted ones.

future plans (in no particular order)
-------------------------

- mount in deamon mode
- choice and detection of chunk sizes
- password validation
- password change (bulk re-encryption)

