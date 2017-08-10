fusecry
==================================================

FUSE based encrypted (AES.MODE\_CBC) filesystem

install
-------------------------

`pip3 install --upgrade git+https://github.com/phlogisto/fusecry.git`

usage
-------------------------

Create 2 empty directories (e.g. `~/source` and `~/dest`). Run
`fusecry mount ~/source ~/dest`, enter password. Copy data in `~/dest` and it
will remain encrypted in `~/source` after unmounting. Ctrl+c to unmount.

future plans (in no particular order)
-------------------------

- deamon
- encrypting/decrypting single files
- choice and detection of chunk sizes
- password validation
- password change

