fusecry
==================================================

FUSE based encrypted (AES.MODE\_CBC) filesystem

install
-------------------------

`pip3 install --upgrade git+https://github.com/phlogisto/fusecry.git`

usage
-------------------------

- create 2 empty directories (e.g. `~/source` and `~/dest`)
- run `python3 -m fusecry mount ~/source ~/dest`
- enter password
- copy data in ~/dest and it will remain encrypted in ~/source after unmounting
- ctrl+c to stop

