import os

def vulnerable():
    os.chmod("/tmp/secret.txt", 0o777)   # DANGEROUS (world writable)
