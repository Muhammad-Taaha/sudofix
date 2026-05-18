import os

def safe():
    os.chmod("/tmp/secret.txt", 0o600)   # Owner read/write only
