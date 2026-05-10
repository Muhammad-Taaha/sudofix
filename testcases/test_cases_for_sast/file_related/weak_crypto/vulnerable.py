import hashlib

def vulnerable():
    password = "secret"
    hash_md5 = hashlib.md5(password.encode()).hexdigest()   # WEAK
    hash_sha1 = hashlib.sha1(password.encode()).hexdigest() # WEAK
    return hash_md5, hash_sha1
