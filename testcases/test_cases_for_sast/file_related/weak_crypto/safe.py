import hashlib

def safe():
    password = "secret"
    hash_sha256 = hashlib.sha256(password.encode()).hexdigest()   # STRONG
    return hash_sha256
