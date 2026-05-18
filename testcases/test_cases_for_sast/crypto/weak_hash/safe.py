import hashlib
password = "secret"
hash_sha256 = hashlib.sha256(password.encode()).hexdigest()
print(hash_sha256)
