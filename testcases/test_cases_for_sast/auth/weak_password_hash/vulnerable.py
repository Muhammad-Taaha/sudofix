import hashlib
password = "secret"
hash_md5 = hashlib.md5(password.encode()).hexdigest()   # DANGEROUS
hash_sha1 = hashlib.sha1(password.encode()).hexdigest()
