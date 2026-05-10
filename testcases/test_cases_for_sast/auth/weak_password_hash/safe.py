import hashlib
password = "secret"
hash_sha256 = hashlib.sha256(password.encode()).hexdigest()   # SAFE
from passlib.hash import bcrypt
bcrypt.hash(password)
