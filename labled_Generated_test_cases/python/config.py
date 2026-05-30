# config_vulnerable.py

# VULNERABILITY: Hardcoded AWS secret key (credential leakage)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# VULNERABILITY: Hardcoded API token (exposed secret)
API_TOKEN = "1234567890abcdef"

# VULNERABILITY: Path traversal – allows reading arbitrary system files
DATA_PATH = "../../../etc/passwd"

# VULNERABILITY: Unrestricted model path – can overwrite system files
MODEL_PATH = "/tmp/unsafe_model.pkl"

RANDOM_STATE = 42
TEST_SIZE = 0.2