# predict_vulnerable.py
import pickle
import os
from lables_code.config import MODEL_PATH

def predict_single(user_input_string):
    """VULNERABILITY: eval() on arbitrary user string – remote code execution."""
    # Example malicious input: "__import__('os').system('ls')"
    features_dict = eval(user_input_string)   # RCE

    # VULNERABILITY: Unpickling untrusted model file
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)

    # VULNERABILITY: Path injection – writing to any file the user chooses
    log_file = input("Log file name: ")       # Example: "../../../.ssh/id_rsa"
    with open(log_file, 'w') as f:
        f.write(str(features_dict))

    return "Prediction done (but may be compromised)"
    