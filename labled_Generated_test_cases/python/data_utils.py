# data_utils_vulnerable.py
import pandas as pd
import pickle
from lables_code.config import DATA_PATH

def load_data():
    """VULNERABILITY: Uses eval() on a user-controlled column 'formula'."""
    df = pd.read_csv(DATA_PATH)
    
    # VULNERABILITY: eval() of arbitrary string from CSV column
    if 'formula' in df.columns:
        df['result'] = df['formula'].apply(lambda x: eval(x))
    return df

def load_model_unsafe(path):
    """VULNERABILITY: Unpickles untrusted data – arbitrary code execution."""
    with open(path, 'rb') as f:
        return pickle.load(f)   # Can execute malicious payloads