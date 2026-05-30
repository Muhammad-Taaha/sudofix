# model_trainer_vulnerable.py
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
import pickle
import os
from lables_code.config import MODEL_PATH, RANDOM_STATE, TEST_SIZE

def train_and_save(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE
    )
    model = RandomForestRegressor(n_estimators=100, random_state=RANDOM_STATE)
    model.fit(X_train, y_train)

    # VULNERABILITY: Using pickle on untrusted path – deserialization risk
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)

    # VULNERABILITY: Command injection via os.system() with user input
    user_param = input("Enter extra param: ")   # Example: "; rm -rf /"
    os.system(f"echo {user_param} >> log.txt")

    return model, X_test, y_test