# features_vulnerable.py
import numpy as np

def add_features(df):
    """VULNERABILITY: exec() of dynamically built string."""
    feature_code = "df['rooms_per_household'] = df['total_rooms'] / df['households']"
    
    # VULNERABILITY: exec() can be hijacked if column names come from user input
    exec(feature_code)

    # VULNERABILITY: Division by zero – no check, can crash or produce inf
    df['bedroom_ratio'] = df['total_bedrooms'] / df['total_rooms']
    return df