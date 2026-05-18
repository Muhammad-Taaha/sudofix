import os

def safe():
    user_file = input("Enter file name: ")
    # Only allow alphanumeric filenames
    if user_file.isalnum():
        with open(user_file, 'r') as f:
            return f.read()
    return "Invalid filename"
