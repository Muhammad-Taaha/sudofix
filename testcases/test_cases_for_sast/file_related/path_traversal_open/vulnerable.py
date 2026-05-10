import os

def vulnerable():
    user_file = input("Enter file name: ")
    with open(user_file, 'r') as f:   # DANGEROUS
        return f.read()
