import os

def vulnerable():
    user_input = input("Enter command: ")
    os.system(user_input)  # DANGEROUS
