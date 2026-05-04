import subprocess

def vulnerable():
    user_input = input("Enter command: ")
    subprocess.call(user_input, shell=True)  # DANGEROUS shell=True
