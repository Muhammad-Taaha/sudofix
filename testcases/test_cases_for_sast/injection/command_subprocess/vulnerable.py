import subprocess

def vulnerable():
    user_cmd = input("Enter command: ")
    subprocess.call(user_cmd, shell=True)  # DANGEROUS: shell=True with variable
