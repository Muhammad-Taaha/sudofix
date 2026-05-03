import subprocess

def safe():
    user_arg = input("Enter argument: ")
    subprocess.call(["ls", "-l", user_arg])  # SAFE: list, no shell
