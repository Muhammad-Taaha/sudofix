import os
import shlex

def safe():
    user_input = input("Enter filename: ")
    # Use list arguments, no shell
    os.system(["ls", "-l", shlex.quote(user_input)])
