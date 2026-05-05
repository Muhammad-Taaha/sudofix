import os
def vulnerable():
    user_cmd = input("Enter command: ")
    os.system(user_cmd)  # DANGEROUS
