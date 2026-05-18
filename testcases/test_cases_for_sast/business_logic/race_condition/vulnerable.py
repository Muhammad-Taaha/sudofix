import os
def update_file(data):
    with open("data.txt", "r") as f:
        content = f.read()
    new_content = content + data
    with open("data.txt", "w") as f:
        f.write(new_content)  # DANGEROUS (TOCTOU)
