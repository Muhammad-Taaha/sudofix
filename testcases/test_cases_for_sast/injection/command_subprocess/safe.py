import subprocess
def safe():
    # List form, no shell, safe
    subprocess.call(["ls", "-la"])
