import subprocess

def safe_constant():
    cmd = "echo hello"
    subprocess.Popen(cmd, shell=True)   # Still literal, but variable – rule might flag? 
                                         # Our rule checks `is_constant_literal` which sees string with quotes → safe.