import os
def safe():
    # Constant command, safe (AST should ignore)
    os.system("ls -la")
