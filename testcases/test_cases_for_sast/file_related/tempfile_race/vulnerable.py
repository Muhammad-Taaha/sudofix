import tempfile

def vulnerable():
    filename = tempfile.mktemp()   # DANGEROUS (race condition)
    with open(filename, 'w') as f:
        f.write("data")
