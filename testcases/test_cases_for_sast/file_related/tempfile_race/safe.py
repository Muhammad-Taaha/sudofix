import tempfile

def safe():
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("data")
        filename = f.name
