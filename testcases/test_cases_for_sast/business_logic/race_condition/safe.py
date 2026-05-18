import fcntl
def update_file(data):
    with open("data.txt", "r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        content = f.read()
        f.seek(0)
        f.write(content + data)
        f.truncate()
        fcntl.flock(f, fcntl.LOCK_UN)
