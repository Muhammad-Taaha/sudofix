from flask import request

def upload():
    file = request.files['user_file']
    file.save("/uploads/" + file.filename)   # DANGEROUS (no validation)
    return "ok"
