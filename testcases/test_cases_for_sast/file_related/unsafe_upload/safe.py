import os
from werkzeug.utils import secure_filename

def upload():
    file = request.files['user_file']
    filename = secure_filename(file.filename)
    if filename and allowed_file(filename):
        file.save(os.path.join("/uploads", filename))
    return "ok"
