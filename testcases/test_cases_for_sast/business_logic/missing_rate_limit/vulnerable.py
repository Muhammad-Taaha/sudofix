@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['user'])
    return "OK"  # DANGEROUS (no rate limiting)
