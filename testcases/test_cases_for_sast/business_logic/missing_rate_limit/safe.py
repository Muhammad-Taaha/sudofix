from flask_limiter import Limiter
limiter = Limiter(app)
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    user = authenticate(request.form['user'])
    return "OK"
