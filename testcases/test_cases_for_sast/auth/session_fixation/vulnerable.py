# Flask vulnerable login
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['user'])
    session['user_id'] = user.id   # DANGEROUS (no session regeneration)
    return redirect('/dashboard')
