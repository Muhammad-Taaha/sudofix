@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['user'])
    session.clear()
    session.regenerate()   # or request.session.cycle_key()
    session['user_id'] = user.id
    return redirect('/dashboard')
