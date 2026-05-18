from flask import request, render_template
@app.route('/hello')
def hello():
    name = request.args.get('name')
    return render_template('hello.html', name=name)  # SAFE (auto-escaped)
