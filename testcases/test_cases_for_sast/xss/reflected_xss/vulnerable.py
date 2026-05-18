from flask import request, render_template_string
@app.route('/hello')
def hello():
    name = request.args.get('name')
    return render_template_string(f"<h1>Hello {name}</h1>")  # DANGEROUS
