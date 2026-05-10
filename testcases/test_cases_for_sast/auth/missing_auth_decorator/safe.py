from flask_login import login_required
@app.route('/admin')
@login_required
def admin_panel():
    return "Admin content"
