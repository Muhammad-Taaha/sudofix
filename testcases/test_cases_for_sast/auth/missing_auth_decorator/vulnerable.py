# Flask view without login decorator
@app.route('/admin')
def admin_panel():
    return "Admin content"   # DANGEROUS (no @login_required)
