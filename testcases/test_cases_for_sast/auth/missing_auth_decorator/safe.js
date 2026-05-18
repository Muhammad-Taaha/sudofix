const ensureAuth = (req, res, next) => { if (req.isAuthenticated()) return next(); res.redirect('/login'); };
app.get('/admin', ensureAuth, (req, res) => {
    res.send('admin');
});
