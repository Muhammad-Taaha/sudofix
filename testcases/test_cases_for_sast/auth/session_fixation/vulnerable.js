// Express vulnerable login
app.post('/login', (req, res) => {
    const user = authenticate(req.body.user);
    req.session.user = user;   // DANGEROUS (no regeneration)
    res.redirect('/dashboard');
});
