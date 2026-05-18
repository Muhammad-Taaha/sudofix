app.post('/login', (req, res) => {
    const user = authenticate(req.body.user);
    req.session.regenerate(() => {   // SAFE
        req.session.user = user;
        res.redirect('/dashboard');
    });
});
