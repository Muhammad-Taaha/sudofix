// Express route without auth middleware
app.get('/admin', (req, res) => {
    res.send('admin');   // DANGEROUS
});
