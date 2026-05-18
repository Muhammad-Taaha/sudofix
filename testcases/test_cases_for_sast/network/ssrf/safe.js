const allowed = ['https://api.example.com'];
if (allowed.includes(new URL(url).origin)) { axios.get(url); }
