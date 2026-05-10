const axios = require('axios');
const url = req.query.url;
axios.get(url);  // DANGEROUS
