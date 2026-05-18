const crypto = require('crypto');
const hash = crypto.createHash('md5').update('secret').digest('hex');
