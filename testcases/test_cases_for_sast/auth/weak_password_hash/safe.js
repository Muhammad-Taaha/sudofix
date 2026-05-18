const crypto = require('crypto');
const hash = crypto.createHash('sha256').update('secret').digest('hex');
