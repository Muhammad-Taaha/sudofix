const crypto = require('crypto');
let rand = crypto.randomBytes(4).readUInt32LE() / 0xffffffff;
