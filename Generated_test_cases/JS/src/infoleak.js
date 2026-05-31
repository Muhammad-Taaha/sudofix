const fs = require('fs');

// INFO LEAK: Using Buffer.allocUnsafe() leaves old memory data that gets written to file.
function writeLeakyLog(filename, level, message) {
    const buf = Buffer.allocUnsafe(128);   // uninitialized memory
    buf.writeInt32LE(level, 0);
    buf.write(message, 4, message.length, 'utf8');
    fs.appendFileSync(filename, buf);
}

module.exports = { writeLeakyLog };