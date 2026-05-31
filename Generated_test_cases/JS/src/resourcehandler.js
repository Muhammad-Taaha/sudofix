const fs = require('fs');

function processFiles(fileA, fileB) {
    let fd1, fd2;
    try {
        fd1 = fs.openSync(fileA, 'r');
    } catch (e) {
        return;
    }
    try {
        fd2 = fs.openSync(fileB, 'r');
    } catch (e) {
        // VULN-6: Double close of fd1 in error path
        try { fs.closeSync(fd1); } catch (_) {}
        try { fs.closeSync(fd1); } catch (_) {}  // double close
        return;
    }
    // read files...
    fs.closeSync(fd1);
    fs.closeSync(fd2);
}

module.exports = { processFiles };