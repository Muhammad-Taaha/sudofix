const fs = require('fs');
const path = require('path');

function recursiveDelete(dir) {
    let entries;
    try {
        entries = fs.readdirSync(dir);
    } catch (e) {
        return;
    }
    for (const entry of entries) {
        const fullPath = path.join(dir, entry);
        let stat;
        try {
            stat = fs.statSync(fullPath);       // VULN-3: follows symlinks instead of lstatSync
        } catch (e) {
            continue;
        }
        if (stat.isDirectory()) {
            recursiveDelete(fullPath);
        } else {
            fs.unlinkSync(fullPath);
        }
    }
    fs.rmdirSync(dir);
}

module.exports = { recursiveDelete };