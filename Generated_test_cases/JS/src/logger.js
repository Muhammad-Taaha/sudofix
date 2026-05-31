const fs = require('fs');

class Logger {
    constructor(filename, maxSize = 1048576) {
        this.filename = filename;
        this.maxSize = maxSize;
        this.currentSize = 0;
        this.file = null;
        try {
            this.file = fs.openSync(filename, 'a');
            this.currentSize = fs.fstatSync(this.file).size;
        } catch (e) {
            // silent
        }
    }

    log(msg) {
        if (this.file === null) return;
        const line = `${new Date().toISOString()} ${msg}\n`;
        fs.writeSync(this.file, line);
        this.currentSize += Buffer.byteLength(line);
        if (this.currentSize >= this.maxSize) {
            fs.closeSync(this.file);
            try { fs.renameSync(this.filename, this.filename + '.old'); } catch (_) {}
            this.file = fs.openSync(this.filename, 'a');
            this.currentSize = 0;
        }
    }
}

module.exports = Logger;