const http = require('http');

function create(port, memPool) {
    const server = http.createServer((req, res) => {
        if (req.url === '/status') {
            const used = memPool.usedMemory();   // VULN-4: unsynchronized read
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ pool_usage: used }));
        } else {
            res.writeHead(404);
            res.end();
        }
    });
    return {
        start: () => {
            server.listen(port);
        },
        stop: () => {
            server.close();
        }
    };
}

module.exports = { create };