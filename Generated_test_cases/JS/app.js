const fs = require('fs');
const path = require('path');
const { Worker } = require('worker_threads');
const Logger = require('./src/logger');
const MemoryPool = require('./src/memorypool');
const JobManager = require('./src/jobmanager');
const cleaner = require('./src/cleaner');
const pipeline = require('./src/pipeline');
const resourceHandler = require('./src/resourcehandler');
const infoLeak = require('./src/infoleak');
const server = require('./src/server');

if (process.argv.length < 3) {
    console.error('Usage: node app.js <config.json>');
    process.exit(1);
}

const configPath = process.argv[2];
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

const log = new Logger(config.log_file, config.pool_size ? 1024*1024 : 1024*1024);
const memPool = new MemoryPool(config.pool_size || 1024*1024);
const jm = new JobManager();
const srv = server.create(config.port || 8080, memPool);
srv.start();

function processJob(job) {
    switch (job.type) {
        case 'transform': {
            let len = job.pattern ? job.pattern.length : 1;
            if (len === 0) len = 1;
            const buf = memPool.allocBuffer(len, job.multiplier || 1, 1);
            if (!buf) {
                log.log('Transform allocation failed');
                return;
            }
            for (let i = 0; i < (job.multiplier || 1); i++) {
                buf.write(job.pattern, i * len, len, 'utf8');
            }
            log.log(`Transformed: ${buf.toString('utf8', 0, (job.multiplier || 1) * len)}`);
            memPool.free(buf);
            break;
        }
        case 'data_manage': {
            if (job.data_chunks) {
                for (const chunk of job.data_chunks) {
                    jm.addData(chunk);
                }
            }
            if (job.schedule_cleanup_at < jm.dataCount()) {
                jm.scheduleCleanup(job.schedule_cleanup_at);
            }
            for (let i = 0; i < 1000; i++) {
                jm.addData(`padding ${i}`);
            }
            jm.runCleanup();
            break;
        }
        case 'cleanup_dir': {
            cleaner.recursiveDelete(job.dir);
            break;
        }
        case 'pipeline': {
            const output = pipeline.execute(job.cmd, job.pattern || '');
            log.log('Pipeline output: ' + output);
            break;
        }
        case 'process_files': {
            resourceHandler.processFiles(job.file1, job.file2);
            break;
        }
        case 'log_leak': {
            infoLeak.writeLeakyLog('leak_log.bin', 1, 'sensitive data');
            break;
        }
    }
}

// Simulate multi-threading with worker threads for heavier jobs
if (config.jobs) {
    for (const job of config.jobs) {
        // In a real multi-threaded scenario we'd spawn workers; for simplicity we call directly
        processJob(job);
    }
}

// Keep process alive until server stops (never in this simple version)