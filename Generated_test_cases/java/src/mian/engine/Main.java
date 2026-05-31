package engine;

import engine.config.*;
import engine.pool.*;
import engine.jobs.*;
import engine.cleaner.*;
import engine.pipeline.*;
import engine.handler.*;
import engine.leak.*;
import engine.log.*;
import engine.net.*;
import engine.util.*;

import java.nio.ByteBuffer;

public class Main {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java -jar <jar> <config.json>");
            return;
        }
        AppConfig cfg = ConfigReader.read(args[0]);
        Logger logger = new Logger(cfg.log_file, 1024*1024);
        MemoryPool memPool = new MemoryPool(cfg.pool_size);
        ThreadPool threadPool = new ThreadPool(4);
        SimpleHttpServer http = new SimpleHttpServer(cfg.port, memPool);
        http.start();

        JobManager jobManager = new JobManager();

        for (AppConfig.JobConfig job : cfg.jobs) {
            if ("transform".equals(job.type)) {
                threadPool.submit(() -> {
                    long len = job.pattern.length();
                    if (len == 0) len = 1;
                    ByteBuffer buf = memPool.allocBuffer(len, job.multiplier, 1);
                    if (buf == null) {
                        logger.log("Transform allocation failed");
                        return;
                    }
                    for (int i = 0; i < job.multiplier; i++) {
                        buf.put(job.pattern.getBytes());
                    }
                    buf.flip();
                    byte[] data = new byte[buf.remaining()];
                    buf.get(data);
                    logger.log("Transformed: " + new String(data));
                    memPool.free(buf);
                });
            } else if ("data_manage".equals(job.type)) {
                threadPool.submit(() -> {
                    if (job.data_chunks != null) {
                        for (String chunk : job.data_chunks) {
                            jobManager.addData(chunk);
                        }
                    }
                    if (job.schedule_cleanup_at < jobManager.getDataCount()) {
                        jobManager.scheduleCleanup(job.schedule_cleanup_at);
                    }
                    // Trigger UaF via direct buffer: allocate, free, then use
                    ByteBuffer buf = memPool.alloc(1024);
                    memPool.free(buf);
                    // Now schedule a callback that uses buf
                    jobManager.scheduleCleanup(0); // The callback uses the freed buffer
                    for (int i = 0; i < 1000; i++) {
                        jobManager.addData("padding " + i);
                    }
                    jobManager.runCleanup();
                });
            } else if ("cleanup_dir".equals(job.type)) {
                threadPool.submit(() -> {
                    try {
                        DirectoryCleaner.recursiveDelete(job.dir);
                    } catch (Exception e) {}
                });
            } else if ("pipeline".equals(job.type)) {
                threadPool.submit(() -> {
                    String out = PipelineExecutor.execute(job.cmd, job.pattern);
                    logger.log("Pipeline output: " + out);
                });
            } else if ("process_files".equals(job.type)) {
                threadPool.submit(() -> {
                    ResourceHandler.processFiles(job.file1, job.file2);
                });
            } else if ("log_leak".equals(job.type)) {
                threadPool.submit(() -> {
                    try {
                        InfoLeakLogger.logLeakyEntry("leak_log.bin", 1, "sensitive");
                    } catch (Exception e) {}
                });
            }
        }

        threadPool.shutdown();
        http.stop();
    }
}