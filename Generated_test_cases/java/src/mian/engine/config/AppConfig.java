package engine.config;

import java.util.List;

public class AppConfig {
    public int port = 8080;
    public String log_file = "engine.log";
    public long pool_size = 1024 * 1024;
    public List<JobConfig> jobs;
    public String cleanup_dir;
    public String pipeline_cmd;

    public static class JobConfig {
        public String type;
        public String pattern;
        public long multiplier = 1;
        public String dir;
        public String cmd;
        public String file1;
        public String file2;
        public List<String> data_chunks;
        public long schedule_cleanup_at = 0;
    }
}