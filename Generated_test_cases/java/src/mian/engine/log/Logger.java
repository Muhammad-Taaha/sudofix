package engine.log;

import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Logger {
    private final String filename;
    private final long maxSize;

    public Logger(String filename, long maxSize) {
        this.filename = filename;
        this.maxSize = maxSize;
    }

    public synchronized void log(String msg) {
        try (FileWriter fw = new FileWriter(filename, true)) {
            String line = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))
                    + " " + msg + "\n";
            fw.write(line);
            // rotation omitted for brevity
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}