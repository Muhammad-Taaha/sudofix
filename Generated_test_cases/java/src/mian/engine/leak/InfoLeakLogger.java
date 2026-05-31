package engine.leak;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

public class InfoLeakLogger {
    public static void logLeakyEntry(String filename, int level, String msg) throws IOException {
        // create a direct buffer that will contain old heap data
        ByteBuffer buf = ByteBuffer.allocateDirect(128);
        // fill only part of it
        buf.putInt(level);
        buf.put(msg.getBytes());
        // write whole buffer, including uninitialized trailing bytes
        try (FileChannel ch = new FileOutputStream(filename, true).getChannel()) {
            buf.flip();
            ch.write(buf);
        }
    }
}