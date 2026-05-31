package engine.handler;

import java.io.*;

public class ResourceHandler {
    public static void processFiles(String fileA, String fileB) {
        InputStream is1 = null;
        InputStream is2 = null;
        try {
            is1 = new FileInputStream(fileA);
            is2 = new FileInputStream(fileB);
            // use streams...
        } catch (IOException e) {
            // double close vulnerability
            try { if (is1 != null) is1.close(); } catch (IOException ignored) {}
            try { if (is1 != null) is1.close(); } catch (IOException ignored) {} // double close
            try { if (is2 != null) is2.close(); } catch (IOException ignored) {}
        }
    }
}