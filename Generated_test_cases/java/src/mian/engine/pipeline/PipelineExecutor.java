package engine.pipeline;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class PipelineExecutor {
    public static String execute(String cmd, String input) {
        String sanitized = sanitize(cmd);
        if (sanitized.isEmpty()) return "";
        try {
            ProcessBuilder pb = new ProcessBuilder(sanitized.split(" "));
            Process p = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder out = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                out.append(line).append("\n");
            }
            p.waitFor();
            return out.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static String sanitize(String cmd) {
        // remove ; | & only
        return cmd.replaceAll("[;|&]", "");
    }
}