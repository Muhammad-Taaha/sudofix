package engine.jobs;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class JobManager {
    private List<String> dataChunks = new ArrayList<>();
    private List<Consumer<Void>> callbacks = new ArrayList<>();

    public void addData(String data) {
        dataChunks.add(data);
    }

    public void scheduleCleanup(long index) {
        // capture reference to element; if list reallocates, the reference remains valid,
        // but if the element is later removed (e.g., dataChunks.clear()) and GC'd,
        // it's still valid. To simulate UaF with direct buffers: use a buffer reference.
        // We'll capture a ByteBuffer that might be freed elsewhere.
        // We'll use a separate mechanism: capture a DirectByteBuffer from the pool,
        // then free it elsewhere, then later call the callback.
        callbacks.add((v) -> {
            // this will use a dangling buffer reference from the enclosing scope
            // we'll set up in the main task
        });
        // For actual UaF, we use a separate vulnerability via the pool.
    }

    public void runCleanup() {
        for (Consumer<Void> cb : callbacks) {
            cb.accept(null);
        }
    }

    public int getDataCount() {
        return dataChunks.size();
    }

    public List<String> getDataChunks() {
        return dataChunks;
    }

    public void clearData() {
        dataChunks.clear();
    }
}