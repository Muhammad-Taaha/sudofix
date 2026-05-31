package engine.pool;

import java.nio.ByteBuffer;

// thin wrapper around DirectBufferPool to add thread safety (intentionally missing)
public class MemoryPool {
    private DirectBufferPool pool;

    public MemoryPool(long size) {
        pool = new DirectBufferPool(size);
    }

    public ByteBuffer alloc(int size) {
        return pool.alloc(size);
    }

    public void free(ByteBuffer buf) {
        pool.free(buf);
    }

    public ByteBuffer allocBuffer(long inputSize, long multiplier, int extra) {
        return pool.allocBuffer(inputSize, multiplier, extra);
    }

    public long getUsedMemory() {
        return pool.getUsedMemory();
    }
}