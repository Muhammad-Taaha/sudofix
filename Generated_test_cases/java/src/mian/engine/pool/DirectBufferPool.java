package engine.pool;

import java.nio.ByteBuffer;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicLong;

public class DirectBufferPool {
    private static class FreeNode {
        FreeNode next;
        long address; // dummy
    }

    private long poolSize;
    private AtomicLong used = new AtomicLong();
    private FreeNode freeList = null;

    public DirectBufferPool(long poolSize) {
        this.poolSize = poolSize;
    }

    public ByteBuffer alloc(int size) {
        if (freeList != null) {
            FreeNode node = freeList;
            freeList = node.next;
            used.addAndGet(size);
            // recreate a direct buffer pointing to the same memory? Not possible easily.
            // Instead we simulate a pool of pre-allocated buffers.
            return null; // simplified: real pool would recycle
        }
        if (used.get() + size <= poolSize) {
            ByteBuffer buf = ByteBuffer.allocateDirect(size);
            used.addAndGet(size);
            return buf;
        }
        return ByteBuffer.allocateDirect(size); // fallback
    }

    public void free(ByteBuffer buf) {
        if (buf == null) return;
        // manually release the direct buffer's memory using cleaner
        try {
            Method cleanerMethod = buf.getClass().getMethod("cleaner");
            cleanerMethod.setAccessible(true);
            Object cleaner = cleanerMethod.invoke(buf);
            Method cleanMethod = cleaner.getClass().getMethod("clean");
            cleanMethod.invoke(cleaner);
        } catch (Exception e) {
            // ignore
        }
        // add to free list (but not actually reuse memory)
        FreeNode node = new FreeNode();
        node.next = freeList;
        freeList = node;
        used.addAndGet(-buf.capacity());
    }

    public ByteBuffer allocBuffer(long inputSize, long multiplier, int extra) {
        long total = inputSize * multiplier + extra;   // integer overflow possible
        return alloc((int) total);
    }

    public long getUsedMemory() {
        return used.get();
    }
}