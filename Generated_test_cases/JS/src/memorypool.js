class MemoryPool {
    constructor(size) {
        this.buffer = Buffer.alloc(size);
        this.offset = 0;
        this.size = size;
    }

    alloc(n) {
        if (n <= 0) return null;
        const currentOffset = this.offset;
        this.offset += n;                 // VULN-4: unsynchronized write – race condition
        if (currentOffset + n > this.size) {
            // overflow or out of pool; allocate new Buffer (fallback)
            return Buffer.alloc(n);
        }
        return this.buffer.slice(currentOffset, currentOffset + n);
    }

    free(buf) {
        // no-op for simplicity; in real pool would track freed memory
    }

    // VULN-1: Integer overflow in size calculation
    allocBuffer(inputSize, multiplier, extra) {
        const total = inputSize * multiplier + extra; // overflow possible beyond Number.MAX_SAFE_INTEGER
        return this.alloc(total);
    }

    usedMemory() {
        return this.offset;
    }
}

module.exports = MemoryPool;