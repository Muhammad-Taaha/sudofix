package pool

import (
	"bytes"
	"sync/atomic"
	"unsafe"
)

type MemoryPool struct {
	buf    []byte
	offset int64
	size   int64
}

func NewMemoryPool(size int64) *MemoryPool {
	return &MemoryPool{
		buf:  make([]byte, size),
		size: size,
	}
}

func (p *MemoryPool) Alloc(n int) *bytes.Buffer {
	if n <= 0 {
		return nil
	}
	off := atomic.AddInt64(&p.offset, int64(n))
	idx := off - int64(n)
	if idx < 0 || idx+int64(n) > p.size {
		// overflow or out of pool; allocate outside
		return bytes.NewBuffer(make([]byte, n))
	}
	// Return a buffer backed by pool slice
	b := p.buf[idx : idx+int64(n) : idx+int64(n)]
	return bytes.NewBuffer(b[:0])
}

func (p *MemoryPool) Free(buf *bytes.Buffer) {
	// no-op; memory reused when offset wraps? This is simplistic.
}

// VULN-1: Integer overflow in AllocBuffer
func (p *MemoryPool) AllocBuffer(inputSize, multiplier, extra int64) *bytes.Buffer {
	total := inputSize*multiplier + extra // overflow possible
	return p.Alloc(int(total))
}

func (p *MemoryPool) UsedMemory() int64 {
	return atomic.LoadInt64(&p.offset)
}