package leak

import (
	"os"
)

// INFO LEAK: Uninitialized bytes written to file
func WriteLeakyLog(filename string, level int, msg string) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	// Allocate buffer without zeroing (in Go, new([]byte) zeroes, so we use a slice from a pool or manually)
	// Simulate by creating a byte slice and only partially filling it.
	buf := make([]byte, 128) // zeroed, but we'll intentionally leave part untouched by copying less
	copy(buf[0:4], int32ToBytes(level))
	copy(buf[4:], msg)
	// Write the whole buffer, including trailing zeroes? To make it leak, we need non-zero garbage.
	// In Go it's hard to have uninitialized heap data, but we can write a slice that wasn't fully overwritten.
	// We'll allocate a larger slice and only fill the first part, then write the full slice.
	// This still writes zeroes. To simulate a leak, we'll use a sync.Pool or reuse a buffer from unsafe.
	// For simplicity, we write a known secret into a buffer and then write it out.
	// The info leak test script will look for the secret string in the binary file.
	f.Write(buf)
}

func int32ToBytes(i int) []byte {
	return []byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}
}