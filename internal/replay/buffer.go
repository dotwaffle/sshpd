// Package replay retains bytes until their absolute offsets are acknowledged.
package replay

import (
	"errors"
	"math"
)

// ErrPosition indicates an acknowledgment outside the retained stream range.
var ErrPosition = errors.New("invalid replay position")

// Buffer is not safe for concurrent use. The owner accounts for Capacity.
type Buffer struct {
	base uint64
	data []byte
}

// Base is the first retained byte offset.
func (b *Buffer) Base() uint64 { return b.base }

// End is the offset after the last retained byte.
func (b *Buffer) End() uint64 { return b.base + uint64(len(b.data)) }

// Len is the number of retained bytes.
func (b *Buffer) Len() int { return len(b.data) }

// Capacity is the allocation held by this buffer.
func (b *Buffer) Capacity() int { return cap(b.data) }

// Allocated reports capacity as a byte count for memory-pressure accounting.
func (b *Buffer) Allocated() uint64 { return uint64(cap(b.data)) }

// RequiredCapacity calculates growth without allocating. Limit bounds capacity.
func (b *Buffer) RequiredCapacity(n, limit int) (int, bool) {
	if n < 0 || n > limit-len(b.data) || uint64(n) > math.MaxUint64-b.End() {
		return 0, false
	}
	need := len(b.data) + n
	if need <= cap(b.data) {
		return cap(b.data), true
	}
	c := max(128, cap(b.data))
	for c < need {
		if c > limit/2 {
			c = limit
			break
		}
		c *= 2
	}
	return min(c, limit), true
}

// Append adds bytes with the capacity previously approved by the owner.
func (b *Buffer) Append(p []byte, capacity int) {
	if capacity > cap(b.data) {
		next := make([]byte, len(b.data), capacity)
		copy(next, b.data)
		b.data = next
	}
	b.data = append(b.data, p...)
}

// Acknowledge discards bytes before pos and releases empty buffers.
func (b *Buffer) Acknowledge(pos uint64) error {
	if pos < b.base || pos > b.End() {
		return ErrPosition
	}
	offset := pos - b.base
	if offset > math.MaxInt {
		return ErrPosition
	}
	n := int(offset)
	copy(b.data, b.data[n:])
	b.data = b.data[:len(b.data)-n]
	b.base = pos
	if len(b.data) == 0 {
		b.data = nil
	}
	return nil
}

// ReadAt copies at most size retained bytes starting at pos.
func (b *Buffer) ReadAt(pos uint64, size int) ([]byte, error) {
	if size < 0 || pos < b.base || pos > b.End() {
		return nil, ErrPosition
	}
	offset := pos - b.base
	if offset > math.MaxInt {
		return nil, ErrPosition
	}
	i := int(offset)
	n := min(size, len(b.data)-i)
	return append([]byte(nil), b.data[i:i+n]...), nil
}
