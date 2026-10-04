package replay

import (
	"errors"
	"math"
	"testing"
)

func TestPartialAcknowledgmentAndRewind(t *testing.T) {
	t.Parallel()
	var b Buffer
	capacity, ok := b.RequiredCapacity(6, 256)
	if !ok {
		t.Fatal("capacity")
	}
	b.Append([]byte("abcdef"), capacity)
	if err := b.Acknowledge(2); err != nil {
		t.Fatal(err)
	}
	for _, pos := range []uint64{0, 1, 7, math.MaxUint64} {
		if err := b.Acknowledge(pos); !errors.Is(err, ErrPosition) {
			t.Fatalf("accepted position %d", pos)
		}
	}
	p, err := b.ReadAt(3, 2)
	if err != nil || string(p) != "de" {
		t.Fatalf("replay %q: %v", p, err)
	}
	if b.Base() != 2 || b.End() != 6 || b.Capacity() == 0 {
		t.Fatalf("range %d..%d capacity %d", b.Base(), b.End(), b.Capacity())
	}
	if err := b.Acknowledge(6); err != nil {
		t.Fatal(err)
	}
	if b.Capacity() != 0 || b.End() != 6 {
		t.Fatal("empty buffer did not release allocation")
	}
	capacity, ok = b.RequiredCapacity(1, 1)
	if !ok || capacity != 1 {
		t.Fatal("small cap")
	}
	b.Append([]byte("g"), capacity)
	if _, ok := b.RequiredCapacity(1, 1); ok {
		t.Fatal("exceeded cap")
	}
	if _, err := b.ReadAt(6, -1); !errors.Is(err, ErrPosition) {
		t.Fatal("negative read size accepted")
	}
}

func TestCounterOverflow(t *testing.T) {
	t.Parallel()
	b := Buffer{base: math.MaxUint64}
	if _, ok := b.RequiredCapacity(1, 128); ok {
		t.Fatal("stream counter wrapped")
	}
}
