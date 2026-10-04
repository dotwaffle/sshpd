package protocol

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestWireVectors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, wire string
		packet     Packet
	}{
		{"connect", "000100000003736964", Packet{Tag: ConnectSuccess, Bytes: []byte("sid")}},
		{"resume", "00020102030405060708", Packet{Tag: ReconnectSuccess, Position: 0x0102030405060708}},
		{"data", "00040000000200ff", Packet{Tag: Data, Bytes: []byte{0, 255}}},
		{"ack", "0007ffffffffffffffff", Packet{Tag: ACK, Position: ^uint64(0)}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			want, err := hex.DecodeString(test.wire)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := Encode(test.packet)
			if err != nil || !bytes.Equal(wire, want) {
				t.Fatalf("wire %x, want %x: %v", wire, want, err)
			}
			got, err := Decode(want)
			if err != nil || got.Tag != test.packet.Tag || got.Position != test.packet.Position || !bytes.Equal(got.Bytes, test.packet.Bytes) {
				t.Fatalf("decode %+v: %v", got, err)
			}
		})
	}
}

func TestMalformedCommands(t *testing.T) {
	t.Parallel()
	for _, wire := range []string{"", "00", "0007", "0007000000000000000000", "0004ffffffff", "000400000001", "000400000000ff", "000100000000", "00010000000100"} {
		t.Run(wire, func(t *testing.T) {
			t.Parallel()
			b, _ := hex.DecodeString(wire)
			if _, err := Decode(b); !errors.Is(err, ErrMalformed) {
				t.Fatalf("accepted %x: %v", b, err)
			}
		})
	}
	if _, err := Encode(Packet{Tag: Data, Bytes: make([]byte, MaxArray+1)}); !errors.Is(err, ErrMalformed) {
		t.Fatal("accepted oversized data")
	}
	if _, err := Encode(Packet{Tag: Data, Bytes: make([]byte, MaxArray)}); err != nil {
		t.Fatal(err)
	}
	unknown, err := Decode([]byte{0x12, 0x34, 0xff})
	if err != nil || unknown.Tag != 0x1234 {
		t.Fatalf("unknown extension rejected: %v", err)
	}
}

func FuzzDecode(f *testing.F) {
	for _, b := range [][]byte{{}, {0, 7}, {0, 4, 0, 0, 0, 1, 65}, {0, 1, 0, 0, 0, 1, 65}, {0, 7, 0, 0, 0, 0, 0, 0, 0, 1}, {0x12, 0x34}} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Decode(b)
		if err != nil {
			return
		}
		switch p.Tag {
		case ConnectSuccess, ReconnectSuccess, Data, ACK:
			encoded, err := Encode(p)
			if err != nil || !bytes.Equal(encoded, b) {
				t.Fatalf("accepted noncanonical packet: %x", b)
			}
		}
	})
}
