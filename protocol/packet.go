// Package protocol encodes the corp-relay-v4 WebSocket commands.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// MaxArray is the maximum accepted byte-array length.
const MaxArray = 16 << 10

// Tag identifies a command.
type Tag uint16

// Command tags defined by corp-relay-v4.
const (
	ConnectSuccess   Tag = 1
	ReconnectSuccess Tag = 2
	Data             Tag = 4
	ACK              Tag = 7
)

// ErrMalformed indicates an invalid command or an oversized byte array.
var ErrMalformed = errors.New("malformed relay command")

// Packet holds one command. Bytes contains DATA or the CONNECT_SUCCESS SID.
// Position contains the absolute stream offset for ACK and RECONNECT_SUCCESS.
type Packet struct {
	Tag      Tag
	Bytes    []byte
	Position uint64
}

// Decode validates known commands. Unknown tags are returned without a payload.
// Clients must ignore unknown tags, as required by the protocol.
func Decode(b []byte) (Packet, error) {
	if len(b) < 2 {
		return Packet{}, ErrMalformed
	}
	p := Packet{Tag: Tag(binary.BigEndian.Uint16(b))}
	switch p.Tag {
	case ACK, ReconnectSuccess:
		if len(b) != 10 {
			return Packet{}, ErrMalformed
		}
		p.Position = binary.BigEndian.Uint64(b[2:])
	case Data, ConnectSuccess:
		if len(b) < 6 {
			return Packet{}, ErrMalformed
		}
		n := binary.BigEndian.Uint32(b[2:])
		if n > MaxArray {
			return Packet{}, ErrMalformed
		}
		if int(n) != len(b)-6 {
			return Packet{}, ErrMalformed
		}
		p.Bytes = b[6:]
		if p.Tag == ConnectSuccess && !validSID(p.Bytes) {
			return Packet{}, ErrMalformed
		}
	}
	return p, nil
}

// Encode returns a binary command. It rejects undefined outgoing tags.
func Encode(p Packet) ([]byte, error) {
	var b []byte
	switch p.Tag {
	case ACK, ReconnectSuccess:
		b = make([]byte, 10)
		binary.BigEndian.PutUint64(b[2:], p.Position)
	case Data, ConnectSuccess:
		n := len(p.Bytes)
		if n > MaxArray || (p.Tag == ConnectSuccess && !validSID(p.Bytes)) {
			return nil, ErrMalformed
		}
		b = make([]byte, 6+len(p.Bytes))
		binary.BigEndian.PutUint32(b[2:], uint32(n))
		copy(b[6:], p.Bytes)
	default:
		return nil, fmt.Errorf("encode tag %d: %w", p.Tag, ErrMalformed)
	}
	binary.BigEndian.PutUint16(b, uint16(p.Tag))
	return b, nil
}

func validSID(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
