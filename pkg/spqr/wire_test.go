package spqr

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
)

func TestEncodeDecodeWireMessage_None(t *testing.T) {
	epoch := uint64(42)
	counter := uint32(7)
	msgType := mlkembraid.MessageTypeNone

	encoded := encodeWireMessage(epoch, counter, msgType, nil)

	decoded, err := decodeWireMessage(encoded)
	if err != nil {
		t.Fatalf("decodeWireMessage failed: %v", err)
	}

	if decoded.Epoch != epoch {
		t.Errorf("epoch: got %d, want %d", decoded.Epoch, epoch)
	}
	if decoded.Counter != counter {
		t.Errorf("counter: got %d, want %d", decoded.Counter, counter)
	}
	if decoded.MsgType != msgType {
		t.Errorf("msgType: got %d, want %d", decoded.MsgType, msgType)
	}
	if decoded.Chunk != nil {
		t.Errorf("chunk: got %v, want nil", decoded.Chunk)
	}
}

func TestEncodeDecodeWireMessage_WithChunk(t *testing.T) {
	epoch := uint64(1000)
	counter := uint32(500)
	msgType := mlkembraid.MessageTypeHdr
	chunkData := make([]byte, 33) // varint(0) + 32 bytes payload
	chunkData[0] = 0x00           // varint index 0
	for i := 1; i < 33; i++ {
		chunkData[i] = byte(i)
	}

	encoded := encodeWireMessage(epoch, counter, msgType, chunkData)

	decoded, err := decodeWireMessage(encoded)
	if err != nil {
		t.Fatalf("decodeWireMessage failed: %v", err)
	}

	if decoded.Epoch != epoch {
		t.Errorf("epoch: got %d, want %d", decoded.Epoch, epoch)
	}
	if decoded.Counter != counter {
		t.Errorf("counter: got %d, want %d", decoded.Counter, counter)
	}
	if decoded.MsgType != msgType {
		t.Errorf("msgType: got %d, want %d", decoded.MsgType, msgType)
	}
	if len(decoded.Chunk) != len(chunkData) {
		t.Fatalf("chunk length: got %d, want %d", len(decoded.Chunk), len(chunkData))
	}
	for i := range chunkData {
		if decoded.Chunk[i] != chunkData[i] {
			t.Errorf("chunk[%d]: got %d, want %d", i, decoded.Chunk[i], chunkData[i])
		}
	}
}

func TestEncodeDecodeWireMessage_AllMessageTypes(t *testing.T) {
	types := []mlkembraid.MessageType{
		mlkembraid.MessageTypeNone,
		mlkembraid.MessageTypeHdr,
		mlkembraid.MessageTypeEk,
		mlkembraid.MessageTypeEkCt1Ack,
		mlkembraid.MessageTypeCt1Ack,
		mlkembraid.MessageTypeCt1,
		mlkembraid.MessageTypeCt2,
	}

	for _, mt := range types {
		t.Run(mt.String(), func(t *testing.T) {
			var chunk []byte
			if messageTypeHasChunk(mt) {
				chunk = make([]byte, 33) // varint(0) + 32 byte payload
				chunk[0] = 0x00
				for i := 1; i < 33; i++ {
					chunk[i] = byte(i)
				}
			}

			encoded := encodeWireMessage(5, 10, mt, chunk)
			decoded, err := decodeWireMessage(encoded)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			if decoded.MsgType != mt {
				t.Errorf("msgType: got %d, want %d", decoded.MsgType, mt)
			}
		})
	}
}

func TestDecodeWireMessage_LegacyFormat(t *testing.T) {
	epoch := uint64(3)
	counter := uint32(15)
	legacy := encodeLegacyMessage(epoch, counter)

	decoded, err := decodeWireMessage(legacy)
	if err != nil {
		t.Fatalf("decodeWireMessage failed: %v", err)
	}

	if decoded.Epoch != epoch {
		t.Errorf("epoch: got %d, want %d", decoded.Epoch, epoch)
	}
	if decoded.Counter != counter {
		t.Errorf("counter: got %d, want %d", decoded.Counter, counter)
	}
	if decoded.MsgType != mlkembraid.MessageTypeNone {
		t.Errorf("msgType: got %d, want None", decoded.MsgType)
	}
	if decoded.Chunk != nil {
		t.Errorf("chunk: got %v, want nil", decoded.Chunk)
	}
}

func TestDecodeWireMessage_Empty(t *testing.T) {
	_, err := decodeWireMessage(nil)
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	if _, ok := err.(*ErrWireDecode); !ok {
		t.Errorf("expected ErrWireDecode, got %T", err)
	}
}

func TestDecodeWireMessage_BadVersion(t *testing.T) {
	data := []byte{0xFF, 0x01, 0x01, 0x00}
	_, err := decodeWireMessage(data)
	if err == nil {
		t.Fatal("expected error for bad version")
	}
	if _, ok := err.(*ErrWireDecode); !ok {
		t.Errorf("expected ErrWireDecode, got %T", err)
	}
}

func TestDecodeWireMessage_TruncatedEpoch(t *testing.T) {
	// Version byte only, no epoch varint.
	data := []byte{wireVersion}
	_, err := decodeWireMessage(data)
	if err == nil {
		t.Fatal("expected error for truncated epoch")
	}
}

func TestDecodeWireMessage_TruncatedCounter(t *testing.T) {
	// Version + valid epoch varint, but no counter.
	data := []byte{wireVersion, 0x01} // epoch = 1
	_, err := decodeWireMessage(data)
	if err == nil {
		t.Fatal("expected error for truncated counter")
	}
}

func TestDecodeWireMessage_MissingMsgType(t *testing.T) {
	// Version + epoch + counter, but no message type byte.
	data := []byte{wireVersion, 0x01, 0x01} // epoch=1, counter=1
	_, err := decodeWireMessage(data)
	if err == nil {
		t.Fatal("expected error for missing message type")
	}
}

func TestDecodeWireMessage_UnknownMsgType(t *testing.T) {
	data := []byte{wireVersion, 0x01, 0x01, 0xFF} // unknown type 0xFF
	_, err := decodeWireMessage(data)
	if err == nil {
		t.Fatal("expected error for unknown message type")
	}
}

func TestEncodeDecodeWireMessage_LargeEpochCounter(t *testing.T) {
	epoch := uint64(1<<63 - 1)
	counter := uint32(1<<32 - 1)

	encoded := encodeWireMessage(epoch, counter, mlkembraid.MessageTypeNone, nil)
	decoded, err := decodeWireMessage(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.Epoch != epoch {
		t.Errorf("epoch: got %d, want %d", decoded.Epoch, epoch)
	}
	if decoded.Counter != counter {
		t.Errorf("counter: got %d, want %d", decoded.Counter, counter)
	}
}

func TestMessageTypeHasChunk(t *testing.T) {
	cases := []struct {
		mt   mlkembraid.MessageType
		want bool
	}{
		{mlkembraid.MessageTypeNone, false},
		{mlkembraid.MessageTypeHdr, true},
		{mlkembraid.MessageTypeEk, true},
		{mlkembraid.MessageTypeEkCt1Ack, true},
		{mlkembraid.MessageTypeCt1Ack, false},
		{mlkembraid.MessageTypeCt1, true},
		{mlkembraid.MessageTypeCt2, true},
	}
	for _, tc := range cases {
		t.Run(tc.mt.String(), func(t *testing.T) {
			got := messageTypeHasChunk(tc.mt)
			if got != tc.want {
				t.Errorf("messageTypeHasChunk(%s): got %v, want %v", tc.mt, got, tc.want)
			}
		})
	}
}
