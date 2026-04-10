package mlkembraid

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
)

// --- Rust-compatible varint+32byte chunk format ---

func TestEncoderChunkWireFormat(t *testing.T) {
	// 10 bytes data -> ceil(10/32) = 1 chunk (32 bytes payload, zero-padded)
	data := []byte("abcdefghij") // 10 bytes
	chunkSize := 32

	enc, err := NewEncoder(data, chunkSize)
	if err != nil {
		t.Fatal(err)
	}

	if enc.TotalChunks() != 1 {
		t.Fatalf("TotalChunks() = %d, want 1", enc.TotalChunks())
	}

	chunk := enc.NextChunk()

	// First byte is varint(0) = 0x00.
	index, n := binary.Uvarint(chunk)
	if n <= 0 {
		t.Fatal("failed to decode varint index")
	}
	if index != 0 {
		t.Errorf("index = %d, want 0", index)
	}

	// Remaining 32 bytes should be the data zero-padded.
	payload := chunk[n:]
	if len(payload) != ChunkDataSize {
		t.Fatalf("payload size = %d, want %d", len(payload), ChunkDataSize)
	}
	if !bytes.Equal(payload[:10], data) {
		t.Errorf("payload[:10] = %q, want %q", payload[:10], data)
	}
	// Verify zero padding.
	for i := 10; i < ChunkDataSize; i++ {
		if payload[i] != 0 {
			t.Errorf("payload[%d] = %d, want 0 (zero padding)", i, payload[i])
		}
	}
}

func TestEncoderMultiChunkWireFormat(t *testing.T) {
	// 64 bytes data -> ceil(64/32) = 2 chunks.
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i)
	}

	enc, err := NewEncoder(data, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	if enc.TotalChunks() != 2 {
		t.Fatalf("TotalChunks() = %d, want 2", enc.TotalChunks())
	}

	for i := 0; i < enc.TotalChunks(); i++ {
		chunk := enc.NextChunk()

		// Decode varint index.
		index, n := binary.Uvarint(chunk)
		if n <= 0 {
			t.Fatalf("chunk %d: failed to decode varint index", i)
		}
		if index != uint64(i) {
			t.Errorf("chunk %d: index = %d, want %d", i, index, i)
		}

		// Payload must be exactly 32 bytes.
		payload := chunk[n:]
		if len(payload) != ChunkDataSize {
			t.Fatalf("chunk %d: payload size = %d, want %d", i, len(payload), ChunkDataSize)
		}

		// Verify payload content.
		start := i * ChunkDataSize
		if !bytes.Equal(payload, data[start:start+ChunkDataSize]) {
			t.Errorf("chunk %d: payload mismatch", i)
		}
	}
}

func TestEncoderChunkPayloadContent(t *testing.T) {
	data := []byte("ABCDE") // 5 bytes -> 1 chunk, zero-padded to 32

	enc, err := NewEncoder(data, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	chunk0 := enc.NextChunk()

	// Decode varint index.
	_, n := binary.Uvarint(chunk0)
	payload := chunk0[n:]

	if !bytes.Equal(payload[:5], []byte("ABCDE")) {
		t.Errorf("chunk 0 payload[:5] = %q, want %q", payload[:5], "ABCDE")
	}
	// Remaining 27 bytes should be zero.
	for i := 5; i < ChunkDataSize; i++ {
		if payload[i] != 0 {
			t.Errorf("payload[%d] = %d, want 0", i, payload[i])
		}
	}
}

// --- Out-of-order delivery ---

func TestDecoderOutOfOrderDelivery(t *testing.T) {
	data := []byte("hello world, erasure coding test!")
	chunkSize := DefaultChunkSize

	enc, err := NewEncoder(data, chunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// Collect all chunks.
	chunks := make([][]byte, 0, enc.TotalChunks())
	for enc.HasMore() {
		chunks = append(chunks, enc.NextChunk())
	}

	// Deliver in reverse order.
	dec, err := NewDecoder(len(data), chunkSize)
	if err != nil {
		t.Fatal(err)
	}

	for i := len(chunks) - 1; i >= 0; i-- {
		if err := dec.AddChunk(chunks[i]); err != nil {
			t.Fatalf("AddChunk(%d) error: %v", i, err)
		}
	}

	if !dec.HasMessage() {
		t.Fatal("decoder should be complete after reverse-order delivery")
	}

	result, err := dec.Message()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, data) {
		t.Errorf("reverse-order reconstruction failed: got %q, want %q", result, data)
	}
}

func TestDecoderRandomOrderDelivery(t *testing.T) {
	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i)
	}
	chunkSize := DefaultChunkSize

	enc, err := NewEncoder(data, chunkSize)
	if err != nil {
		t.Fatal(err)
	}

	chunks := make([][]byte, 0, enc.TotalChunks())
	for enc.HasMore() {
		chunks = append(chunks, enc.NextChunk())
	}

	// Shuffle using deterministic seed for reproducibility.
	rng := rand.New(rand.NewSource(42))
	rng.Shuffle(len(chunks), func(i, j int) {
		chunks[i], chunks[j] = chunks[j], chunks[i]
	})

	dec, err := NewDecoder(len(data), chunkSize)
	if err != nil {
		t.Fatal(err)
	}

	for _, chunk := range chunks {
		if err := dec.AddChunk(chunk); err != nil {
			t.Fatal(err)
		}
	}

	if !dec.HasMessage() {
		t.Fatal("decoder should be complete after random-order delivery")
	}

	result, err := dec.Message()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, data) {
		t.Error("random-order reconstruction failed")
	}
}

// --- Duplicate chunk handling ---

func TestDecoderDuplicateChunksIgnored(t *testing.T) {
	data := []byte("duplicate test data for chunk test")

	enc, err := NewEncoder(data, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	chunks := make([][]byte, 0, enc.TotalChunks())
	for enc.HasMore() {
		chunks = append(chunks, enc.NextChunk())
	}

	dec, err := NewDecoder(len(data), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// Send each chunk three times.
	for _, chunk := range chunks {
		for dup := 0; dup < 3; dup++ {
			if err := dec.AddChunk(chunk); err != nil {
				t.Fatal(err)
			}
		}
	}

	if dec.ReceivedCount() != enc.TotalChunks() {
		t.Errorf("ReceivedCount() = %d, want %d (duplicates should be ignored)",
			dec.ReceivedCount(), enc.TotalChunks())
	}

	result, err := dec.Message()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, data) {
		t.Error("reconstruction with duplicates failed")
	}
}

// --- Chunk format validation ---

func TestDecoderRejectsEmptyChunk(t *testing.T) {
	dec, err := NewDecoder(32, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	err = dec.AddChunk([]byte{})
	if err == nil {
		t.Fatal("expected error for empty chunk")
	}
	if _, ok := err.(*ErrChunkFormat); !ok {
		t.Errorf("expected ErrChunkFormat, got %T", err)
	}
}

func TestDecoderRejectsInvalidVarintIndex(t *testing.T) {
	dec, err := NewDecoder(32, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// A chunk with only continuation bytes (no termination) is invalid varint.
	chunk := make([]byte, 33)
	for i := range chunk {
		chunk[i] = 0x80 // all continuation bits
	}
	err = dec.AddChunk(chunk)
	if err == nil {
		t.Fatal("expected error for invalid varint")
	}
	if _, ok := err.(*ErrChunkFormat); !ok {
		t.Errorf("expected ErrChunkFormat, got %T", err)
	}
}

func TestDecoderRejectsWrongDataSize(t *testing.T) {
	dec, err := NewDecoder(32, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// varint(0) = 0x00, but only 5 bytes of data (not 32).
	chunk := []byte{0x00, 1, 2, 3, 4, 5}
	err = dec.AddChunk(chunk)
	if err == nil {
		t.Fatal("expected error for wrong data size")
	}
	if _, ok := err.(*ErrChunkFormat); !ok {
		t.Errorf("expected ErrChunkFormat, got %T", err)
	}
}

func TestDecoderRejectsIndexOutOfRange(t *testing.T) {
	// 32 bytes data -> 1 chunk. Index 5 is out of range.
	dec, err := NewDecoder(32, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// Build a valid wire chunk with index=5.
	var varintBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(varintBuf[:], 5)
	chunk := make([]byte, n+ChunkDataSize)
	copy(chunk[:n], varintBuf[:n])

	err = dec.AddChunk(chunk)
	if err == nil {
		t.Fatal("expected error for index out of range")
	}
	if _, ok := err.(*ErrChunkFormat); !ok {
		t.Errorf("expected ErrChunkFormat, got %T", err)
	}
}

// --- Encoder validation ---

func TestEncoderRejectsEmptyData(t *testing.T) {
	_, err := NewEncoder([]byte{}, DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for empty data")
	}
	if _, ok := err.(*ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestDecoderRejectsNonPositiveSize(t *testing.T) {
	_, err := NewDecoder(0, DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for zero expectedSize")
	}
	if _, ok := err.(*ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}

	_, err = NewDecoder(-1, DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for negative expectedSize")
	}
}

// --- Round-trip with various data sizes ---

func TestEncoderDecoderRoundTripVariousSizes(t *testing.T) {
	sizes := []struct {
		name     string
		dataSize int
	}{
		{"tiny_1byte", 1},
		{"small_10bytes", 10},
		{"medium_100bytes", 100},
		{"header_size", HeaderSize + MacSize},
		{"ek_vector", MLKEM768EKSize},
		{"ct1_size", MLKEM768CT1Size},
		{"ct2_with_mac", MLKEM768CT2Size + MacSize},
		{"exact_32bytes", 32},
		{"exact_64bytes", 64},
		{"large_500bytes", 500},
	}

	for _, tc := range sizes {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, tc.dataSize)
			for i := range data {
				data[i] = byte(i & 0xFF)
			}

			enc, err := NewEncoder(data, DefaultChunkSize)
			if err != nil {
				t.Fatal(err)
			}

			dec, err := NewDecoder(tc.dataSize, DefaultChunkSize)
			if err != nil {
				t.Fatal(err)
			}

			for enc.HasMore() {
				if err := dec.AddChunk(enc.NextChunk()); err != nil {
					t.Fatal(err)
				}
			}

			if !dec.HasMessage() {
				t.Fatal("decoder not complete")
			}

			result, err := dec.Message()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(result, data) {
				t.Errorf("round trip failed for %s", tc.name)
			}
		})
	}
}

// --- Encoder wraparound with varint indices ---

func TestEncoderWraparoundProducesCorrectIndices(t *testing.T) {
	data := make([]byte, 64) // 2 chunks
	for i := range data {
		data[i] = byte(i)
	}

	enc, err := NewEncoder(data, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	decodeIndex := func(chunk []byte) uint64 {
		idx, n := binary.Uvarint(chunk)
		if n <= 0 {
			t.Fatal("failed to decode varint")
		}
		return idx
	}

	// First pass: chunks 0, 1.
	c0 := enc.NextChunk()
	c1 := enc.NextChunk()
	if decodeIndex(c0) != 0 {
		t.Errorf("first pass chunk 0: index = %d, want 0", decodeIndex(c0))
	}
	if decodeIndex(c1) != 1 {
		t.Errorf("first pass chunk 1: index = %d, want 1", decodeIndex(c1))
	}

	if enc.HasMore() {
		t.Error("encoder should not have more after first pass")
	}

	// Wraparound: chunks 0, 1 again.
	c2 := enc.NextChunk()
	c3 := enc.NextChunk()
	if decodeIndex(c2) != 0 {
		t.Errorf("wraparound chunk 0: index = %d, want 0", decodeIndex(c2))
	}
	if decodeIndex(c3) != 1 {
		t.Errorf("wraparound chunk 1: index = %d, want 1", decodeIndex(c3))
	}
}

// --- Decoder Reset clears state ---

func TestDecoderResetClearsState(t *testing.T) {
	dec, err := NewDecoder(32, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// Build a valid chunk: varint(0) + 32 zero bytes.
	chunk := make([]byte, 1+ChunkDataSize) // varint(0) = 0x00
	if err := dec.AddChunk(chunk); err != nil {
		t.Fatal(err)
	}

	if dec.ReceivedCount() != 1 {
		t.Fatalf("ReceivedCount() = %d, want 1", dec.ReceivedCount())
	}

	dec.Reset()

	if dec.ReceivedCount() != 0 {
		t.Errorf("after reset, ReceivedCount() = %d, want 0", dec.ReceivedCount())
	}
	if dec.HasMessage() {
		t.Error("after reset, HasMessage() should be false")
	}

	// After reset, first chunk should be accepted again.
	if err := dec.AddChunk(chunk); err != nil {
		t.Fatal(err)
	}
	if dec.ReceivedCount() != 1 {
		t.Errorf("after re-add, ReceivedCount() = %d, want 1", dec.ReceivedCount())
	}
}

// --- Error type coverage ---

func TestErrChunkFormatError(t *testing.T) {
	err := &ErrChunkFormat{Reason: "test reason"}
	if err.Error() == "" {
		t.Error("error string should not be empty")
	}
}

func TestErrChunkIndexError(t *testing.T) {
	err := &ErrChunkIndex{Index: 10, Total: 5}
	if err.Error() == "" {
		t.Error("error string should not be empty")
	}
}

func TestErrChunkCountError(t *testing.T) {
	err := &ErrChunkCount{Count: 300, Max: 255}
	if err.Error() == "" {
		t.Error("error string should not be empty")
	}
}

// --- Out-of-order delivery with protocol-realistic sizes ---

func TestOutOfOrderHeaderChunks(t *testing.T) {
	// Simulate header + mac = 96 bytes with DefaultChunkSize=32.
	payload := make([]byte, HeaderSize+MacSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	enc, err := NewEncoder(payload, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	chunks := make([][]byte, 0, enc.TotalChunks())
	for enc.HasMore() {
		chunks = append(chunks, enc.NextChunk())
	}

	// Deliver in reverse.
	dec, err := NewDecoder(len(payload), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	for i := len(chunks) - 1; i >= 0; i-- {
		if err := dec.AddChunk(chunks[i]); err != nil {
			t.Fatal(err)
		}
	}

	if !dec.HasMessage() {
		t.Fatal("decoder should be complete")
	}

	result, err := dec.Message()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, payload) {
		t.Error("header reconstruction failed with reverse-order delivery")
	}
}

func TestOutOfOrderEkVectorChunks(t *testing.T) {
	// ek_vector = 1152 bytes with DefaultChunkSize=32.
	payload := make([]byte, MLKEM768EKSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	enc, err := NewEncoder(payload, DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	chunks := make([][]byte, 0, enc.TotalChunks())
	for enc.HasMore() {
		chunks = append(chunks, enc.NextChunk())
	}

	// Shuffle deterministically.
	rng := rand.New(rand.NewSource(99))
	rng.Shuffle(len(chunks), func(i, j int) {
		chunks[i], chunks[j] = chunks[j], chunks[i]
	})

	dec, err := NewDecoder(len(payload), DefaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	for _, chunk := range chunks {
		if err := dec.AddChunk(chunk); err != nil {
			t.Fatal(err)
		}
	}

	result, err := dec.Message()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, payload) {
		t.Error("ek_vector reconstruction failed with shuffled delivery")
	}
}

// --- SCKA message serialization round-trip ---

func TestSCKASerializeDeserializeRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		epoch      uint64
		msgType    MessageType
		chainIndex uint32
		hasChunk   bool
	}{
		{"none_msg", 1, MessageTypeNone, 0, false},
		{"ct1_ack", 3, MessageTypeCt1Ack, 42, false},
		{"hdr_chunk", 1, MessageTypeHdr, 0, true},
		{"ek_chunk", 2, MessageTypeEk, 5, true},
		{"ek_ct1_ack", 4, MessageTypeEkCt1Ack, 100, true},
		{"ct1_chunk", 5, MessageTypeCt1, 999, true},
		{"ct2_chunk", 6, MessageTypeCt2, 65535, true},
		{"large_epoch", 1<<32 + 1, MessageTypeHdr, 0, true},
		{"large_chain_index", 1, MessageTypeCt1, ^uint32(0), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var data []byte
			if tc.hasChunk {
				// Build a valid chunk wire: varint(7) + 32 bytes.
				var buf [binary.MaxVarintLen64]byte
				n := binary.PutUvarint(buf[:], 7)
				data = make([]byte, n+ChunkDataSize)
				copy(data[:n], buf[:n])
				for i := n; i < len(data); i++ {
					data[i] = byte(i)
				}
			}

			msg := &Message{
				Epoch: tc.epoch,
				Type:  tc.msgType,
				Data:  data,
			}

			serialized := msg.SerializeSCKA(tc.chainIndex)

			// Verify version byte.
			if serialized[0] != SPQRVersion {
				t.Errorf("version byte = %d, want %d", serialized[0], SPQRVersion)
			}

			// Deserialize and verify round-trip.
			restored, chainIdx, err := DeserializeSCKA(serialized)
			if err != nil {
				t.Fatalf("DeserializeSCKA error: %v", err)
			}

			if restored.Epoch != tc.epoch {
				t.Errorf("epoch = %d, want %d", restored.Epoch, tc.epoch)
			}
			if restored.Type != tc.msgType {
				t.Errorf("type = %d, want %d", restored.Type, tc.msgType)
			}
			if chainIdx != tc.chainIndex {
				t.Errorf("chainIndex = %d, want %d", chainIdx, tc.chainIndex)
			}
			if !bytes.Equal(restored.Data, msg.Data) {
				t.Errorf("data mismatch")
			}
		})
	}
}

func TestSCKADeserializeRejectsEmptyInput(t *testing.T) {
	_, _, err := DeserializeSCKA([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	if _, ok := err.(*ErrSCKADecode); !ok {
		t.Errorf("expected ErrSCKADecode, got %T", err)
	}
}

func TestSCKADeserializeRejectsBadVersion(t *testing.T) {
	_, _, err := DeserializeSCKA([]byte{0xFF, 0x01, 0x00, 0x00})
	if err == nil {
		t.Fatal("expected error for bad version")
	}
	if _, ok := err.(*ErrSCKADecode); !ok {
		t.Errorf("expected ErrSCKADecode, got %T", err)
	}
}

func TestSCKADeserializeRejectsZeroEpoch(t *testing.T) {
	// version=1, epoch=0 (varint), chain_index=0, msg_type=0
	_, _, err := DeserializeSCKA([]byte{0x01, 0x00, 0x00, 0x00})
	if err == nil {
		t.Fatal("expected error for zero epoch")
	}
	if _, ok := err.(*ErrSCKADecode); !ok {
		t.Errorf("expected ErrSCKADecode, got %T", err)
	}
}

// --- uitoa helper ---

func TestUitoa(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{255, "255"},
		{65535, "65535"},
	}
	for _, tc := range tests {
		got := uitoa(tc.input)
		if got != tc.want {
			t.Errorf("uitoa(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
