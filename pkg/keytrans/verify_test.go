package keytrans

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestErrorTypes(t *testing.T) {
	t.Run("errRequiredFieldMissing", func(t *testing.T) {
		err := errRequiredFieldMissing("field_name")
		if err.Error() != "required field 'field_name' not found" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("errBadData", func(t *testing.T) {
		err := errBadData("bad data reason")
		if err.Error() != "bad data: bad data reason" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("errVerificationFailed", func(t *testing.T) {
		err := errVerificationFailed("verify reason")
		if err.Error() != "verification failed: verify reason" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("unknown error kind", func(t *testing.T) {
		err := &Error{kind: errorKind(99), message: "raw message"}
		if err.Error() != "raw message" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}

func TestQualifierString(t *testing.T) {
	tests := []struct {
		q    qualifier
		want string
	}{
		{qualifierServer, "Server"},
		{qualifierValidator, "Validator"},
		{qualifier(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.q.String(); got != tt.want {
			t.Errorf("qualifier(%d).String() = %q, want %q", tt.q, got, tt.want)
		}
	}
}

func TestGetHashProof(t *testing.T) {
	t.Run("valid proof", func(t *testing.T) {
		proof := [][]byte{make([]byte, 32), make([]byte, 32)}
		result, err := getHashProof(proof)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 2 {
			t.Errorf("expected 2 elements, got %d", len(result))
		}
	})

	t.Run("wrong element size", func(t *testing.T) {
		proof := [][]byte{make([]byte, 16)}
		_, err := getHashProof(proof)
		if err == nil {
			t.Fatal("expected error for wrong element size")
		}
	})

	t.Run("empty proof", func(t *testing.T) {
		result, err := getHashProof(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 0 {
			t.Errorf("expected empty result, got %d elements", len(result))
		}
	})
}

func TestMarshalUpdateValue(t *testing.T) {
	t.Run("normal value", func(t *testing.T) {
		value := []byte("hello")
		buf, err := marshalUpdateValue(value)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should be 4 bytes length + value
		if len(buf) != 4+len(value) {
			t.Errorf("expected %d bytes, got %d", 4+len(value), len(buf))
		}
		// Check big-endian length prefix
		l := uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
		if l != uint32(len(value)) {
			t.Errorf("length prefix = %d, want %d", l, len(value))
		}
	})

	t.Run("empty value", func(t *testing.T) {
		buf, err := marshalUpdateValue(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(buf) != 4 {
			t.Errorf("expected 4 bytes, got %d", len(buf))
		}
	})
}

func TestVerifyLeafHash(t *testing.T) {
	prefixRoot := &[32]byte{1, 2, 3}
	commitment := &[32]byte{4, 5, 6}

	result := verifyLeafHash(prefixRoot, commitment)
	expected := sha256Sum(prefixRoot[:], commitment[:])
	if result != expected {
		t.Error("verifyLeafHash should return sha256 of prefix root and commitment")
	}
}

func TestSha256Sum(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		h1 := sha256Sum([]byte("hello"), []byte("world"))
		h2 := sha256Sum([]byte("hello"), []byte("world"))
		if h1 != h2 {
			t.Fatal("same inputs should produce same hash")
		}
	})

	t.Run("different inputs", func(t *testing.T) {
		h1 := sha256Sum([]byte("hello"))
		h2 := sha256Sum([]byte("world"))
		if h1 == h2 {
			t.Fatal("different inputs should produce different hash")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		h := sha256Sum()
		if h == [32]byte{} {
			t.Fatal("sha256 of empty should not be all zeros")
		}
	})
}

func TestWrapLogError(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		if wrapLogError(nil) != nil {
			t.Error("wrapping nil should return nil")
		}
	})

	t.Run("non-nil error", func(t *testing.T) {
		err := wrapLogError(logMalformedProof())
		if err == nil {
			t.Fatal("wrapping non-nil should return non-nil")
		}
	})
}

func TestWrapPrefixError(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		if wrapPrefixError(nil) != nil {
			t.Error("wrapping nil should return nil")
		}
	})

	t.Run("non-nil error", func(t *testing.T) {
		err := wrapPrefixError(ErrMalformedPrefixProof)
		if err == nil {
			t.Fatal("wrapping non-nil should return non-nil")
		}
	})
}

func TestIntoSortedPairsHash(t *testing.T) {
	m := map[uint64][32]byte{
		30: {3},
		10: {1},
		20: {2},
	}
	keys, values := intoSortedPairsHash(m)
	if len(keys) != 3 || len(values) != 3 {
		t.Fatalf("expected 3 pairs, got %d keys and %d values", len(keys), len(values))
	}
	if keys[0] != 10 || keys[1] != 20 || keys[2] != 30 {
		t.Errorf("keys not sorted: %v", keys)
	}
	if values[0] != ([32]byte{1}) || values[1] != ([32]byte{2}) || values[2] != ([32]byte{3}) {
		t.Error("values don't match sorted keys")
	}
}

func TestHashesToSlice(t *testing.T) {
	hashes := [][32]byte{{1}, {2}, {3}}
	result := hashesToSlice(hashes)
	if len(result) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(result))
	}
}

func TestVerifyTimestamp(t *testing.T) {
	now := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	nowMs := now.UnixMilli()

	t.Run("valid timestamp", func(t *testing.T) {
		err := verifyTimestamp(qualifierServer, nowMs, &timestampRange{
			maxBehind: 24 * time.Hour,
			maxAhead:  60 * time.Second,
		}, now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("too far behind", func(t *testing.T) {
		oldTimestamp := nowMs - int64(48*time.Hour/time.Millisecond)
		err := verifyTimestamp(qualifierServer, oldTimestamp, &timestampRange{
			maxBehind: 24 * time.Hour,
			maxAhead:  60 * time.Second,
		}, now)
		if err == nil {
			t.Fatal("expected error for timestamp too far behind")
		}
	})

	t.Run("too far ahead", func(t *testing.T) {
		futureTimestamp := nowMs + int64(120*time.Second/time.Millisecond)
		err := verifyTimestamp(qualifierServer, futureTimestamp, &timestampRange{
			maxBehind: 24 * time.Hour,
			maxAhead:  60 * time.Second,
		}, now)
		if err == nil {
			t.Fatal("expected error for timestamp too far ahead")
		}
	})
}

func TestCheckAndVerifyConsistency(t *testing.T) {
	t.Run("nil baseline with no proof", func(t *testing.T) {
		current := &TreeHead{TreeSize: 10, Timestamp: 100}
		root := &[32]byte{1}
		err := checkAndVerifyConsistency(current, root, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("nil baseline with proof", func(t *testing.T) {
		current := &TreeHead{TreeSize: 10, Timestamp: 100}
		root := &[32]byte{1}
		err := checkAndVerifyConsistency(current, root, [][32]byte{{2}}, nil)
		if err == nil {
			t.Fatal("expected error when proof provided but baseline is nil")
		}
	})

	t.Run("same size different root", func(t *testing.T) {
		root := &[32]byte{1}
		baseline := &LastTreeHead{
			Head: TreeHead{TreeSize: 10, Timestamp: 100},
			Root: [32]byte{2},
		}
		current := &TreeHead{TreeSize: 10, Timestamp: 100}
		err := checkAndVerifyConsistency(current, root, nil, baseline)
		if err == nil {
			t.Fatal("expected error for same size different root")
		}
	})

	t.Run("same size different timestamp", func(t *testing.T) {
		root := [32]byte{1}
		baseline := &LastTreeHead{
			Head: TreeHead{TreeSize: 10, Timestamp: 100},
			Root: root,
		}
		current := &TreeHead{TreeSize: 10, Timestamp: 200}
		err := checkAndVerifyConsistency(current, &root, nil, baseline)
		if err == nil {
			t.Fatal("expected error for same size different timestamp")
		}
	})

	t.Run("same size with unnecessary proof", func(t *testing.T) {
		root := [32]byte{1}
		baseline := &LastTreeHead{
			Head: TreeHead{TreeSize: 10, Timestamp: 100},
			Root: root,
		}
		current := &TreeHead{TreeSize: 10, Timestamp: 100}
		err := checkAndVerifyConsistency(current, &root, [][32]byte{{2}}, baseline)
		if err == nil {
			t.Fatal("expected error for unnecessary proof")
		}
	})

	t.Run("same size same root", func(t *testing.T) {
		root := [32]byte{1}
		baseline := &LastTreeHead{
			Head: TreeHead{TreeSize: 10, Timestamp: 100},
			Root: root,
		}
		current := &TreeHead{TreeSize: 10, Timestamp: 100}
		err := checkAndVerifyConsistency(current, &root, nil, baseline)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("current smaller than baseline", func(t *testing.T) {
		root := &[32]byte{1}
		baseline := &LastTreeHead{
			Head: TreeHead{TreeSize: 20, Timestamp: 200},
			Root: [32]byte{2},
		}
		current := &TreeHead{TreeSize: 10, Timestamp: 100}
		err := checkAndVerifyConsistency(current, root, nil, baseline)
		if err == nil {
			t.Fatal("expected error for current smaller than baseline")
		}
	})

	t.Run("current older timestamp than baseline", func(t *testing.T) {
		root := &[32]byte{1}
		baseline := &LastTreeHead{
			Head: TreeHead{TreeSize: 10, Timestamp: 200},
			Root: [32]byte{2},
		}
		current := &TreeHead{TreeSize: 20, Timestamp: 100}
		err := checkAndVerifyConsistency(current, root, nil, baseline)
		if err == nil {
			t.Fatal("expected error for current with older timestamp")
		}
	})
}

func TestMonitoringDataWrapper(t *testing.T) {
	t.Run("nil data", func(t *testing.T) {
		mdw := newMonitoringDataWrapper(nil)
		if mdw.intoDataUpdate() != nil {
			t.Error("nil data should produce nil update")
		}
	})

	t.Run("with data", func(t *testing.T) {
		data := &MonitoringData{
			Index: [32]byte{1},
			Pos:   5,
			Ptrs:  map[uint64]uint32{1: 1},
		}
		mdw := newMonitoringDataWrapper(data)
		update := mdw.intoDataUpdate()
		if update == nil {
			t.Fatal("should have update for non-nil data")
		}
		// Should be a clone
		update.Ptrs[1] = 99
		if data.Ptrs[1] == 99 {
			t.Error("wrapper should clone the data")
		}
	})
}

func TestStartMonitoring(t *testing.T) {
	t.Run("initializes from nil", func(t *testing.T) {
		mdw := newMonitoringDataWrapper(nil)
		index := &[32]byte{1}
		mdw.startMonitoring(index, 0, 5, 1, true)
		data := mdw.intoDataUpdate()
		if data == nil {
			t.Fatal("should have data after startMonitoring")
		}
		if data.Pos != 0 {
			t.Errorf("expected Pos 0, got %d", data.Pos)
		}
		if !data.Owned {
			t.Error("expected Owned=true")
		}
	})

	t.Run("does not overwrite existing", func(t *testing.T) {
		existing := &MonitoringData{
			Index: [32]byte{2},
			Pos:   10,
			Ptrs:  map[uint64]uint32{10: 2},
		}
		mdw := newMonitoringDataWrapper(existing)
		index := &[32]byte{1}
		mdw.startMonitoring(index, 0, 5, 1, true)
		data := mdw.intoDataUpdate()
		// Should keep existing data since inner was non-nil
		if data.Pos != 10 {
			t.Errorf("expected Pos 10 (existing), got %d", data.Pos)
		}
	})
}

func TestVerifyDistinguished(t *testing.T) {
	t.Run("nil tree head", func(t *testing.T) {
		err := VerifyDistinguished(&FullTreeHead{}, nil, nil)
		if err == nil {
			t.Fatal("expected error for nil tree head")
		}
	})

	t.Run("nil last tree head", func(t *testing.T) {
		fth := &FullTreeHead{TreeHead: &TreeHead{TreeSize: 10}}
		err := VerifyDistinguished(fth, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v (nil lastTreeHead should be ok)", err)
		}
	})

	t.Run("size mismatch", func(t *testing.T) {
		fth := &FullTreeHead{TreeHead: &TreeHead{TreeSize: 10}}
		lth := &LastTreeHead{Head: TreeHead{TreeSize: 20}}
		err := VerifyDistinguished(fth, lth, nil)
		if err == nil {
			t.Fatal("expected error for size mismatch")
		}
	})
}

func TestEvaluateVRFProof(t *testing.T) {
	basePoint := [32]byte{
		0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	}
	vrfKey, err := NewVRFPublicKey(basePoint)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("wrong proof length", func(t *testing.T) {
		_, err = evaluateVRFProof(make([]byte, 50), vrfKey, []byte("test"))
		if err == nil {
			t.Fatal("expected error for wrong proof length")
		}
	})

	t.Run("valid length but invalid proof", func(t *testing.T) {
		_, err = evaluateVRFProof(make([]byte, 80), vrfKey, []byte("test"))
		// Should fail VRF verification
		if err == nil {
			t.Fatal("expected error for invalid proof")
		}
	})
}

func TestToSingleSignatureTreeHeads(t *testing.T) {
	t.Run("no associated keys", func(t *testing.T) {
		config := &PublicConfig{Mode: ContactMonitoring()}
		th := &TreeHead{TreeSize: 10, Signatures: []Signature{{SignatureBytes: make([]byte, 64)}}}
		result, err := toSingleSignatureTreeHeads(th, config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Error("no associated keys should return nil")
		}
	})

	t.Run("missing signature for key", func(t *testing.T) {
		key := make(ed25519.PublicKey, 32)
		key[0] = 1
		config := &PublicConfig{Mode: ThirdPartyManagement([]ed25519.PublicKey{key})}
		th := &TreeHead{TreeSize: 10, Signatures: []Signature{}}
		_, err := toSingleSignatureTreeHeads(th, config)
		if err == nil {
			t.Fatal("expected error when signature not found")
		}
	})

	t.Run("matching signature found", func(t *testing.T) {
		key := make(ed25519.PublicKey, 32)
		key[0] = 1
		config := &PublicConfig{Mode: ThirdPartyManagement([]ed25519.PublicKey{key})}
		th := &TreeHead{
			TreeSize:  10,
			Timestamp: 100,
			Signatures: []Signature{
				{AuditorPublicKey: key, SignatureBytes: make([]byte, 64)},
			},
		}
		result, err := toSingleSignatureTreeHeads(th, config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("expected 1 result, got %d", len(result))
		}
	})
}

func TestSelectAuditorTreeHead(t *testing.T) {
	key1 := ed25519.PublicKey{1}
	key2 := ed25519.PublicKey{2}

	fth := &FullTreeHead{
		FullAuditorTreeHeads: []FullAuditorTreeHead{
			{PublicKey: key1, TreeHead: &AuditorTreeHead{TreeSize: 10}},
		},
	}

	t.Run("found", func(t *testing.T) {
		result := selectAuditorTreeHead(fth, key1)
		if result == nil {
			t.Fatal("expected to find auditor tree head")
		}
	})

	t.Run("not found", func(t *testing.T) {
		result := selectAuditorTreeHead(fth, key2)
		if result != nil {
			t.Error("should not find non-existent key")
		}
	})
}

func TestAuditorTreeHeads(t *testing.T) {
	key1 := ed25519.PublicKey{1}
	key2 := ed25519.PublicKey{2}

	fth := &FullTreeHead{
		FullAuditorTreeHeads: []FullAuditorTreeHead{
			{PublicKey: key1, TreeHead: &AuditorTreeHead{TreeSize: 10}},
		},
	}

	t.Run("all keys found", func(t *testing.T) {
		result, err := auditorTreeHeads(fth, []ed25519.PublicKey{key1})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 1 {
			t.Errorf("expected 1 result, got %d", len(result))
		}
	})

	t.Run("missing key", func(t *testing.T) {
		_, err := auditorTreeHeads(fth, []ed25519.PublicKey{key2})
		if err == nil {
			t.Fatal("expected error for missing key")
		}
	})
}

func TestSingleSignatureTreeHead(t *testing.T) {
	th := &TreeHead{
		TreeSize:   100,
		Timestamp:  12345,
		Signatures: []Signature{{SignatureBytes: []byte("sig")}},
	}
	ssth := &singleSignatureTreeHead{inner: th}
	if ssth.treeSize() != 100 {
		t.Errorf("expected treeSize 100, got %d", ssth.treeSize())
	}
	if ssth.timestamp() != 12345 {
		t.Errorf("expected timestamp 12345, got %d", ssth.timestamp())
	}
	if string(ssth.signatureBytes()) != "sig" {
		t.Errorf("expected sig, got %s", string(ssth.signatureBytes()))
	}
}

func TestAuditorTreeHeadWrapper(t *testing.T) {
	ath := &AuditorTreeHead{
		TreeSize:  200,
		Timestamp: 67890,
		Signature: []byte("auditor-sig"),
	}
	w := &auditorTreeHeadWrapper{inner: ath}
	if w.treeSize() != 200 {
		t.Errorf("expected treeSize 200, got %d", w.treeSize())
	}
	if w.timestamp() != 67890 {
		t.Errorf("expected timestamp 67890, got %d", w.timestamp())
	}
	if string(w.signatureBytes()) != "auditor-sig" {
		t.Errorf("expected auditor-sig, got %s", string(w.signatureBytes()))
	}
}

func TestCheckSearchConsistency(t *testing.T) {
	t.Run("nil data returns nil", func(t *testing.T) {
		mdw := newMonitoringDataWrapper(nil)
		index := &[32]byte{1}
		err := mdw.checkSearchConsistency(10, index, 0, 5, 1, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("index mismatch", func(t *testing.T) {
		data := &MonitoringData{
			Index: [32]byte{1},
			Pos:   0,
			Ptrs:  map[uint64]uint32{},
		}
		mdw := newMonitoringDataWrapper(data)
		wrongIndex := &[32]byte{2}
		err := mdw.checkSearchConsistency(10, wrongIndex, 0, 5, 1, true)
		if err == nil {
			t.Fatal("expected error for index mismatch")
		}
	})

	t.Run("pos mismatch", func(t *testing.T) {
		data := &MonitoringData{
			Index: [32]byte{1},
			Pos:   0,
			Ptrs:  map[uint64]uint32{},
		}
		mdw := newMonitoringDataWrapper(data)
		index := &[32]byte{1}
		err := mdw.checkSearchConsistency(10, index, 5, 5, 1, true)
		if err == nil {
			t.Fatal("expected error for pos mismatch")
		}
	})

	t.Run("same version at same position", func(t *testing.T) {
		data := &MonitoringData{
			Index: [32]byte{1},
			Pos:   0,
			Ptrs:  map[uint64]uint32{5: 1},
		}
		mdw := newMonitoringDataWrapper(data)
		index := &[32]byte{1}
		err := mdw.checkSearchConsistency(10, index, 0, 5, 1, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("different version at same position", func(t *testing.T) {
		data := &MonitoringData{
			Index: [32]byte{1},
			Pos:   0,
			Ptrs:  map[uint64]uint32{5: 1},
		}
		mdw := newMonitoringDataWrapper(data)
		index := &[32]byte{1}
		err := mdw.checkSearchConsistency(10, index, 0, 5, 2, false)
		if err == nil {
			t.Fatal("expected error for different versions at same position")
		}
	})

	t.Run("updates owned flag", func(t *testing.T) {
		data := &MonitoringData{
			Index: [32]byte{1},
			Pos:   0,
			Ptrs:  map[uint64]uint32{5: 1},
			Owned: false,
		}
		mdw := newMonitoringDataWrapper(data)
		index := &[32]byte{1}
		err := mdw.checkSearchConsistency(10, index, 0, 5, 1, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		update := mdw.intoDataUpdate()
		if !update.Owned {
			t.Error("owned should be updated to true")
		}
	})
}

func TestUpdate(t *testing.T) {
	t.Run("nil data", func(t *testing.T) {
		mdw := newMonitoringDataWrapper(nil)
		err := mdw.update(10, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty entries", func(t *testing.T) {
		data := &MonitoringData{
			Index: [32]byte{1},
			Pos:   0,
			Ptrs:  map[uint64]uint32{0: 1},
		}
		mdw := newMonitoringDataWrapper(data)
		err := mdw.update(10, map[uint64]ProofStep{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestFindUpdatedMapping(t *testing.T) {
	t.Run("no entries on path", func(t *testing.T) {
		result, err := findUpdatedMapping(0, 1, 0, 8, map[uint64]ProofStep{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Error("no matching entries should return nil")
		}
	})

	t.Run("nil prefix returns error", func(t *testing.T) {
		// Build a monitoring path for position 0 in tree starting at 0 with size 8.
		// monitoringPath(0,0,8) always returns [1,3,7] (3 elements).
		path, pathErr := monitoringPath(0, 0, 8)
		if pathErr != nil {
			t.Fatalf("unexpected error: %v", pathErr)
		}
		entries := map[uint64]ProofStep{
			path[0]: {Prefix: nil}, // nil prefix should cause error
		}
		_, err := findUpdatedMapping(0, 1, 0, 8, entries)
		if err == nil {
			t.Fatal("expected error for nil prefix")
		}
	})

	t.Run("lower version returns error", func(t *testing.T) {
		// monitoringPath(0,0,8) always returns [1,3,7] (3 elements).
		path, pathErr := monitoringPath(0, 0, 8)
		if pathErr != nil {
			t.Fatalf("unexpected error: %v", pathErr)
		}
		entries := map[uint64]ProofStep{
			path[0]: {Prefix: &PrefixProof{Counter: 0}}, // 0 < stored version 5
		}
		_, err := findUpdatedMapping(0, 5, 0, 8, entries)
		if err == nil {
			t.Fatal("expected error for lower version")
		}
	})

	t.Run("valid updated mapping", func(t *testing.T) {
		// monitoringPath(0,0,8) always returns [1,3,7] (3 elements).
		path, pathErr := monitoringPath(0, 0, 8)
		if pathErr != nil {
			t.Fatalf("unexpected error: %v", pathErr)
		}
		entries := map[uint64]ProofStep{
			path[0]: {Prefix: &PrefixProof{Counter: 10}},
		}
		result, err := findUpdatedMapping(0, 1, 0, 8, entries)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.ver != 10 {
			t.Errorf("expected version 10, got %d", result.ver)
		}
	})
}

func TestMarshalTreeHeadTBS(t *testing.T) {
	basePoint := [32]byte{
		0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	}
	vrfKey, _ := NewVRFPublicKey(basePoint)

	config := &PublicConfig{
		Mode:         ContactMonitoring(),
		SignatureKey: make(ed25519.PublicKey, 32),
		VRFKey:       vrfKey,
	}

	head := &singleSignatureTreeHead{
		inner: &TreeHead{
			TreeSize:   100,
			Timestamp:  12345,
			Signatures: []Signature{{SignatureBytes: make([]byte, 64)}},
		},
	}

	root := &[32]byte{1, 2, 3}

	t.Run("without auditor key", func(t *testing.T) {
		buf := marshalTreeHeadTBS(head, root, config, nil)
		if len(buf) == 0 {
			t.Fatal("expected non-empty TBS")
		}
	})

	t.Run("with auditor key", func(t *testing.T) {
		auditorKey := make(ed25519.PublicKey, 32)
		buf := marshalTreeHeadTBS(head, root, config, auditorKey)
		if len(buf) == 0 {
			t.Fatal("expected non-empty TBS")
		}
	})
}

func TestVerifyTreeHeadSignature(t *testing.T) {
	basePoint := [32]byte{
		0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	}
	vrfKey, _ := NewVRFPublicKey(basePoint)

	config := &PublicConfig{
		Mode:         ContactMonitoring(),
		SignatureKey: make(ed25519.PublicKey, 32),
		VRFKey:       vrfKey,
	}

	t.Run("wrong signature size", func(t *testing.T) {
		head := &singleSignatureTreeHead{
			inner: &TreeHead{
				TreeSize:   100,
				Timestamp:  12345,
				Signatures: []Signature{{SignatureBytes: make([]byte, 32)}}, // wrong size
			},
		}
		root := &[32]byte{}
		err := verifyTreeHeadSignature(config, head, root, config.SignatureKey, nil)
		if err == nil {
			t.Fatal("expected error for wrong signature size")
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		head := &singleSignatureTreeHead{
			inner: &TreeHead{
				TreeSize:   100,
				Timestamp:  12345,
				Signatures: []Signature{{SignatureBytes: make([]byte, 64)}}, // correct size but invalid
			},
		}
		root := &[32]byte{}
		err := verifyTreeHeadSignature(config, head, root, config.SignatureKey, nil)
		if err == nil {
			t.Fatal("expected error for invalid signature")
		}
	})
}

func TestNewMonitorProofAcc(t *testing.T) {
	mpa := newMonitorProofAcc(100)
	if mpa.treeSize != 100 {
		t.Errorf("expected treeSize 100, got %d", mpa.treeSize)
	}
	if len(mpa.leaves) != 0 {
		t.Error("leaves should be empty initially")
	}
}

func TestMonitorProofAccProcess(t *testing.T) {
	t.Run("unknown search key", func(t *testing.T) {
		mpa := newMonitorProofAcc(10)
		key := &MonitorKey{SearchKey: []byte("unknown")}
		proof := &MonitorProof{}
		err := mpa.process(map[string]*MonitoringData{}, key, proof)
		if err == nil {
			t.Fatal("expected error for unknown search key")
		}
	})
}

func TestVerifyDistinguished_SameSize(t *testing.T) {
	root := [32]byte{1, 2, 3}
	fth := &FullTreeHead{TreeHead: &TreeHead{TreeSize: 10}}
	lth := &LastTreeHead{
		Head: TreeHead{TreeSize: 10},
		Root: root,
	}
	dlth := &LastTreeHead{
		Head: TreeHead{TreeSize: 10},
		Root: root,
	}
	err := VerifyDistinguished(fth, lth, dlth)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyDistinguished_SameSizeDifferentRoot(t *testing.T) {
	fth := &FullTreeHead{TreeHead: &TreeHead{TreeSize: 10}}
	lth := &LastTreeHead{
		Head: TreeHead{TreeSize: 10},
		Root: [32]byte{1},
	}
	dlth := &LastTreeHead{
		Head: TreeHead{TreeSize: 10},
		Root: [32]byte{2},
	}
	err := VerifyDistinguished(fth, lth, dlth)
	if err == nil {
		t.Fatal("expected error for different root at same size")
	}
}
