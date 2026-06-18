package keytrans

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

func TestDeploymentMode(t *testing.T) {
	t.Run("ContactMonitoring", func(t *testing.T) {
		dm := ContactMonitoring()
		if dm.byte() != 1 {
			t.Errorf("expected byte 1, got %d", dm.byte())
		}
		if dm.hasAssociatedKeys() {
			t.Error("contact monitoring should not have associated keys")
		}
		if len(dm.getAssociatedKeys()) != 0 {
			t.Error("contact monitoring should return empty keys")
		}
	})

	t.Run("ThirdPartyManagement", func(t *testing.T) {
		keys := []ed25519.PublicKey{{1, 2, 3}, {4, 5, 6}}
		dm := ThirdPartyManagement(keys)
		if dm.byte() != 2 {
			t.Errorf("expected byte 2, got %d", dm.byte())
		}
		if !dm.hasAssociatedKeys() {
			t.Error("third party management should have associated keys")
		}
		if len(dm.getAssociatedKeys()) != 2 {
			t.Errorf("expected 2 keys, got %d", len(dm.getAssociatedKeys()))
		}
	})

	t.Run("ThirdPartyAuditing", func(t *testing.T) {
		keys := []ed25519.PublicKey{{7, 8, 9}}
		dm := ThirdPartyAuditing(keys)
		if dm.byte() != 3 {
			t.Errorf("expected byte 3, got %d", dm.byte())
		}
		if !dm.hasAssociatedKeys() {
			t.Error("third party auditing should have associated keys")
		}
	})

	t.Run("default byte", func(t *testing.T) {
		dm := DeploymentMode{kind: deploymentKind(99)}
		if dm.byte() != 0 {
			t.Errorf("unknown deployment kind should return 0, got %d", dm.byte())
		}
	})
}

func TestLastTreeHead_IntoStored(t *testing.T) {
	lth := &LastTreeHead{
		Head: TreeHead{
			TreeSize:  100,
			Timestamp: 1234567890,
		},
		Root: [32]byte{1, 2, 3},
	}

	storedAt := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	stored := lth.IntoStored(storedAt)

	if stored.TreeHead == nil {
		t.Fatal("TreeHead should not be nil")
	}
	if stored.TreeHead.TreeSize != 100 {
		t.Errorf("expected TreeSize 100, got %d", stored.TreeHead.TreeSize)
	}
	if len(stored.Root) != 32 {
		t.Errorf("expected 32-byte root, got %d", len(stored.Root))
	}
	if stored.StoredAtMs != uint64(storedAt.UnixMilli()) {
		t.Errorf("StoredAtMs mismatch")
	}
}

func TestStoredTreeHeadToLastTreeHead(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := StoredTreeHeadToLastTreeHead(nil)
		if result != nil {
			t.Error("nil input should return nil")
		}
	})

	t.Run("nil tree head", func(t *testing.T) {
		result := StoredTreeHeadToLastTreeHead(&StoredTreeHead{})
		if result != nil {
			t.Error("nil tree head should return nil")
		}
	})

	t.Run("wrong root length", func(t *testing.T) {
		result := StoredTreeHeadToLastTreeHead(&StoredTreeHead{
			TreeHead: &TreeHead{TreeSize: 1},
			Root:     []byte{1, 2, 3},
		})
		if result != nil {
			t.Error("wrong root length should return nil")
		}
	})

	t.Run("valid conversion", func(t *testing.T) {
		root := make([]byte, 32)
		root[0] = 42
		sth := &StoredTreeHead{
			TreeHead: &TreeHead{TreeSize: 100, Timestamp: 1234},
			Root:     root,
		}
		result := StoredTreeHeadToLastTreeHead(sth)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Head.TreeSize != 100 {
			t.Errorf("expected TreeSize 100, got %d", result.Head.TreeSize)
		}
		if result.Root[0] != 42 {
			t.Errorf("expected root[0]=42, got %d", result.Root[0])
		}
	})
}

func TestMonitoringData_Clone(t *testing.T) {
	original := &MonitoringData{
		Index: [32]byte{1, 2, 3},
		Pos:   42,
		Ptrs:  map[uint64]uint32{10: 1, 20: 2},
		Owned: true,
	}

	cloned := original.Clone()

	// Verify values match
	if cloned.Index != original.Index {
		t.Error("cloned Index should match")
	}
	if cloned.Pos != original.Pos {
		t.Error("cloned Pos should match")
	}
	if cloned.Owned != original.Owned {
		t.Error("cloned Owned should match")
	}
	if len(cloned.Ptrs) != len(original.Ptrs) {
		t.Error("cloned Ptrs should have same length")
	}

	// Verify deep copy - modifying clone shouldn't affect original
	cloned.Ptrs[10] = 99
	if original.Ptrs[10] == 99 {
		t.Error("modifying cloned Ptrs should not affect original")
	}
}

func TestMonitoringData_Entries(t *testing.T) {
	md := &MonitoringData{
		Ptrs: map[uint64]uint32{30: 3, 10: 1, 20: 2},
	}
	entries := md.Entries()
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	// Should be sorted
	if entries[0] != 10 || entries[1] != 20 || entries[2] != 30 {
		t.Errorf("entries should be sorted, got %v", entries)
	}
}

func TestMonitoringData_LatestLogPosition(t *testing.T) {
	t.Run("normal case", func(t *testing.T) {
		md := &MonitoringData{
			Ptrs: map[uint64]uint32{10: 1, 30: 3, 20: 2},
		}
		if got := md.LatestLogPosition(); got != 30 {
			t.Errorf("expected 30, got %d", got)
		}
	})

	t.Run("empty ptrs", func(t *testing.T) {
		md := &MonitoringData{Ptrs: map[uint64]uint32{}}
		got := md.LatestLogPosition()
		if got != 0 {
			t.Errorf("expected 0 for empty ptrs, got %d", got)
		}
	})
}

func TestMonitoringData_GreatestVersion(t *testing.T) {
	t.Run("normal case", func(t *testing.T) {
		md := &MonitoringData{
			Ptrs: map[uint64]uint32{10: 1, 30: 5, 20: 3},
		}
		if got := md.GreatestVersion(); got != 5 {
			t.Errorf("expected 5, got %d", got)
		}
	})

	t.Run("empty ptrs", func(t *testing.T) {
		md := &MonitoringData{Ptrs: map[uint64]uint32{}}
		got := md.GreatestVersion()
		if got != 0 {
			t.Errorf("expected 0 for empty ptrs, got %d", got)
		}
	})
}

func TestMonitoringData_NextMonitor(t *testing.T) {
	md := &MonitoringData{
		Ptrs: map[uint64]uint32{0: 1},
	}
	result := md.NextMonitor()
	expected := nextMonitor([]uint64{0})
	if result != expected {
		t.Errorf("expected %d, got %d", expected, result)
	}
}

func TestMonitoringData_IntoStored(t *testing.T) {
	md := &MonitoringData{
		Index: [32]byte{1},
		Pos:   42,
		Ptrs:  map[uint64]uint32{10: 1},
		Owned: true,
	}
	searchKey := []byte("test-key")
	stored := md.IntoStored(searchKey)

	if stored.Pos != 42 {
		t.Errorf("expected Pos 42, got %d", stored.Pos)
	}
	if stored.Owned != true {
		t.Error("expected Owned true")
	}
	if string(stored.SearchKey) != "test-key" {
		t.Errorf("expected search key 'test-key', got %s", string(stored.SearchKey))
	}
}

func TestMonitoringDataFromStored(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := MonitoringDataFromStored(nil)
		if result != nil {
			t.Error("nil input should return nil")
		}
	})

	t.Run("valid conversion", func(t *testing.T) {
		index := make([]byte, 32)
		index[0] = 42
		smd := &StoredMonitoringData{
			Index: index,
			Pos:   10,
			Ptrs:  map[uint64]uint32{5: 1},
			Owned: true,
		}
		result := MonitoringDataFromStored(smd)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Index[0] != 42 {
			t.Errorf("expected Index[0]=42, got %d", result.Index[0])
		}
		if result.Pos != 10 {
			t.Errorf("expected Pos 10, got %d", result.Pos)
		}
	})
}

func TestVerifiedSearchResult_AreAllRootsEqual(t *testing.T) {
	root1 := TreeRoot{1, 2, 3}
	root2 := TreeRoot{1, 2, 3}
	root3 := TreeRoot{4, 5, 6}

	vsr := &VerifiedSearchResult{StateUpdate: SearchStateUpdate{TreeRoot: root1}}
	other1 := &VerifiedSearchResult{StateUpdate: SearchStateUpdate{TreeRoot: root2}}
	other2 := &VerifiedSearchResult{StateUpdate: SearchStateUpdate{TreeRoot: root3}}

	t.Run("same roots", func(t *testing.T) {
		if !vsr.AreAllRootsEqual(other1) {
			t.Error("same roots should be equal")
		}
	})

	t.Run("different roots", func(t *testing.T) {
		if vsr.AreAllRootsEqual(other2) {
			t.Error("different roots should not be equal")
		}
	})

	t.Run("nil other", func(t *testing.T) {
		if !vsr.AreAllRootsEqual(nil) {
			t.Error("nil other should be treated as equal")
		}
	})

	t.Run("no others", func(t *testing.T) {
		if !vsr.AreAllRootsEqual() {
			t.Error("no others should return true")
		}
	})
}

func TestVerifiedSearchResult_TreeRoot(t *testing.T) {
	root := TreeRoot{1, 2, 3}
	vsr := &VerifiedSearchResult{StateUpdate: SearchStateUpdate{TreeRoot: root}}
	got := vsr.TreeRoot()
	if *got != root {
		t.Error("TreeRoot should return the state update's tree root")
	}
}

func TestNewSlimSearchRequest(t *testing.T) {
	searchKey := []byte("test-key")
	req := NewSlimSearchRequest(searchKey)
	if string(req.SearchKey) != "test-key" {
		t.Errorf("expected search key 'test-key', got %s", string(req.SearchKey))
	}
	if req.Version != nil {
		t.Error("version should be nil")
	}
}

func TestNewFullSearchResponse(t *testing.T) {
	condensed := &CondensedTreeSearchResponse{}
	treeHead := &FullTreeHead{}
	resp := NewFullSearchResponse(condensed, treeHead)
	if resp.Condensed != condensed {
		t.Error("Condensed should match")
	}
	if resp.TreeHead != treeHead {
		t.Error("TreeHead should match")
	}
}

func TestAccountDataFromStored(t *testing.T) {
	t.Run("nil stored", func(t *testing.T) {
		_, err := AccountDataFromStored(nil)
		if err == nil {
			t.Fatal("expected error for nil stored")
		}
	})

	t.Run("nil last tree head", func(t *testing.T) {
		_, err := AccountDataFromStored(&StoredAccountData{})
		if err == nil {
			t.Fatal("expected error for nil last tree head")
		}
	})

	t.Run("nil aci", func(t *testing.T) {
		root := make([]byte, 32)
		_, err := AccountDataFromStored(&StoredAccountData{
			LastTreeHead: &StoredTreeHead{
				TreeHead: &TreeHead{TreeSize: 1},
				Root:     root,
			},
		})
		if err == nil {
			t.Fatal("expected error for nil ACI")
		}
	})

	t.Run("invalid stored tree head", func(t *testing.T) {
		_, err := AccountDataFromStored(&StoredAccountData{
			LastTreeHead: &StoredTreeHead{
				TreeHead: &TreeHead{TreeSize: 1},
				Root:     []byte{1, 2}, // wrong length
			},
		})
		if err == nil {
			t.Fatal("expected error for invalid stored tree head")
		}
	})

	t.Run("valid conversion", func(t *testing.T) {
		root := make([]byte, 32)
		aciIndex := make([]byte, 32)
		stored := &StoredAccountData{
			LastTreeHead: &StoredTreeHead{
				TreeHead: &TreeHead{TreeSize: 10},
				Root:     root,
			},
			ACI: &StoredMonitoringData{
				Index: aciIndex,
				Pos:   5,
				Ptrs:  map[uint64]uint32{1: 1},
			},
		}
		ad, err := AccountDataFromStored(stored)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ad.E164 != nil {
			t.Error("E164 should be nil")
		}
		if ad.UsernameHash != nil {
			t.Error("UsernameHash should be nil")
		}
	})

	t.Run("with optional fields", func(t *testing.T) {
		root := make([]byte, 32)
		idx := make([]byte, 32)
		stored := &StoredAccountData{
			LastTreeHead: &StoredTreeHead{
				TreeHead: &TreeHead{TreeSize: 10},
				Root:     root,
			},
			ACI: &StoredMonitoringData{
				Index: idx,
				Ptrs:  map[uint64]uint32{1: 1},
			},
			E164: &StoredMonitoringData{
				Index: idx,
				Ptrs:  map[uint64]uint32{2: 2},
			},
			UsernameHash: &StoredMonitoringData{
				Index: idx,
				Ptrs:  map[uint64]uint32{3: 3},
			},
		}
		ad, err := AccountDataFromStored(stored)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ad.E164 == nil {
			t.Error("E164 should not be nil")
		}
		if ad.UsernameHash == nil {
			t.Error("UsernameHash should not be nil")
		}
	})
}

func TestAccountData_IntoStored(t *testing.T) {
	ad := &AccountData{
		ACI: MonitoringData{
			Index: [32]byte{1},
			Ptrs:  map[uint64]uint32{1: 1},
		},
		LastTreeHead: LastTreeHead{
			Head: TreeHead{TreeSize: 10},
			Root: [32]byte{2},
		},
	}

	stored := ad.IntoStored([]byte("aci"), nil, nil, time.Now())
	if stored.ACI == nil {
		t.Fatal("ACI should not be nil")
	}
	if stored.E164 != nil {
		t.Error("E164 should be nil when no search key provided")
	}
	if stored.UsernameHash != nil {
		t.Error("UsernameHash should be nil when no search key provided")
	}
}

func TestMonitoringData_SearchKey_RoundTrip(t *testing.T) {
	searchKey := []byte("round-trip-search-key")
	original := &MonitoringData{
		Index:     [32]byte{1, 2, 3},
		Pos:       7,
		Ptrs:      map[uint64]uint32{10: 1, 20: 2},
		Owned:     true,
		SearchKey: searchKey,
	}

	stored := original.IntoStored(original.SearchKey)
	if !bytes.Equal(stored.SearchKey, searchKey) {
		t.Errorf("IntoStored: SearchKey = %q, want %q", stored.SearchKey, searchKey)
	}

	recovered := MonitoringDataFromStored(&stored)
	if recovered == nil {
		t.Fatal("MonitoringDataFromStored returned nil")
	}
	if !bytes.Equal(recovered.SearchKey, searchKey) {
		t.Errorf("MonitoringDataFromStored: SearchKey = %q, want %q", recovered.SearchKey, searchKey)
	}

	// Verify byte-for-byte equality.
	if recovered.Index != original.Index {
		t.Error("Index mismatch after round-trip")
	}
	if recovered.Pos != original.Pos {
		t.Errorf("Pos: got %d, want %d", recovered.Pos, original.Pos)
	}
	if recovered.Owned != original.Owned {
		t.Error("Owned mismatch after round-trip")
	}
}

func TestMonitoringData_SearchKey_NilRoundTrip(t *testing.T) {
	// Nil SearchKey must survive the round-trip as nil (not empty slice).
	original := &MonitoringData{
		Index: [32]byte{5},
		Pos:   3,
		Ptrs:  map[uint64]uint32{1: 1},
		Owned: false,
	}

	stored := original.IntoStored(nil)
	if stored.SearchKey != nil {
		t.Errorf("IntoStored with nil searchKey: stored.SearchKey = %v, want nil", stored.SearchKey)
	}

	recovered := MonitoringDataFromStored(&stored)
	if recovered.SearchKey != nil {
		t.Errorf("MonitoringDataFromStored: SearchKey = %v, want nil", recovered.SearchKey)
	}
}

func TestMonitoringData_Clone_SearchKey(t *testing.T) {
	original := &MonitoringData{
		Index:     [32]byte{9},
		Pos:       1,
		Ptrs:      map[uint64]uint32{5: 5},
		Owned:     true,
		SearchKey: []byte("clone-key"),
	}

	cloned := original.Clone()
	if !bytes.Equal(cloned.SearchKey, original.SearchKey) {
		t.Error("cloned SearchKey should match original")
	}

	// Verify deep copy: modifying clone should not affect original.
	cloned.SearchKey[0] = 'X'
	if original.SearchKey[0] == 'X' {
		t.Error("modifying cloned SearchKey should not affect original")
	}
}

func TestAccountData_IntoStored_WithOptionalFields(t *testing.T) {
	e164Data := &MonitoringData{
		Index: [32]byte{3},
		Ptrs:  map[uint64]uint32{2: 2},
	}
	usernameData := &MonitoringData{
		Index: [32]byte{4},
		Ptrs:  map[uint64]uint32{3: 3},
	}
	ad := &AccountData{
		ACI: MonitoringData{
			Index: [32]byte{1},
			Ptrs:  map[uint64]uint32{1: 1},
		},
		E164:         e164Data,
		UsernameHash: usernameData,
		LastTreeHead: LastTreeHead{
			Head: TreeHead{TreeSize: 10},
			Root: [32]byte{2},
		},
	}

	stored := ad.IntoStored([]byte("aci"), []byte("e164"), []byte("username"), time.Now())
	if stored.E164 == nil {
		t.Error("E164 should not be nil")
	}
	if stored.UsernameHash == nil {
		t.Error("UsernameHash should not be nil")
	}
}
