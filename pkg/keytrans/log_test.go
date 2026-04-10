package keytrans

import (
	"crypto/sha256"
	"testing"
)

func TestLogNodeWidth(t *testing.T) {
	tests := []struct {
		n    uint64
		want uint64
	}{
		{0, 0},
		{1, 1},
		{2, 3},
		{3, 5},
		{4, 7},
		{8, 15},
	}

	for _, tt := range tests {
		got := logNodeWidth(tt.n)
		if got != tt.want {
			t.Errorf("logNodeWidth(%d) = %d, want %d", tt.n, got, tt.want)
		}
	}
}

func TestLogRoot(t *testing.T) {
	tests := []struct {
		n    uint64
		want uint64
	}{
		{1, 0},
		{2, 1},
		{4, 3},
		{8, 7},
	}

	for _, tt := range tests {
		got := logRoot(tt.n)
		if got != tt.want {
			t.Errorf("logRoot(%d) = %d, want %d", tt.n, got, tt.want)
		}
	}
}

func TestLogLeft(t *testing.T) {
	// logLeft is just leftStep
	got, err := logLeft(1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 0 {
		t.Errorf("logLeft(1) = %d, want 0", got)
	}
	got, err = logLeft(3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 1 {
		t.Errorf("logLeft(3) = %d, want 1", got)
	}
}

func TestLogRight(t *testing.T) {
	// For n=4 (7 nodes), root is 3
	// rightStep(3) = 5, which is within 7 nodes, so logRight(3, 4) = 5
	got, err := logRight(3, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 5 {
		t.Errorf("logRight(3, 4) = %d, want 5", got)
	}

	// For n=3 (5 nodes), root is 3
	// rightStep(3) = 5, which >= 5 (nodeWidth), so take logLeft
	got, err = logRight(3, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got >= logNodeWidth(3) {
		t.Errorf("logRight(3, 3) = %d, should be < %d", got, logNodeWidth(3))
	}
}

func TestLogParent(t *testing.T) {
	// For n=4: tree is 0,1,2,3,4,5,6 (7 nodes)
	// Parent of 0 should be 1
	got, err := logParent(0, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 1 {
		t.Errorf("logParent(0, 4) = %d, want 1", got)
	}
	// Parent of 2 should be 1
	got, err = logParent(2, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 1 {
		t.Errorf("logParent(2, 4) = %d, want 1", got)
	}
}

func TestLogParent_ErrorOnRoot(t *testing.T) {
	_, err := logParent(logRoot(4), 4)
	if err != ErrRootHasNoParent {
		t.Errorf("logParent on root should return ErrRootHasNoParent, got %v", err)
	}
}

func TestLogSibling(t *testing.T) {
	// For n=4: sibling of 0 should be 2
	got, err := logSibling(0, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 2 {
		t.Errorf("logSibling(0, 4) = %d, want 2", got)
	}

	// Sibling of 2 should be 0
	got, err = logSibling(2, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 0 {
		t.Errorf("logSibling(2, 4) = %d, want 0", got)
	}
}

func TestIsFullSubtree(t *testing.T) {
	// For n=4 (rightmost leaf node is 6):
	// Node 3 (level 2) with coverage to node 6 is full
	if !isFullSubtree(3, 4) {
		t.Error("node 3 in tree of 4 leaves should be full subtree")
	}
	// Node 0 is a leaf, always full
	if !isFullSubtree(0, 4) {
		t.Error("leaf 0 should be full subtree")
	}
}

func TestLogFullSubtrees(t *testing.T) {
	// For a tree of 4 leaves, root at 3: all subtrees should be full
	subtrees, err := logFullSubtrees(logRoot(4), 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(subtrees) == 0 {
		t.Error("full subtrees should not be empty")
	}
}

func TestLogConsistencyProof(t *testing.T) {
	t.Run("m=1 n=2", func(t *testing.T) {
		proof, err := logConsistencyProof(1, 2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(proof) == 0 {
			t.Error("consistency proof should not be empty for m=1, n=2")
		}
	})

	t.Run("m=2 n=4", func(t *testing.T) {
		proof, err := logConsistencyProof(2, 4)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(proof) == 0 {
			t.Error("consistency proof should not be empty for m=2, n=4")
		}
	})

	t.Run("m=4 n=8", func(t *testing.T) {
		proof, err := logConsistencyProof(4, 8)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(proof) == 0 {
			t.Error("consistency proof should not be empty for m=4, n=8")
		}
	})

	t.Run("m=3 n=5", func(t *testing.T) {
		proof, err := logConsistencyProof(3, 5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(proof) == 0 {
			t.Error("consistency proof should not be empty for m=3, n=5")
		}
	})
}

func TestLogBatchCopath(t *testing.T) {
	t.Run("single leaf", func(t *testing.T) {
		copath, err := logBatchCopath([]uint64{0}, 4)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(copath) == 0 {
			t.Error("batch copath for single leaf should not be empty")
		}
	})

	t.Run("all leaves", func(t *testing.T) {
		copath, err := logBatchCopath([]uint64{0, 1, 2, 3}, 4)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(copath) != 0 {
			t.Errorf("batch copath for all leaves should be empty, got %v", copath)
		}
	})

	t.Run("two siblings", func(t *testing.T) {
		copath, err := logBatchCopath([]uint64{0, 1}, 4)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(copath) > 3 {
			t.Errorf("copath for siblings should be small, got %d elements", len(copath))
		}
	})
}

func TestSortUint64s(t *testing.T) {
	t.Run("already sorted", func(t *testing.T) {
		s := []uint64{1, 2, 3, 4}
		sortUint64s(s)
		for i := 1; i < len(s); i++ {
			if s[i] < s[i-1] {
				t.Errorf("not sorted at index %d", i)
			}
		}
	})

	t.Run("reverse sorted", func(t *testing.T) {
		s := []uint64{4, 3, 2, 1}
		sortUint64s(s)
		expected := []uint64{1, 2, 3, 4}
		for i, v := range s {
			if v != expected[i] {
				t.Errorf("s[%d] = %d, want %d", i, v, expected[i])
			}
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		sortUint64s(nil) // should not panic
	})

	t.Run("single element", func(t *testing.T) {
		s := []uint64{42}
		sortUint64s(s)
		if s[0] != 42 {
			t.Errorf("s[0] = %d, want 42", s[0])
		}
	})
}

func TestNodeDataMarshal(t *testing.T) {
	t.Run("leaf node", func(t *testing.T) {
		nd := &nodeData{interior: false, value: [32]byte{1, 2, 3}}
		buf := nd.marshal()
		if len(buf) != 33 {
			t.Fatalf("expected 33 bytes, got %d", len(buf))
		}
		if buf[0] != 0 {
			t.Errorf("leaf node should have 0 prefix, got %d", buf[0])
		}
		if buf[1] != 1 || buf[2] != 2 || buf[3] != 3 {
			t.Error("value bytes not correctly marshaled")
		}
	})

	t.Run("interior node", func(t *testing.T) {
		nd := &nodeData{interior: true, value: [32]byte{4, 5, 6}}
		buf := nd.marshal()
		if len(buf) != 33 {
			t.Fatalf("expected 33 bytes, got %d", len(buf))
		}
		if buf[0] != 1 {
			t.Errorf("interior node should have 1 prefix, got %d", buf[0])
		}
	})
}

func TestTreeHash(t *testing.T) {
	left := &nodeData{interior: false, value: [32]byte{1}}
	right := &nodeData{interior: false, value: [32]byte{2}}

	result := treeHash(left, right)
	if !result.interior {
		t.Error("tree hash should produce an interior node")
	}

	// Verify it's a SHA-256 of both marshaled nodes
	h := sha256.New()
	h.Write(left.marshal())
	h.Write(right.marshal())
	var expected [32]byte
	copy(expected[:], h.Sum(nil))
	if result.value != expected {
		t.Error("tree hash value doesn't match expected SHA-256")
	}
}

func TestSimpleRootCalculator(t *testing.T) {
	t.Run("empty chain returns error", func(t *testing.T) {
		calc := newSimpleRootCalculator()
		_, err := calc.root()
		if err != ErrEmptyChain {
			t.Errorf("expected ErrEmptyChain, got %v", err)
		}
	})

	t.Run("single leaf", func(t *testing.T) {
		calc := newSimpleRootCalculator()
		value := [32]byte{1, 2, 3}
		calc.insert(0, value)
		root, err := calc.root()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if root != value {
			t.Error("single leaf root should equal the leaf value")
		}
	})

	t.Run("two leaves", func(t *testing.T) {
		calc := newSimpleRootCalculator()
		v1 := [32]byte{1}
		v2 := [32]byte{2}
		calc.insert(0, v1)
		calc.insert(0, v2)
		root, err := calc.root()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Root should be tree hash of two leaves
		left := &nodeData{interior: false, value: v1}
		right := &nodeData{interior: false, value: v2}
		expected := treeHash(left, right)
		if root != expected.value {
			t.Error("two-leaf root doesn't match expected tree hash")
		}
	})

	t.Run("four leaves", func(t *testing.T) {
		calc := newSimpleRootCalculator()
		for i := 0; i < 4; i++ {
			calc.insert(0, [32]byte{byte(i)})
		}
		_, err := calc.root()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("mixed levels", func(t *testing.T) {
		calc := newSimpleRootCalculator()
		calc.insert(0, [32]byte{1})
		calc.insert(1, [32]byte{2}) // interior node at level 1
		_, err := calc.root()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestEvaluateBatchProof(t *testing.T) {
	t.Run("mismatched indices and values", func(t *testing.T) {
		_, err := EvaluateBatchProof([]uint64{0, 1}, 4, []Hash{{1}}, nil)
		if err == nil {
			t.Fatal("expected error for mismatched indices and values")
		}
	})

	t.Run("unsorted indices", func(t *testing.T) {
		_, err := EvaluateBatchProof([]uint64{1, 0}, 4, []Hash{{1}, {2}}, nil)
		if err == nil {
			t.Fatal("expected error for unsorted indices")
		}
	})

	t.Run("duplicate indices", func(t *testing.T) {
		_, err := EvaluateBatchProof([]uint64{0, 0}, 4, []Hash{{1}, {2}}, nil)
		if err == nil {
			t.Fatal("expected error for duplicate indices")
		}
	})

	t.Run("empty batch", func(t *testing.T) {
		_, err := EvaluateBatchProof(nil, 4, nil, nil)
		if err == nil {
			t.Fatal("expected error for empty batch")
		}
	})

	t.Run("leaf index too large", func(t *testing.T) {
		_, err := EvaluateBatchProof([]uint64{4}, 4, []Hash{{1}}, nil)
		if err == nil {
			t.Fatal("expected error for leaf index >= tree size")
		}
	})

	t.Run("wrong proof length", func(t *testing.T) {
		// For a single leaf 0 in tree of size 4, the copath has 2 elements
		// So providing 3 elements should fail
		copath, cpErr := logBatchCopath([]uint64{0}, 4)
		if cpErr != nil {
			t.Fatalf("unexpected error: %v", cpErr)
		}
		wrongProof := make([]Hash, len(copath)+1)
		_, err := EvaluateBatchProof([]uint64{0}, 4, []Hash{{1}}, wrongProof)
		if err == nil {
			t.Fatal("expected error for wrong proof length")
		}
	})

	t.Run("all leaves of size 4", func(t *testing.T) {
		indices := []uint64{0, 1, 2, 3}
		values := make([]Hash, 4)
		for i := range values {
			values[i] = Hash{byte(i)}
		}
		// All leaves means empty copath
		root, err := EvaluateBatchProof(indices, 4, values, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// The root should match building the tree from scratch
		_ = root
	})
}

func TestVerifyConsistencyProof(t *testing.T) {
	t.Run("invalid m=0", func(t *testing.T) {
		err := VerifyConsistencyProof(0, 4, nil, &Hash{}, &Hash{})
		if err == nil {
			t.Fatal("expected error for m=0")
		}
	})

	t.Run("invalid m>=n", func(t *testing.T) {
		err := VerifyConsistencyProof(4, 4, nil, &Hash{}, &Hash{})
		if err == nil {
			t.Fatal("expected error for m>=n")
		}
	})

	t.Run("wrong proof length", func(t *testing.T) {
		err := VerifyConsistencyProof(1, 2, nil, &Hash{}, &Hash{})
		if err == nil {
			t.Fatal("expected error for wrong proof length")
		}
	})

	t.Run("valid consistency proof for simple trees", func(t *testing.T) {
		// Build tree of 2 leaves: leaf0 and leaf1
		leaf0 := Hash{0}
		leaf1 := Hash{1}

		nd0 := &nodeData{interior: false, value: leaf0}
		nd1 := &nodeData{interior: false, value: leaf1}

		// Root of 1-leaf tree is just leaf0
		mRoot := leaf0

		// Root of 2-leaf tree is treeHash(leaf0, leaf1)
		nRootNode := treeHash(nd0, nd1)
		nRoot := nRootNode.value

		// Consistency proof from m=1 to n=2:
		// logConsistencyProof(1, 2) returns some node IDs
		ids, idsErr := logConsistencyProof(1, 2)
		if idsErr != nil {
			t.Fatalf("unexpected error: %v", idsErr)
		}
		// Build the proof by providing the hash at each id
		proof := make([]Hash, len(ids))
		for i, id := range ids {
			switch id {
			case 2:
				proof[i] = leaf1
			case 0:
				proof[i] = leaf0
			}
		}

		err := VerifyConsistencyProof(1, 2, proof, &mRoot, &nRoot)
		if err != nil {
			t.Fatalf("expected valid proof, got error: %v", err)
		}
	})

	t.Run("proof mismatch", func(t *testing.T) {
		leaf0 := Hash{0}
		leaf1 := Hash{1}

		nd0 := &nodeData{interior: false, value: leaf0}
		nd1 := &nodeData{interior: false, value: leaf1}

		mRoot := leaf0
		nRootNode := treeHash(nd0, nd1)
		nRoot := nRootNode.value

		ids, idsErr := logConsistencyProof(1, 2)
		if idsErr != nil {
			t.Fatalf("unexpected error: %v", idsErr)
		}
		proof := make([]Hash, len(ids))
		// Provide wrong hash values
		for i := range proof {
			proof[i] = Hash{99}
		}

		err := VerifyConsistencyProof(1, 2, proof, &mRoot, &nRoot)
		if err == nil {
			t.Fatal("expected error for proof mismatch")
		}
	})

	t.Run("multi-element proof m=2 n=4", func(t *testing.T) {
		// Build a 4-leaf tree
		leaves := [4]Hash{{0}, {1}, {2}, {3}}
		nodes := make(map[uint64]*nodeData)
		for i, l := range leaves {
			nodes[uint64(2*i)] = &nodeData{interior: false, value: l}
		}
		// Node 1 = treeHash(node0, node2)
		nodes[1] = func() *nodeData { n := treeHash(nodes[0], nodes[2]); return &n }()
		// Node 5 = treeHash(node4, node6)
		nodes[5] = func() *nodeData { n := treeHash(nodes[4], nodes[6]); return &n }()
		// Node 3 = treeHash(node1, node5)
		nodes[3] = func() *nodeData { n := treeHash(nodes[1], nodes[5]); return &n }()

		mRoot := nodes[1].value // root of 2-leaf tree
		nRoot := nodes[3].value // root of 4-leaf tree

		ids, idsErr := logConsistencyProof(2, 4)
		if idsErr != nil {
			t.Fatalf("unexpected error: %v", idsErr)
		}
		proof := make([]Hash, len(ids))
		for i, id := range ids {
			if nd, ok := nodes[id]; ok {
				proof[i] = nd.value
			}
		}

		err := VerifyConsistencyProof(2, 4, proof, &mRoot, &nRoot)
		if err != nil {
			t.Fatalf("expected valid proof, got error: %v", err)
		}
	})

	t.Run("non-power-of-two m=3 n=5", func(t *testing.T) {
		// Just verify it handles non-power-of-two without panicking
		ids, idsErr := logConsistencyProof(3, 5)
		if idsErr != nil {
			t.Fatalf("unexpected error: %v", idsErr)
		}
		proof := make([]Hash, len(ids))
		mRoot := Hash{1}
		nRoot := Hash{2}
		err := VerifyConsistencyProof(3, 5, proof, &mRoot, &nRoot)
		// Will likely fail verification but shouldn't panic.
		// Either outcome is acceptable — we just verify no panic occurred.
		_ = err
	})
}

func TestEvaluateBatchProof_SingleLeaf(t *testing.T) {
	// Test with a single leaf in a 2-leaf tree
	// Leaf 0, tree size 2
	leaf0 := Hash{0}
	leaf1 := Hash{1}

	nd0 := &nodeData{interior: false, value: leaf0}
	nd1 := &nodeData{interior: false, value: leaf1}
	expectedRoot := treeHash(nd0, nd1)

	// Copath for leaf 0 in 2-leaf tree should be [leaf1]
	copath, cpErr := logBatchCopath([]uint64{0}, 2)
	if cpErr != nil {
		t.Fatalf("unexpected error: %v", cpErr)
	}
	proof := make([]Hash, len(copath))
	for i, id := range copath {
		if id == 2 { // node 2 = leaf1
			proof[i] = leaf1
		}
	}

	root, err := EvaluateBatchProof([]uint64{0}, 2, []Hash{leaf0}, proof)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if root != expectedRoot.value {
		t.Error("batch proof root does not match expected tree root")
	}
}

func TestLogFullSubtrees_NonFull(t *testing.T) {
	// For n=3 (5 nodes), root at 3
	// Node 3 is NOT a full subtree because rightmost is 4 (2*(3-1)=4)
	// expected = 3 + (1<<2) - 1 = 3+3 = 6, but rightmost is 4, so 6 > 4 -> not full
	subtrees, stErr := logFullSubtrees(logRoot(3), 3)
	if stErr != nil {
		t.Fatalf("unexpected error: %v", stErr)
	}
	if len(subtrees) < 2 {
		t.Errorf("non-full root should decompose into multiple subtrees, got %d", len(subtrees))
	}
}

func TestLogErrorTypes(t *testing.T) {
	t.Run("LogError", func(t *testing.T) {
		err := &LogError{msg: "test error"}
		if err.Error() != "test error" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("logInvalidInput", func(t *testing.T) {
		err := logInvalidInput("bad input")
		if err.Error() != "invalid input: bad input" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("logMalformedProof", func(t *testing.T) {
		err := logMalformedProof()
		if err.Error() != "malformed proof" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("logProofMismatch", func(t *testing.T) {
		err := logProofMismatch("mismatch detail")
		if err.Error() != "proof mismatch: mismatch detail" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("logUnexpected", func(t *testing.T) {
		err := logUnexpected("unexpected detail")
		if err.Error() != "unexpected error: unexpected detail" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}
