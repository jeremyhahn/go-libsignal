// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package keytrans

import (
	"sort"
)

// versionedID associates an id with a version number.
type versionedID struct {
	id      uint64
	version uint32
}

// ProofGuide is used for determining which nodes should be accessed when
// conducting searches in the Implicit Binary Search Tree.
type ProofGuide struct {
	pos        uint64
	n          uint64
	version    uint32
	ids        []uint64
	sorted     []versionedID
	isFrontier bool
}

// NewProofGuide creates a new ProofGuide for the given version, position, and tree size.
func NewProofGuide(version *uint32, pos, n uint64) (*ProofGuide, error) {
	if version == nil {
		return newProofGuideForMostRecent(pos, n)
	}
	return newProofGuideForVersion(*version, pos, n)
}

func newProofGuideForVersion(version uint32, pos, n uint64) (*ProofGuide, error) {
	root, err := implicitRoot(pos, n)
	if err != nil {
		return nil, err
	}
	return &ProofGuide{
		pos:        pos,
		n:          n,
		version:    version,
		ids:        []uint64{root},
		isFrontier: false,
	}, nil
}

func newProofGuideForMostRecent(pos, n uint64) (*ProofGuide, error) {
	frontier, err := implicitFrontier(pos, n)
	if err != nil {
		return nil, err
	}
	return &ProofGuide{
		pos:        pos,
		n:          n,
		version:    0,
		ids:        frontier,
		isFrontier: true,
	}, nil
}

// poll returns true if the search proof is finished.
func (g *ProofGuide) poll() (bool, error) {
	if len(g.ids) > len(g.sorted) {
		return false, nil
	}

	// Sort by id.
	sort.Slice(g.sorted, func(i, j int) bool {
		return g.sorted[i].id < g.sorted[j].id
	})

	// Check that the list of counters is monotonic.
	for i := 1; i < len(g.sorted); i++ {
		if g.sorted[i-1].version > g.sorted[i].version {
			return false, ErrInvalidGuideState
		}
	}

	// Determine the "last" id looked up.
	var last uint64
	if g.isFrontier {
		g.version = g.sorted[len(g.sorted)-1].version
		g.isFrontier = false

		for _, vid := range g.sorted {
			if vid.version == g.version {
				last = vid.id
				break
			}
		}
	} else {
		last = g.ids[len(g.ids)-1]
	}

	if isLeaf(last) {
		return true, nil
	}

	// Find the counter associated with the last id looked up.
	var ctr uint32
	for _, vid := range g.sorted {
		if vid.id == last {
			ctr = vid.version
			break
		}
	}

	// Find the next id to lookup.
	var (
		nextID uint64
		err    error
	)
	if ctr < g.version {
		if last == g.n-1 {
			return true, nil
		}
		nextID, err = implicitRight(last, g.pos, g.n)
		if err != nil {
			return false, err
		}
	} else {
		if last == g.pos {
			return true, nil
		}
		nextID, err = implicitLeft(last, g.pos, g.n)
		if err != nil {
			return false, err
		}
	}
	g.ids = append(g.ids, nextID)
	return false, nil
}

// nextID returns the next id to fetch from the database.
func (g *ProofGuide) nextID() uint64 {
	return g.ids[len(g.sorted)]
}

// Insert adds an id-counter pair to the guide.
func (g *ProofGuide) Insert(id uint64, ctr uint32) {
	g.sorted = append(g.sorted, versionedID{id: id, version: ctr})
}

// result returns the index and id that represent the final search result.
func (g *ProofGuide) result() (int, uint64, bool) {
	// Find the smallest id with version >= g.version that equals g.version.
	for _, vid := range g.sorted {
		if vid.version > g.version {
			return 0, 0, false
		}
		if vid.version == g.version {
			// Find the index in ids.
			for i, id := range g.ids {
				if id == vid.id {
					return i, vid.id, true
				}
			}
		}
	}
	return 0, 0, false
}

// Consume iterates over the ProofGuide by continuously calling poll until it
// returns true. Invokes step on each iteration passing it the current id.
// Returns the result index and id, or false if no result was found.
func (g *ProofGuide) Consume(step func(guide *ProofGuide, id uint64) error) (int, uint64, bool, error) {
	for {
		done, err := g.poll()
		if err != nil {
			return 0, 0, false, err
		}
		if done {
			idx, id, ok := g.result()
			return idx, id, ok, nil
		}
		nextID := g.nextID()
		if err := step(g, nextID); err != nil {
			return 0, 0, false, err
		}
	}
}
