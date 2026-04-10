// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package keytrans

// implicitMoveWithin adjusts x to be within the range [start, n).
func implicitMoveWithin(x, start, n uint64) (uint64, error) {
	for x < start || x >= n {
		var err error
		if x < start {
			x, err = rightStep(x)
		} else {
			x, err = leftStep(x)
		}
		if err != nil {
			return 0, err
		}
	}
	return x, nil
}

// implicitRoot returns the position of the root node of a search.
func implicitRoot(start, n uint64) (uint64, error) {
	return implicitMoveWithin((1<<log2(n))-1, start, n)
}

// implicitLeft returns the left child of an intermediate node in the implicit tree.
func implicitLeft(x, start, n uint64) (uint64, error) {
	l, err := leftStep(x)
	if err != nil {
		return 0, err
	}
	return implicitMoveWithin(l, start, n)
}

// implicitRight returns the right child of an intermediate node in the implicit tree.
func implicitRight(x, start, n uint64) (uint64, error) {
	r, err := rightStep(x)
	if err != nil {
		return 0, err
	}
	return implicitMoveWithin(r, start, n)
}

// implicitParent returns the parent of x in a tree with n leaves.
func implicitParent(x, n uint64) uint64 {
	p := parentStep(x)
	for p >= n {
		p = parentStep(p)
	}
	return p
}

// implicitDirectPath returns the sequence of parent nodes from x to the root.
func implicitDirectPath(x, start, n uint64) ([]uint64, error) {
	r, err := implicitRoot(start, n)
	if err != nil {
		return nil, err
	}
	var path []uint64
	for x != r {
		x = implicitParent(x, n)
		path = append(path, x)
	}
	return path, nil
}

// monitoringPath returns the sequence of parent nodes to be checked as part of
// monitoring a single version of a key. Only returns parents greater than x.
func monitoringPath(x, start, n uint64) ([]uint64, error) {
	dp, err := implicitDirectPath(x, start, n)
	if err != nil {
		return nil, err
	}
	var path []uint64
	for _, p := range dp {
		if p > x {
			path = append(path, p)
		}
	}
	return path, nil
}

// implicitFrontier returns the frontier of the log.
func implicitFrontier(start, n uint64) ([]uint64, error) {
	last, err := implicitRoot(start, n)
	if err != nil {
		return nil, err
	}
	frontier := []uint64{last}
	for last != n-1 {
		last, err = implicitRight(last, start, n)
		if err != nil {
			return nil, err
		}
		frontier = append(frontier, last)
	}
	return frontier, nil
}

// monitoringFrontier returns the frontier nodes that still need to be monitored.
// It finds the last frontier node present in entries and returns all subsequent
// frontier nodes. Returns an error if no frontier entry matches, which indicates
// invalid input since monitoring paths must always terminate at some frontier node.
func monitoringFrontier(frontier []uint64, entries map[uint64]struct{}) ([]uint64, error) {
	idx := -1
	for i := len(frontier) - 1; i >= 0; i-- {
		if _, ok := entries[frontier[i]]; ok {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, &Error{kind: errorKindBadData, message: "no frontier entry matches any monitored node"}
	}
	result := make([]uint64, len(frontier)-(idx+1))
	copy(result, frontier[idx+1:])
	return result, nil
}

// fullMonitoringPath returns the full set of entries that should be checked as
// part of monitoring a particular version of a key.
func fullMonitoringPath(entry, start, n uint64) ([]uint64, error) {
	mp, err := monitoringPath(entry, start, n)
	if err != nil {
		return nil, err
	}
	var path []uint64
	dedup := make(map[uint64]struct{})
	for _, x := range mp {
		if _, ok := dedup[x]; !ok {
			dedup[x] = struct{}{}
			path = append(path, x)
		}
	}
	dedup[entry] = struct{}{}
	frontier, err := implicitFrontier(start, n)
	if err != nil {
		return nil, err
	}
	mf, err := monitoringFrontier(frontier, dedup)
	if err != nil {
		return nil, err
	}
	path = append(path, mf...)
	return path, nil
}

// firstParentToTheRight finds the first parent node which is to the right of the entry.
func firstParentToTheRight(entry uint64) uint64 {
	out := entry
	for out <= entry {
		out = parentStep(out)
	}
	return out + 1
}

// nextMonitor returns the smallest tree size where monitoring would be valuable.
func nextMonitor(entries []uint64) uint64 {
	if len(entries) == 0 {
		return 0
	}
	minVal := firstParentToTheRight(entries[0])
	for _, e := range entries[1:] {
		v := firstParentToTheRight(e)
		if v < minVal {
			minVal = v
		}
	}
	return minVal
}
