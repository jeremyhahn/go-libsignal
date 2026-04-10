# Key Transparency

Package `keytrans` implements client-side verification for Signal's key transparency system. It provides VRF proof verification, Merkle tree operations, an implicit binary search tree for log lookups, and a monitoring protocol to detect server misbehavior.

## Architecture

Key transparency binds a user's identity key to their account in a publicly auditable log. The system has three roles:

- **Server**: maintains an append-only transparency log of key updates
- **Client**: searches the log and monitors for unauthorized changes
- **Auditor**: independently verifies the log's consistency (in third-party auditing mode)

The client never trusts the server blindly. Every search result includes a VRF proof, prefix tree proof, inclusion proof, and signed tree head that the client verifies locally.

## VRF (Verifiable Random Function)

The VRF maps a search key to a deterministic, unpredictable index in the transparency tree. It uses ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381, suite ID 0x03).

### Public Key

```go
pk, err := keytrans.NewVRFPublicKey(compressedBytes)
```

`NewVRFPublicKey` decompresses the 32-byte Edwards25519 point and rejects small-order points by multiplying by the cofactor (8) via `edwards25519.Point.MultByCofactor` and checking for the identity element.

### Proof Verification

```go
hash, err := pk.ProofToHash(message, &proof)
```

`ProofToHash` takes a message and an 80-byte proof (`[32 gamma][16 c][32 s]`), then:

1. Decodes gamma as an Edwards25519 point, c as the lower 16 bytes of a 32-byte scalar, and s as a full scalar
2. Computes `H = encode_to_curve_try_and_increment(pk, message)` (see below)
3. Computes `U = [s]B + [-c]Y` and `V = [s]H + [-c]gamma` using variable-time multi-scalar multiplication
4. Recomputes the challenge from `(pk, H, gamma, U, V)` and verifies it matches c (constant-time, first 16 bytes)
5. Returns `vrfProofToHash(gamma)`, which multiplies gamma by the cofactor and hashes: `SHA-512(0x03 || 0x03 || cofactored || 0x00)`, truncated to 32 bytes

### Try-and-Increment Encoding

`encodeToCurveTryAndIncrement` hashes the message with a counter byte (0 to 255):

```
SHA-512(0x03 || 0x01 || public_key || message || counter || 0x00)
```

It attempts to decompress the first 32 bytes of each hash as an Edwards25519 point. On success, the point is multiplied by the cofactor and returned (rejecting the identity). Returns `ErrTryAndIncrementFailed` if all 256 attempts fail.

### Cofactor Multiplication

All cofactor multiplications use `edwards25519.Point.MultByCofactor`, which multiplies a point by 8. Applied in:

- `NewVRFPublicKey` (small-order point rejection)
- `encodeToCurveTryAndIncrement` (clearing the cofactor of hash-to-curve output)
- `vrfProofToHash` (clearing the cofactor of gamma before final hashing)

## Left-Balanced Binary Trees

The log tree uses a left-balanced binary representation where node positions encode both the node's location and its level in the tree. Leaves occupy even positions (level 0), and a node at position `x` has level equal to `bits.TrailingZeros64(^x)`.

### Node Navigation

| Function | Description |
|----------|-------------|
| `leftStep(x)` | Left child: `x ^ (1 << (k-1))` where k = level(x) |
| `rightStep(x)` | Right child: `x ^ (3 << (k-1))` |
| `parentStep(x)` | Parent node |
| `logLeft(x)` | Left child in the log tree |
| `logRight(x, n)` | Right child constrained to fit in a tree with n leaves |
| `logParent(x, n)` | Parent constrained to the tree width |
| `logSibling(x, n)` | The other child of the node's parent |

### Tree Metrics

- `logNodeWidth(n)` returns `2*(n-1) + 1` for n > 0 leaves
- `logRoot(n)` returns the root node ID: `(1 << log2(logNodeWidth(n))) - 1`

### Root Computation

`simpleRootCalculator` computes the Merkle root by accumulating hashes level by level. Each `nodeData` is a 33-byte value: 1 byte indicating whether the node is interior (1) or leaf (0), followed by a 32-byte SHA-256 hash. Interior hashes are computed as `SHA-256(left.marshal() || right.marshal())`.

Leaf hashes are computed by `verifyLeafHash(prefixRoot, commitment)` = `SHA-256(prefixRoot || commitment)`.

### Batch Inclusion Proofs

`EvaluateBatchProof` verifies that a set of leaf values at given positions are consistent with a claimed root. It computes the copath (the set of sibling nodes needed to reconstruct the root) via `logBatchCopath`, then feeds both the leaf values and the copath hashes into `simpleRootCalculator`.

### Consistency Proofs

`VerifyConsistencyProof(m, n, proof, mRoot, nRoot)` verifies that a tree of size m is a prefix of a tree of size n. It uses `logConsistencyProof` to compute the expected proof node IDs, then verifies that the proof hashes reconstruct both roots.

## Implicit Binary Search Tree

The transparency log stores versioned key updates. To find a specific version of a key, the client performs a binary search over an implicit tree structure that overlays the log entries for that key.

### Tree Structure

The implicit tree is defined over a range `[start, n)` of log entries. Unlike the left-balanced log tree, this tree constrains navigation to stay within the valid range using `implicitMoveWithin`, which repeatedly takes left or right steps until the node is within bounds.

| Function | Description |
|----------|-------------|
| `implicitRoot(start, n)` | Root of the implicit tree over [start, n) |
| `implicitLeft(x, start, n)` | Left child within [start, n) |
| `implicitRight(x, start, n)` | Right child within [start, n) |
| `implicitParent(x, n)` | Parent, skipping out-of-range nodes |
| `implicitDirectPath(x, start, n)` | Path from x to the root |
| `implicitFrontier(start, n)` | Frontier nodes (root + rightmost chain) |

### ProofGuide

`ProofGuide` drives the binary search by determining which nodes to query. It supports two modes:

- **Version search** (`NewProofGuide` with non-nil version): starts at `implicitRoot`, binary searches for the target version
- **Most recent** (`NewProofGuide` with nil version): starts at the frontier nodes

The `Consume` method iterates the search:

```go
guide, err := keytrans.NewProofGuide(version, pos, treeSize)
resultIdx, resultID, found, err := guide.Consume(func(g *keytrans.ProofGuide, nextID uint64) error {
    // fetch step from server, call g.Insert(nextID, counter)
    return nil
})
```

At each step, the guide compares the node's counter against the target version. If the counter is less than the target, it goes right (the version must be newer). Otherwise, it goes left (looking for an earlier occurrence). The search terminates at a leaf node or when the boundary is reached.

## Verification Functions

### VerifySearch

`VerifySearch` validates a search response from the server:

1. Evaluates the VRF proof to get the index for the search key
2. Runs the `ProofGuide` to traverse the implicit binary search tree
3. Evaluates prefix tree proofs and leaf hashes at each step
4. Verifies the batch inclusion proof against the tree root
5. Verifies the commitment opening against the search key and value
6. Validates the `FullTreeHead` (signatures, timestamps, consistency with prior state)
7. Updates monitoring data

```go
update, err := keytrans.VerifySearch(config, request, response, context, forceMonitor, time.Now())
```

### VerifyMonitor

`VerifyMonitor` validates a monitor response, checking that all monitored keys have consistent updates:

```go
update, err := keytrans.VerifyMonitor(config, request, response, context, time.Now())
```

### VerifyDistinguished

`VerifyDistinguished` checks that a `FullTreeHead` has a valid consistency proof relative to a distinguished (well-known) tree head.

## Tree Head Verification

`verifyFullTreeHead` performs a complete validation:

1. Checks consistency with the last seen tree head (monotonic size and timestamp)
2. Checks consistency with the last distinguished tree head
3. Verifies Ed25519 signatures from all required auditors
4. Validates the timestamp is within `maxTimestampBehind` (24 hours) and `maxTimestampAhead` (60 seconds)
5. For third-party auditing mode, verifies each auditor's tree head signature, timestamp (within 7 days behind), and consistency proof

## Monitoring

The monitoring system tracks key updates over time to detect unauthorized changes. `MonitoringData` stores:

- `Index`: the 32-byte VRF output for the search key
- `Pos`: the initial position in the log
- `Ptrs`: a map of log positions to version counters
- `Owned`: whether the client owns this key

`monitoringPath(x, start, n)` returns the parent nodes above x in the implicit tree that need to be checked. `fullMonitoringPath` extends this with frontier nodes. `nextMonitor` computes the smallest tree size at which monitoring would produce new information.

## Configuration

`PublicConfig` holds the public parameters for the transparency system:

| Field | Type | Description |
|-------|------|-------------|
| `Mode` | `DeploymentMode` | Third-party auditing or contact monitoring |
| `SignatureKey` | `ed25519.PublicKey` | Server's signing key |
| `VRFKey` | `*VRFPublicKey` | Server's VRF public key |

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `maxTimestampBehind` | 24 hours | Maximum age for server timestamps |
| `maxTimestampAhead` | 60 seconds | Maximum clock skew allowed |
| `maxAuditorTimestampBehind` | 7 days | Maximum age for auditor timestamps |
| `entriesMaxBehind` | 10,000,000 | Maximum entries an auditor can lag |
| `maxTreeSize` | 2^62 | Upper bound on tree size |

## Error Types

| Error | Description |
|-------|-------------|
| `Error` | General verification error with kind (required field missing, bad data, verification failed) |
| `LogError` | Log tree operation errors (malformed proof, proof mismatch, invalid input) |
| `ErrInvalidCurvePoint` | Edwards25519 point decompression failure or small-order |
| `ErrInvalidVRFProof` | VRF proof verification failure |
| `ErrTryAndIncrementFailed` | All 256 hash-to-curve attempts failed |
| `ErrLeafNodeHasNoChildren` | Navigation attempted on a leaf node |
| `ErrInvalidGuideState` | ProofGuide counters are not monotonic |
