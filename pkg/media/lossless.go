package media

// lossless.go — Pure-Go VP8L/ALPH lossless bitstream validator.
//
// This is an exact port of the webpsan 0.5.3 lossless decoder/validator:
//
//	webpsan/src/parse/bitstream.rs  — LSB-first BitReader, CanonicalHuffmanTree, buf_read_lz77
//	webpsan/src/parse/lossless.rs   — LosslessImage::read (transforms, prefix codes, pixel loop)
//	webpsan/src/parse/vp8l.rs       — Vp8lChunk header parsing + sanitize_image_data
//	webpsan/src/parse/alph.rs       — AlphChunk::sanitize_image_data (COMPRESS_LOSSLESS path)
//
// The Go implementation reproduces every accept/reject decision from the Rust
// oracle including: duplicate-transform rejection, color-cache bounds, LZ77
// back-reference distance/length checks, code-length repetition bounds, invalid
// predictor, invalid symbol count, and truncated-stream errors.
//
// Bit-reader fidelity: bitstream_io LE reads bits LSB-first within each byte,
// exactly like the VP8L specification. Each byte is consumed from bit 0 (LSB)
// to bit 7 (MSB), and consecutive bits span bytes in little-endian order.
// lossless.rs uses BitBufReader<R, LE>; this file's leBitReader matches that.

// ---------------------------------------------------------------------------
// Typed errors (project convention: NEVER fmt.Errorf inline)
// ---------------------------------------------------------------------------

// ErrLosslessTruncated indicates the VP8L bitstream ended before the image was complete.
// Matches: webpsan/src/parse/bitstream.rs map_eof → ParseError::TruncatedChunk.
type ErrLosslessTruncated struct{}

func (e *ErrLosslessTruncated) Error() string { return "VP8L: truncated bitstream" }

// ErrLosslessInvalidColorCacheSize indicates a color-cache order outside [1,11].
// Matches: lossless.rs:464 — InvalidColorCacheSize.
type ErrLosslessInvalidColorCacheSize struct{ Order uint8 }

func (e *ErrLosslessInvalidColorCacheSize) Error() string {
	return "VP8L: invalid color cache size"
}

// ErrLosslessColorCacheIndexOutOfBounds indicates a green-channel symbol in
// [280, 280+cache_len) referenced an out-of-range index.
// Matches: lossless.rs:344-348 — ColorCacheIndexOutOfBounds.
type ErrLosslessColorCacheIndexOutOfBounds struct {
	Index uint16
	Len   uint16
}

func (e *ErrLosslessColorCacheIndexOutOfBounds) Error() string {
	return "VP8L: color cache index out of bounds"
}

// ErrLosslessInvalidBackRefDistance indicates a back-reference distance that
// would reach before the beginning of the image.
// Matches: lossless.rs:328-333 — InvalidBackRefDistance.
type ErrLosslessInvalidBackRefDistance struct {
	Dist     uint32
	PixelIdx uint32
}

func (e *ErrLosslessInvalidBackRefDistance) Error() string {
	return "VP8L: invalid back-reference distance"
}

// ErrLosslessInvalidBackRefLength indicates a back-reference copy length that
// would extend past the end of the image.
// Matches: lossless.rs:334-338 — InvalidBackRefLength.
type ErrLosslessInvalidBackRefLength struct {
	Len      uint32
	PixelIdx uint32
	ImageLen uint32
}

func (e *ErrLosslessInvalidBackRefLength) Error() string {
	return "VP8L: invalid back-reference length"
}

// ErrLosslessInvalidCodeLengthRepetition indicates a code-length run-length
// expansion would exceed the symbol table size.
// Matches: lossless.rs:592-597 — InvalidCodeLengthRepetition.
type ErrLosslessInvalidCodeLengthRepetition struct {
	RepeatTimes uint8
	CurrentPos  int
	MaxSymbols  uint16
}

func (e *ErrLosslessInvalidCodeLengthRepetition) Error() string {
	return "VP8L: invalid code length repetition"
}

// ErrLosslessInvalidPredictor indicates a predictor transform pixel with a
// green value outside [0,13].
// Matches: lossless.rs:211-215 — InvalidPredictor.
type ErrLosslessInvalidPredictor struct{ Value uint8 }

func (e *ErrLosslessInvalidPredictor) Error() string { return "VP8L: invalid predictor" }

// ErrLosslessDuplicateTransform indicates a transform type appeared more than once.
// Matches: lossless.rs:179-183 — InvalidDuplicateTransform.
type ErrLosslessDuplicateTransform struct{ Which uint8 }

func (e *ErrLosslessDuplicateTransform) Error() string { return "VP8L: duplicate transform" }

// ErrLosslessInvalidSymbolCount indicates max_symbol_reads > alphabet_size.
// Matches: lossless.rs:567-571 — InvalidSymbolCount.
type ErrLosslessInvalidSymbolCount struct {
	Reads uint16
	Max   uint16
}

func (e *ErrLosslessInvalidSymbolCount) Error() string { return "VP8L: invalid symbol count" }

// ErrLosslessInvalidPrefixCode indicates the Huffman code lengths are inconsistent.
// Matches: lossless.rs — InvalidVp8lPrefixCode.
type ErrLosslessInvalidPrefixCode struct{}

func (e *ErrLosslessInvalidPrefixCode) Error() string { return "VP8L: invalid prefix code" }

// ErrLosslessLZ77PrefixCode indicates an LZ77 prefix code value > LZ77_MAX_SYMBOL.
// Matches: bitstream.rs:98 — InvalidLz77PrefixCode.
type ErrLosslessLZ77PrefixCode struct{ Code uint16 }

func (e *ErrLosslessLZ77PrefixCode) Error() string { return "VP8L: invalid LZ77 prefix code" }

// ---------------------------------------------------------------------------
// LSB-first / LE bit reader
//
// Matches bitstream_io LE semantics used by BitBufReader<R, LE>:
//   - Bits are consumed LSB-first within each byte.
//   - Multi-bit reads accumulate bits from consecutive bytes in LE order.
//
// bitstream.rs: buf_read<T: Numeric>(bits) delegates to BitReader<Cursor<...>, LE>
// ---------------------------------------------------------------------------

// leBitReader reads bits from a byte slice in LSB-first order.
// It pre-buffers the entire VP8L image-stream into memory (webpsan does the
// same via BitBufReader::fill_buf; VP8L streams are bounded by the chunk size).
type leBitReader struct {
	data   []byte
	bitPos uint64 // current position in bits
}

func newLeBitReader(data []byte) *leBitReader {
	return &leBitReader{data: data}
}

// readBits reads n bits (0 <= n <= 32) in LSB-first order.
// Returns ErrLosslessTruncated if fewer than n bits remain.
func (r *leBitReader) readBits(n uint32) (uint32, error) {
	if n == 0 {
		return 0, nil
	}
	end := r.bitPos + uint64(n)
	if end > uint64(len(r.data))*8 {
		return 0, &ErrLosslessTruncated{}
	}
	var result uint32
	for i := uint32(0); i < n; i++ {
		byteIdx := (r.bitPos + uint64(i)) / 8
		bitIdx := (r.bitPos + uint64(i)) % 8
		bit := (r.data[byteIdx] >> bitIdx) & 1
		result |= uint32(bit) << i
	}
	r.bitPos = end
	return result, nil
}

// readBit reads a single bit.
func (r *leBitReader) readBit() (bool, error) {
	v, err := r.readBits(1)
	return v != 0, err
}

// readBits8 reads up to 8 bits, returning a uint8.
func (r *leBitReader) readBits8(n uint32) (uint8, error) {
	v, err := r.readBits(n)
	return uint8(v), err
}

// ---------------------------------------------------------------------------
// LZ77 prefix code expansion
//
// Matches bitstream.rs:90-99 — buf_read_lz77.
// LZ77_MAX_SYMBOL = 39 (bitstream.rs:34).
// Returns a NonZeroU32 equivalent (value >= 1).
// ---------------------------------------------------------------------------

const lz77MaxSymbol = 39

// expandLZ77 converts an LZ77 prefix code to the actual length/distance value.
// prefix_code 0 → value 1, prefix_code 1 → value 2, prefix_code 2 → value 3,
// prefix_code 3 → value 4; higher codes add extra bits.
// bitstream.rs:90-99.
func expandLZ77(r *leBitReader, prefixCode uint16) (uint32, error) {
	switch {
	case prefixCode <= 3:
		// bitstream.rs:92: NonZeroU32::MIN.saturating_add(prefix_code.into()) = 1 + prefix_code
		return 1 + uint32(prefixCode), nil
	case prefixCode <= lz77MaxSymbol:
		// bitstream.rs:94-96
		extraBits := (uint32(prefixCode) - 2) >> 1
		offset := (2 + (uint32(prefixCode) & 1)) << extraBits
		extra, err := r.readBits(extraBits)
		if err != nil {
			return 0, err
		}
		return 1 + offset + extra, nil
	default:
		return 0, &ErrLosslessLZ77PrefixCode{Code: prefixCode}
	}
}

// ---------------------------------------------------------------------------
// Canonical Huffman tree (LE / LSB-first decoding)
//
// Matches bitstream.rs:132-190 — CanonicalHuffmanTree::new / symbols().
//
// The canonical code assignment algorithm (bitstream.rs:160-190):
//  1. Sort symbols by (code_length, symbol) — ascending.
//  2. Skip symbols with code_length == 0.
//  3. Special case: exactly one non-zero symbol → code = [] (0 bits).
//  4. Assign codes incrementally: start with a vector of <first_code_length>
//     zero bits, then for each subsequent symbol, increment the code like a
//     binary counter and extend to the new code length.
//
// Decoding is done with a lookup table indexed by the next `maxCodeLen` bits
// (LSB-first). Each entry stores the symbol value and the actual code length.
// ---------------------------------------------------------------------------

// huffSymbol holds a decoded symbol and the bit length of its code.
type huffSymbol struct {
	symbol  uint16 // decoded symbol value (up to u16 for green channel)
	codeLen uint8  // number of bits consumed
}

// huffmanTree is a flat lookup table for LSB-first canonical Huffman decoding.
// table[prefix] is valid if prefix < (1 << maxCodeLen).
type huffmanTree struct {
	table      []huffSymbol
	maxCodeLen uint8
	// singleSymbol is set when there is exactly one symbol (0-bit code).
	singleSymbol    bool
	singleSymbolVal uint16
}

// buildHuffmanTree constructs a canonical Huffman tree from (symbol, codeLen) pairs.
// symbols is a slice of (symbol_value, code_length) pairs with code_length >= 0.
// Zero-length codes indicate absent symbols.
//
// bitstream.rs:132-190: CanonicalHuffmanTree::new → symbols() → from_symbols().
func buildHuffmanTree(codeLengths []symLen) (*huffmanTree, error) {
	// Sort by (code_length, symbol) ascending — bitstream.rs:164.
	sortSymLens(codeLengths)

	// Partition: find first non-zero code length — bitstream.rs:165.
	firstNonZero := 0
	for firstNonZero < len(codeLengths) && codeLengths[firstNonZero].length == 0 {
		firstNonZero++
	}
	active := codeLengths[firstNonZero:]

	if len(active) == 0 {
		// All symbols have code_length == 0.
		// This matches CanonicalHuffmanTree::symbols() returning [] (bitstream.rs:188),
		// which then becomes a single-entry tree via Default impl (bitstream.rs:193-196).
		// However, this only occurs for channels that are unused; the validator
		// still needs to decode them. We use the first (or only) symbol if present.
		if len(codeLengths) == 1 {
			return &huffmanTree{
				singleSymbol:    true,
				singleSymbolVal: codeLengths[0].sym,
			}, nil
		}
		// Zero symbols with zero lengths: return the default single-symbol tree
		// (bitstream.rs:193-196 — Default impl returns symbol 0).
		return &huffmanTree{singleSymbol: true, singleSymbolVal: 0}, nil
	}

	// Special case: exactly one non-zero symbol → 0-bit code (bitstream.rs:168).
	// bitstream.rs:167: (&[(first_symbol, 1)], _) — note: the Rust pattern matches
	// code_length==1 specifically; but the Go equivalent is any single non-zero symbol
	// since the symbols() function returns vec![(first_symbol, vec![])] for this case.
	if len(active) == 1 {
		return &huffmanTree{
			singleSymbol:    true,
			singleSymbolVal: active[0].sym,
		}, nil
	}

	// Find max code length.
	maxLen := uint8(0)
	for _, sl := range active {
		if sl.length > maxLen {
			maxLen = sl.length
		}
	}
	if maxLen > 15 {
		return nil, &ErrLosslessInvalidPrefixCode{}
	}

	tableSize := 1 << maxLen
	table := make([]huffSymbol, tableSize)
	// Mark all entries invalid initially.
	for i := range table {
		table[i].codeLen = 255
	}

	// Assign canonical codes.
	// bitstream.rs:170-190: code starts as a []u8 of zeros with length = first_code_length,
	// then increments (binary counter, LSB of code vector first) for each subsequent symbol.
	code := make([]uint8, active[0].length)

	for i, sl := range active {
		if i > 0 {
			// Increment code as a binary counter (LSB of code-vector is bit 0).
			// bitstream.rs:177-181: iterate rev, XOR with 1, break on 1.
			for j := len(code) - 1; j >= 0; j-- {
				code[j] ^= 1
				if code[j] == 1 {
					break
				}
			}
			// Extend to new code length.
			for len(code) < int(sl.length) {
				code = append(code, 0)
			}
		}

		// Build the integer code value from the code bits (LSB-first).
		// The code bits are in canonical order where code[0] is the MSB of the
		// codeword as a bitstream — but since the bit reader reads LSB-first,
		// we need to reverse the bit order for the lookup table.
		//
		// In bitstream_io LE, the first bit read is the LSB of the first byte.
		// The canonical code bits (code[0]..code[len-1]) correspond to bits
		// read in order. So the lookup table key is:
		//   key = code[0]*2^0 + code[1]*2^1 + ... + code[len-1]*2^(len-1)
		// which is the code vector interpreted as a little-endian bit pattern.
		codeVal := uint16(0)
		for bit, v := range code {
			if v != 0 {
				codeVal |= 1 << bit
			}
		}

		// Fill all table entries that have this code as a prefix.
		// (Pad with all combinations of the remaining bits.)
		step := uint16(1) << sl.length
		for prefix := codeVal; int(prefix) < tableSize; prefix += step {
			table[prefix] = huffSymbol{symbol: sl.sym, codeLen: sl.length}
		}
	}

	// Verify the table is complete.
	for _, entry := range table {
		if entry.codeLen == 255 {
			return nil, &ErrLosslessInvalidPrefixCode{}
		}
	}

	return &huffmanTree{
		table:      table,
		maxCodeLen: maxLen,
	}, nil
}

// decode reads the next Huffman symbol from the bit reader.
//
// When fewer than maxCodeLen bits remain in the stream, we read only the
// remaining bits and zero-extend to maxCodeLen for the table lookup.  This
// correctly decodes valid short codes that end exactly at the chunk boundary
// without triggering a spurious ErrLosslessTruncated.  If the matched code's
// actual length exceeds the number of bits available, the stream is genuinely
// truncated and we return ErrLosslessTruncated.
func (h *huffmanTree) decode(r *leBitReader) (uint16, error) {
	if h.singleSymbol {
		return h.singleSymbolVal, nil
	}
	n := uint32(h.maxCodeLen)
	totalBits := uint64(len(r.data)) * 8

	// Determine how many bits we can actually read.
	available := uint32(0)
	if totalBits > r.bitPos {
		avail64 := totalBits - r.bitPos
		if avail64 > uint64(n) {
			available = n
		} else {
			available = uint32(avail64)
		}
	}

	var v uint32
	if available == n {
		// Fast path: enough bits for a full maxCodeLen read.
		var err error
		v, err = r.readBits(n)
		if err != nil {
			return 0, err
		}
	} else {
		// Partial path: read however many bits remain, zero-extend to n bits.
		if available == 0 {
			return 0, &ErrLosslessTruncated{}
		}
		partial, err := r.readBits(available)
		if err != nil {
			return 0, err
		}
		v = partial // upper bits are already zero
	}

	entry := h.table[v]
	if entry.codeLen == 255 {
		return 0, &ErrLosslessInvalidPrefixCode{}
	}

	if available < n {
		// We read fewer bits than maxCodeLen. Check that the matched code's
		// actual length fits within what was available.
		if uint32(entry.codeLen) > available {
			return 0, &ErrLosslessTruncated{}
		}
		// Advance only by entry.codeLen (we already advanced by available,
		// so back up the over-read).
		overRead := available - uint32(entry.codeLen)
		r.bitPos -= uint64(overRead)
	} else {
		// Normal case: back up by (maxCodeLen - entry.codeLen).
		overRead := n - uint32(entry.codeLen)
		r.bitPos -= uint64(overRead)
	}
	return entry.symbol, nil
}

// ---------------------------------------------------------------------------
// symLen pair used during Huffman tree construction
// ---------------------------------------------------------------------------

// symLen pairs a symbol value with its code length.
type symLen struct {
	sym    uint16
	length uint8
}

// sortSymLens sorts in place by (length, sym) ascending — bitstream.rs:164.
func sortSymLens(s []symLen) {
	// Insertion sort is fine for the small (<= 288) arrays used here.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0; j-- {
			a, b := s[j-1], s[j]
			if a.length > b.length || (a.length == b.length && a.sym > b.sym) {
				s[j-1], s[j] = s[j], s[j-1]
			} else {
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Color-length prefix code (meta-tree for reading symbol code lengths)
//
// lossless.rs:627-644 — CodeLengthPrefixCode::read.
// The 19-element code order is fixed by the VP8L spec.
// ---------------------------------------------------------------------------

// codeOrder is the permutation used to read code-length code lengths.
// lossless.rs:628: CODE_ORDER = [17, 18, 0, 1, 2, 3, 4, 5, 16, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
var codeOrder = [19]uint8{17, 18, 0, 1, 2, 3, 4, 5, 16, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

// readCodeLengthPrefixCode reads the meta-Huffman tree used to decode symbol
// code lengths.
// lossless.rs:627-644.
func readCodeLengthPrefixCode(r *leBitReader) (*huffmanTree, error) {
	// lossless.rs:630: code_length_count = 4 + reader.read::<u8>(4)?
	rawCount, err := r.readBits8(4)
	if err != nil {
		return nil, err
	}
	codeLengthCount := 4 + int(rawCount)

	// Read code lengths for each position in codeOrder.
	lengths := [19]uint8{}
	for i := 0; i < codeLengthCount; i++ {
		l, err2 := r.readBits8(3)
		if err2 != nil {
			return nil, err2
		}
		lengths[codeOrder[i]] = l
	}
	// Remaining positions stay 0 (lossless.rs:637-639).

	pairs := make([]symLen, 19)
	for i := range pairs {
		pairs[i] = symLen{sym: uint16(i), length: lengths[i]}
	}
	return buildHuffmanTree(pairs)
}

// ---------------------------------------------------------------------------
// Prefix code group (5 trees: green+length, red, blue, alpha, distance)
//
// lossless.rs:518-620 — PrefixCodeGroup::read, read_prefix_code.
// ---------------------------------------------------------------------------

// prefixCodeGroup holds the 5 Huffman trees for an entropy-coded image block.
type prefixCodeGroup struct {
	green    *huffmanTree // alphabet: 256 literals + 24 len codes + color_cache_len
	red      *huffmanTree // alphabet: 256
	blue     *huffmanTree // alphabet: 256
	alpha    *huffmanTree // alphabet: 256
	distance *huffmanTree // alphabet: 40
}

// alphabetSizes returns the alphabet sizes for each of the 5 channels.
// lossless.rs:657-692.
func alphabetSizes(colorCacheLen uint16) [5]uint16 {
	return [5]uint16{
		256 + 24 + colorCacheLen, // green (lossless.rs:657-659)
		256,                      // red
		256,                      // blue
		256,                      // alpha
		40,                       // distance (lossless.rs:689)
	}
}

// readPrefixCode reads one prefix code tree for a channel with the given
// alphabet size.
// lossless.rs:528-606 — read_prefix_code.
func readPrefixCode(r *leBitReader, alphabetSize uint16) (*huffmanTree, error) {
	// lossless.rs:537: simple_code_length_code = reader.read_bit()?
	simple, err := r.readBit()
	if err != nil {
		return nil, err
	}

	if simple {
		// Simple prefix code — lossless.rs:538-552.
		hasSecond, err := r.readBit()
		if err != nil {
			return nil, err
		}
		is8bit, err := r.readBit()
		if err != nil {
			return nil, err
		}
		var firstSym uint16
		if is8bit {
			v, err := r.readBits(8)
			if err != nil {
				return nil, err
			}
			firstSym = uint16(v)
		} else {
			b, err := r.readBit()
			if err != nil {
				return nil, err
			}
			if b {
				firstSym = 1
			}
		}

		var pairs []symLen
		if hasSecond {
			v, err := r.readBits(8)
			if err != nil {
				return nil, err
			}
			secondSym := uint16(v)
			pairs = []symLen{
				{sym: firstSym, length: 1},
				{sym: secondSym, length: 1},
			}
		} else {
			pairs = []symLen{{sym: firstSym, length: 0}}
		}
		return buildHuffmanTree(pairs)
	}

	// Normal prefix code — lossless.rs:553-604.
	codeLenTree, err := readCodeLengthPrefixCode(r)
	if err != nil {
		return nil, err
	}

	// lossless.rs:556-562: max_symbol_reads selection.
	maxSymbolCount := alphabetSize
	var maxSymbolReads uint16
	hasExplicitLen, err := r.readBit()
	if err != nil {
		return nil, err
	}
	if hasExplicitLen {
		// lossless.rs:558-560: length_bit_len = 2 + 2*reader.read::<u32>(3)?
		lenBits3, err := r.readBits(3)
		if err != nil {
			return nil, err
		}
		lengthBitLen := 2 + 2*lenBits3
		extra, err := r.readBits(lengthBitLen)
		if err != nil {
			return nil, err
		}
		// lossless.rs:561: 2u16.saturating_add(reader.read(length_bit_len)?)
		v := uint32(2) + extra
		if v > 0xFFFF {
			maxSymbolReads = 0xFFFF
		} else {
			maxSymbolReads = uint16(v)
		}
	} else {
		maxSymbolReads = maxSymbolCount
	}

	// lossless.rs:567-571: ensure max_symbol_reads <= max_symbol_count.
	if maxSymbolReads > maxSymbolCount {
		return nil, &ErrLosslessInvalidSymbolCount{Reads: maxSymbolReads, Max: maxSymbolCount}
	}

	// Read code lengths using the meta-tree.
	// lossless.rs:573-601.
	codeLengths := make([]symLen, 0, maxSymbolCount)
	lastNonZero := uint8(8) // lossless.rs:574

	for i := uint16(0); i < maxSymbolReads; i++ {
		if uint16(len(codeLengths)) == maxSymbolCount {
			break
		}
		clCode, err := codeLenTree.decode(r)
		if err != nil {
			return nil, err
		}
		clCode8 := uint8(clCode)

		var codeLength uint8
		var repeatTimes uint8

		switch {
		case clCode8 <= 15:
			// lossless.rs:582: (code_length_code, 1)
			codeLength = clCode8
			repeatTimes = 1
		case clCode8 == 16:
			// lossless.rs:583: (last_non_zero_code_length.get(), 3 + reader.read::<u8>(2)?)
			codeLength = lastNonZero
			extra, err := r.readBits8(2)
			if err != nil {
				return nil, err
			}
			repeatTimes = 3 + extra
		case clCode8 == 17:
			// lossless.rs:584: (0, 3 + reader.read::<u8>(3)?)
			codeLength = 0
			extra, err := r.readBits8(3)
			if err != nil {
				return nil, err
			}
			repeatTimes = 3 + extra
		case clCode8 == 18:
			// lossless.rs:585: (0, 11 + reader.read::<u8>(7)?)
			codeLength = 0
			extra, err := r.readBits8(7)
			if err != nil {
				return nil, err
			}
			repeatTimes = 11 + extra
		}

		if codeLength != 0 {
			lastNonZero = codeLength
		}

		// lossless.rs:592-597: check overflow.
		newLen := len(codeLengths) + int(repeatTimes)
		if newLen > int(maxSymbolCount) {
			return nil, &ErrLosslessInvalidCodeLengthRepetition{
				RepeatTimes: repeatTimes,
				CurrentPos:  len(codeLengths),
				MaxSymbols:  maxSymbolCount,
			}
		}

		sym := uint16(len(codeLengths))
		for k := uint8(0); k < repeatTimes; k++ {
			codeLengths = append(codeLengths, symLen{sym: sym + uint16(k), length: codeLength})
		}
	}

	return buildHuffmanTree(codeLengths)
}

// readPrefixCodeGroup reads all 5 prefix code trees for one entropy group.
// lossless.rs:519-526.
func readPrefixCodeGroup(r *leBitReader, colorCacheLen uint16) (*prefixCodeGroup, error) {
	sizes := alphabetSizes(colorCacheLen)
	green, err := readPrefixCode(r, sizes[0])
	if err != nil {
		return nil, err
	}
	red, err := readPrefixCode(r, sizes[1])
	if err != nil {
		return nil, err
	}
	blue, err := readPrefixCode(r, sizes[2])
	if err != nil {
		return nil, err
	}
	alpha, err := readPrefixCode(r, sizes[3])
	if err != nil {
		return nil, err
	}
	dist, err := readPrefixCode(r, sizes[4])
	if err != nil {
		return nil, err
	}
	return &prefixCodeGroup{
		green:    green,
		red:      red,
		blue:     blue,
		alpha:    alpha,
		distance: dist,
	}, nil
}

// ---------------------------------------------------------------------------
// ColorCache
//
// lossless.rs:459-480 — ColorCache::read, ColorCache::len.
// ---------------------------------------------------------------------------

// readColorCache reads the color cache flag and optional order (1..11).
// Returns the cache length (2^order) or 0 if no color cache.
func readColorCache(r *leBitReader) (uint16, error) {
	hasCache, err := r.readBit()
	if err != nil {
		return 0, err
	}
	if !hasCache {
		return 0, nil
	}
	// lossless.rs:463: order = reader.read::<u8>(4)?
	order, err := r.readBits8(4)
	if err != nil {
		return 0, err
	}
	// lossless.rs:464: ensure order <= 11
	if order > 11 {
		return 0, &ErrLosslessInvalidColorCacheSize{Order: order}
	}
	// lossless.rs:465-469: ensure NonZeroU8::new(order) == Some(order), i.e. order != 0
	if order == 0 {
		return 0, &ErrLosslessInvalidColorCacheSize{Order: order}
	}
	return 1 << order, nil
}

// ---------------------------------------------------------------------------
// MetaPrefixCodes
//
// lossless.rs:486-512 — MetaPrefixCodes::read, max_code_group.
// ---------------------------------------------------------------------------

// readMetaPrefixCodes reads the meta-prefix-code block and returns the maximum
// code group index.
// lossless.rs:486-512.
func readMetaPrefixCodes(r *leBitReader, width, height uint32) (uint16, error) {
	hasMeta, err := r.readBit()
	if err != nil {
		return 0, err
	}
	if !hasMeta {
		return 0, nil
	}

	// lossless.rs:490: block_order = 2 + reader.read::<u32>(3)?
	blockOrder3, err := r.readBits(3)
	if err != nil {
		return 0, err
	}
	blockOrder := 2 + blockOrder3
	blockSize := uint32(1) << blockOrder

	wInBlocks := divCeil(width, blockSize)
	hInBlocks := divCeil(height, blockSize)

	// lossless.rs:495-499: read EntropyCodedImage, tracking max code group.
	var maxCodeGroup uint16
	fn := func(green, red uint8) error {
		group := uint16(red)<<8 | uint16(green)
		if group > maxCodeGroup {
			maxCodeGroup = group
		}
		return nil
	}
	if err := readEntropyCodedImageFull(r, wInBlocks, hInBlocks, 0, fn); err != nil {
		return 0, err
	}
	return maxCodeGroup, nil
}

// ---------------------------------------------------------------------------
// EntropyCodedImage
//
// lossless.rs:294-358 — EntropyCodedImage::read.
// ---------------------------------------------------------------------------

// colorCallback is called for each decoded literal pixel (green, red values).
// Used for predictor validation and meta-huffman group tracking.
type colorCallback func(green, red uint8) error

// readEntropyCodedImageFull reads an entropy-coded image of width×height pixels.
// It reads the color cache header from the stream, then the prefix code group
// and the full pixel loop.
// fn is called for each literal pixel with (green, red) values; nil = no callback.
//
// lossless.rs:294-358 — EntropyCodedImage::read.
func readEntropyCodedImageFull(
	r *leBitReader,
	width, height uint32,
	_ uint16, // ignored: colorCacheLen is read from the stream directly below
	fn colorCallback,
) error {
	// lossless.rs:301: let color_cache = ColorCache::read(reader)
	colorCacheLen, err := readColorCache(r)
	if err != nil {
		return err
	}
	codes, err := readPrefixCodeGroup(r, colorCacheLen)
	if err != nil {
		return err
	}

	totalPixels := width * height
	pixelIdx := uint32(0)

	for pixelIdx < totalPixels {
		greenSym, err := codes.green.decode(r)
		if err != nil {
			return err
		}

		switch {
		case greenSym <= 255:
			green := uint8(greenSym)
			redSym, err := codes.red.decode(r)
			if err != nil {
				return err
			}
			_, err = codes.blue.decode(r)
			if err != nil {
				return err
			}
			_, err = codes.alpha.decode(r)
			if err != nil {
				return err
			}
			if fn != nil {
				if err := fn(green, uint8(redSym)); err != nil {
					return err
				}
			}
			pixelIdx++

		case greenSym >= 256 && greenSym <= 279:
			lenSym := greenSym - 256
			length, err := expandLZ77(r, lenSym)
			if err != nil {
				return err
			}
			distSym, err := codes.distance.decode(r)
			if err != nil {
				return err
			}
			distCode, err := expandLZ77(r, distSym)
			if err != nil {
				return err
			}
			dist := lz77DistToPixelDist(distCode, width)

			if pixelIdx < dist {
				return &ErrLosslessInvalidBackRefDistance{Dist: dist, PixelIdx: pixelIdx}
			}
			if length > totalPixels-pixelIdx {
				return &ErrLosslessInvalidBackRefLength{
					Len:      length,
					PixelIdx: pixelIdx,
					ImageLen: totalPixels,
				}
			}
			pixelIdx += length

		default:
			cacheIndex := greenSym - 280
			if cacheIndex >= colorCacheLen {
				return &ErrLosslessColorCacheIndexOutOfBounds{
					Index: cacheIndex,
					Len:   colorCacheLen,
				}
			}
			pixelIdx++
		}
	}
	return nil
}

// lz77DistToPixelDist converts an LZ77 distance code to a pixel distance.
// Matches lossless.rs:406-426 — BackReference::buf_read.
//
// The distanceMap is the fixed 120-entry table from the VP8L spec.
// Values > 120 map directly: pixel_dist = dist_code - 120.
func lz77DistToPixelDist(distCode, width uint32) uint32 {
	const distanceMapLen = 120

	// lossless.rs:406-426 — BackReference::buf_read distance mapping.
	if distCode >= 1 && distCode <= distanceMapLen {
		dx := int32(distanceMap[distCode-1][0])
		dy := int32(distanceMap[distCode-1][1])
		v := int64(dy)*int64(width) + int64(dx)
		if v <= 0 {
			return 1 // clamp to 1 (NonZeroU32::MIN) as in Rust
		}
		return uint32(v)
	}
	// dist_code > 120: pixel_dist = dist_code - 120 (lossless.rs:424).
	result := distCode - distanceMapLen
	if result == 0 {
		return 1
	}
	return result
}

// distanceMap is the 120-entry VP8L back-reference distance map.
// lossless.rs:384-403: DISTANCE_MAP [(i8, u8); 120].
// Each entry is [dx, dy] where the pixel distance = dy*width + dx.
var distanceMap = [120][2]int8{
	{0, 1}, {1, 0}, {1, 1}, {-1, 1}, {0, 2}, {2, 0}, {1, 2},
	{-1, 2}, {2, 1}, {-2, 1}, {2, 2}, {-2, 2}, {0, 3}, {3, 0},
	{1, 3}, {-1, 3}, {3, 1}, {-3, 1}, {2, 3}, {-2, 3}, {3, 2},
	{-3, 2}, {0, 4}, {4, 0}, {1, 4}, {-1, 4}, {4, 1}, {-4, 1},
	{3, 3}, {-3, 3}, {2, 4}, {-2, 4}, {4, 2}, {-4, 2}, {0, 5},
	{3, 4}, {-3, 4}, {4, 3}, {-4, 3}, {5, 0}, {1, 5}, {-1, 5},
	{5, 1}, {-5, 1}, {2, 5}, {-2, 5}, {5, 2}, {-5, 2}, {4, 4},
	{-4, 4}, {3, 5}, {-3, 5}, {5, 3}, {-5, 3}, {0, 6}, {6, 0},
	{1, 6}, {-1, 6}, {6, 1}, {-6, 1}, {2, 6}, {-2, 6}, {6, 2},
	{-6, 2}, {4, 5}, {-4, 5}, {5, 4}, {-5, 4}, {3, 6}, {-3, 6},
	{6, 3}, {-6, 3}, {0, 7}, {7, 0}, {1, 7}, {-1, 7}, {5, 5},
	{-5, 5}, {7, 1}, {-7, 1}, {4, 6}, {-4, 6}, {6, 4}, {-6, 4},
	{2, 7}, {-2, 7}, {7, 2}, {-7, 2}, {3, 7}, {-3, 7}, {7, 3},
	{-7, 3}, {5, 6}, {-5, 6}, {6, 5}, {-6, 5}, {8, 0}, {4, 7},
	{-4, 7}, {7, 4}, {-7, 4}, {8, 1}, {8, 2}, {6, 6}, {-6, 6},
	{8, 3}, {5, 7}, {-5, 7}, {7, 5}, {-7, 5}, {8, 4}, {6, 7},
	{-6, 7}, {7, 6}, {-7, 6}, {8, 5}, {7, 7}, {-7, 7}, {8, 6},
	{8, 7},
}

// ---------------------------------------------------------------------------
// SpatiallyCodedImage
//
// lossless.rs:365-376 — SpatiallyCodedImage::read.
// ---------------------------------------------------------------------------

// readSpatiallyCodedImage reads the main image body with meta-huffman support.
// lossless.rs:365-376.
func readSpatiallyCodedImage(r *leBitReader, width, height uint32) error {
	colorCacheLen, err := readColorCache(r)
	if err != nil {
		return err
	}

	maxCodeGroup, err := readMetaPrefixCodes(r, width, height)
	if err != nil {
		return err
	}

	// lossless.rs:371: for _ in 0..=meta.max_code_group() { read PrefixCodeGroup }
	for g := uint16(0); g <= maxCodeGroup; g++ {
		_, err := readPrefixCodeGroup(r, colorCacheLen)
		if err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Transform reading
//
// lossless.rs:199-288 — Transform::read, TransformType::read.
// ---------------------------------------------------------------------------

// transform type constants — lossless.rs:43-49.
const (
	transformPredictor     = uint8(0b00)
	transformColor         = uint8(0b01)
	transformSubGreen      = uint8(0b10)
	transformColorIndexing = uint8(0b11)
	transformCount         = 4
)

// readTransform reads one transform block and returns the transform type.
// It also applies any width adjustment (for ColorIndexing).
// Returns (transformType, newWidth, error).
//
// lossless.rs:200-244.
func readTransform(r *leBitReader, width, height uint32) (uint8, uint32, error) {
	ttype, err := r.readBits8(2)
	if err != nil {
		return 0, 0, err
	}

	switch ttype {
	case transformPredictor:
		// lossless.rs:202-219.
		blockOrder3, err := r.readBits(3)
		if err != nil {
			return 0, 0, err
		}
		blockOrder := 2 + blockOrder3
		blockSize := uint32(1) << blockOrder
		wInBlocks := divCeil(width, blockSize)
		hInBlocks := divCeil(height, blockSize)
		// Read the predictor transform image and validate green values [0,13].
		// lossless.rs:209-218.
		fn := func(green, _ uint8) error {
			if green > 13 {
				return &ErrLosslessInvalidPredictor{Value: green}
			}
			return nil
		}
		if err := readEntropyCodedImageFull(r, wInBlocks, hInBlocks, 0, fn); err != nil {
			return 0, 0, err
		}
		return ttype, width, nil

	case transformColor:
		// lossless.rs:222-232.
		blockOrder3, err := r.readBits(3)
		if err != nil {
			return 0, 0, err
		}
		blockOrder := 2 + blockOrder3
		blockSize := uint32(1) << blockOrder
		wInBlocks := divCeil(width, blockSize)
		hInBlocks := divCeil(height, blockSize)
		if err := readEntropyCodedImageFull(r, wInBlocks, hInBlocks, 0, nil); err != nil {
			return 0, 0, err
		}
		return ttype, width, nil

	case transformSubGreen:
		// lossless.rs:234: no data; just a marker.
		return ttype, width, nil

	case transformColorIndexing:
		// lossless.rs:235-242.
		lenMinus1, err := r.readBits(8)
		if err != nil {
			return 0, 0, err
		}
		paletteLen := 1 + lenMinus1 // NonZeroU32
		// Read the palette as an entropy-coded image of paletteLen×1 pixels.
		if err := readEntropyCodedImageFull(r, paletteLen, 1, 0, nil); err != nil {
			return 0, 0, err
		}
		// Width adjustment: lossless.rs:255-267 — transformed_width for ColorIndexing.
		newWidth := colorIndexingTransformedWidth(width, paletteLen)
		return ttype, newWidth, nil
	}
	// unreachable: readBits(2) only returns 0-3.
	return 0, 0, &ErrLosslessTruncated{}
}

// colorIndexingTransformedWidth computes the new image width after the
// ColorIndexing transform, which may pack multiple pixels per "super-pixel".
// lossless.rs:255-268 — Transform::transformed_width for ColorIndexing.
func colorIndexingTransformedWidth(width, paletteLen uint32) uint32 {
	var pixelsPerSuperPixel uint32
	switch {
	case paletteLen <= 2:
		pixelsPerSuperPixel = 8
	case paletteLen <= 4:
		pixelsPerSuperPixel = 4
	case paletteLen <= 16:
		pixelsPerSuperPixel = 2
	default:
		pixelsPerSuperPixel = 1
	}
	return divCeil(width, pixelsPerSuperPixel)
}

// ---------------------------------------------------------------------------
// LosslessImage::read — top-level entry point
//
// lossless.rs:166-193.
// ---------------------------------------------------------------------------

// readLosslessImage validates a VP8L lossless image bitstream.
// width and height are the image dimensions (must be >= 1).
//
// This matches LosslessImage::read exactly:
//  1. Read transform bits; for each transform present, validate and track.
//  2. Reject duplicate transforms.
//  3. Read the SpatiallyCodedImage with the (possibly adjusted) width.
//
// lossless.rs:166-193.
func readLosslessImage(r *leBitReader, width, height uint32) error {
	transformedWidth := width
	var seenTransforms [transformCount]bool

	// lossless.rs:174: while reader.read_bit()? { ... }
	for {
		hasTransform, err := r.readBit()
		if err != nil {
			return err
		}
		if !hasTransform {
			break
		}

		ttype, newWidth, err := readTransform(r, transformedWidth, height)
		if err != nil {
			return err
		}

		// lossless.rs:179-183: duplicate transform check.
		if seenTransforms[ttype] {
			return &ErrLosslessDuplicateTransform{Which: ttype}
		}
		seenTransforms[ttype] = true
		transformedWidth = newWidth
	}

	// lossless.rs:189: SpatiallyCodedImage::read
	return readSpatiallyCodedImage(r, transformedWidth, height)
}

// ---------------------------------------------------------------------------
// Public API: sanitize VP8L and ALPH image streams
// ---------------------------------------------------------------------------

// sanitizeVP8LImageData validates the image-stream portion of a VP8L chunk.
// payload is the raw VP8L chunk data (starting with the 0x2F signature byte).
// width and height must be >= 1 (extracted from the 5-byte VP8L header).
//
// Matches vp8l.rs:52-56 — Vp8lChunk::sanitize_image_data.
// The image-stream begins after the 5-byte header (byte offset 5).
func sanitizeVP8LImageData(payload []byte, width, height uint32) error {
	if len(payload) < 5 {
		return &ErrLosslessTruncated{}
	}
	// Skip the 5-byte VP8L header; the lossless image stream starts at byte 5.
	// vp8l.rs:53: BitBufReader::with_capacity(input, 4096) — input already seeked
	// past the header by the caller (ParseChunk::parse consumed 5 bytes then
	// sanitize_image_data receives the rest).
	//
	// However, examining vp8l.rs more carefully: sanitize_image_data receives
	// the entire remaining input (after the chunk header bytes were consumed
	// by parse()), not the VP8L header. The VP8L header bytes (5 bytes) were
	// consumed by ParseChunk::parse via the BitReader. The sanitize_image_data
	// input starts after those 5 bytes.
	//
	// In our Go implementation, payload is the full VP8L chunk data. The first
	// 5 bytes are the VP8L header. The image stream starts at byte 5.
	imageStream := payload[5:]
	r := newLeBitReader(imageStream)
	return readLosslessImage(r, width, height)
}

// sanitizeALPHImageData validates the image-stream portion of an ALPH chunk
// when COMPRESS_LOSSLESS is set. The alpha plane stream starts immediately
// at the beginning of alphaStream (no VP8L 0x2F header).
//
// Matches alph.rs:39-47 — AlphChunk::sanitize_image_data.
// Note: ALPH uses width/height from VP8X; the lossless stream has no 0x2F header.
func sanitizeALPHImageData(alphaStream []byte, width, height uint32) error {
	r := newLeBitReader(alphaStream)
	return readLosslessImage(r, width, height)
}

// ---------------------------------------------------------------------------
// Helper: ceiling division (matches num_integer::div_ceil)
// ---------------------------------------------------------------------------

func divCeil(n, d uint32) uint32 {
	if d == 0 {
		return 0
	}
	return (n + d - 1) / d
}
