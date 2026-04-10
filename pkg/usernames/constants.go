package usernames

import (
	"github.com/gtank/ristretto255"
)

// MaxNicknameLength is the maximum allowed length of a nickname.
// Going past 37^48 will overflow the Scalar.
const MaxNicknameLength = 48

// compressedBasePointsRaw contains the 3 compressed base points used for
// username hash computation.
var compressedBasePointsRaw = [3][32]byte{
	{
		0x60, 0xb9, 0x93, 0x66, 0x3a, 0x3d, 0xae, 0xcc,
		0x4c, 0x85, 0x2f, 0x53, 0x35, 0x47, 0xe3, 0x05,
		0x38, 0x8c, 0x2a, 0x50, 0xa5, 0x83, 0x93, 0xea,
		0x27, 0x7d, 0xe4, 0xab, 0xf3, 0xde, 0x54, 0x3a,
	},
	{
		0xf2, 0xb6, 0xf1, 0xc8, 0x26, 0xfa, 0x36, 0x40,
		0x20, 0x6f, 0x3b, 0x58, 0xb2, 0x28, 0x6b, 0xde,
		0xfd, 0xfd, 0xa6, 0xa5, 0x4f, 0xf9, 0x02, 0xf2,
		0x04, 0xa7, 0x2d, 0xe7, 0x37, 0xd2, 0x61, 0x57,
	},
	{
		0x06, 0x06, 0xbd, 0x3a, 0xbf, 0xce, 0x4e, 0x96,
		0x17, 0xd4, 0x48, 0xfb, 0x2c, 0xae, 0xb6, 0xcc,
		0x02, 0x8e, 0xc9, 0xa2, 0xb6, 0x2b, 0x10, 0xb3,
		0xd9, 0xeb, 0x29, 0x48, 0xda, 0x6f, 0x3f, 0x53,
	},
}

// basePoints holds the decompressed base points, initialized at package load time.
var basePoints [3]*ristretto255.Element

func init() {
	for i, raw := range compressedBasePointsRaw {
		e := ristretto255.NewIdentityElement()
		if _, err := e.SetCanonicalBytes(raw[:]); err != nil {
			panic("usernames: failed to decompress base point: " + err.Error())
		}
		basePoints[i] = e
	}
}

// discriminatorRange represents a half-open range [Start, End).
type discriminatorRange struct {
	Start int
	End   int
}

// discriminatorRanges defines the ranges from which random discriminators are drawn.
var discriminatorRanges = [8]discriminatorRange{
	{1, 100},
	{100, 1_000},
	{1_000, 10_000},
	{10_000, 100_000},
	{100_000, 1_000_000},
	{1_000_000, 10_000_000},
	{10_000_000, 100_000_000},
	{100_000_000, 1_000_000_000},
}

// candidatesPerRange specifies how many random discriminators to generate
// from each range when creating username candidates.
var candidatesPerRange = [8]int{4, 3, 3, 2, 2, 2, 2, 2}

// Username link constants.
const (
	UsernameLinkEntropySize = 32
	usernameLinkKeySize     = 32
	usernameLinkIVSize      = 16
	usernameLinkHMACLen     = 32
)

var (
	usernameLinkLabelEncryptionKey     = []byte("Signal Username Link Encryption Key")
	usernameLinkLabelAuthenticationKey = []byte("Signal Username Link Authentication Key")
)
