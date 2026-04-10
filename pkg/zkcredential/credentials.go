package zkcredential

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/gtank/ristretto255"
)

// zeroScalar overwrites a ristretto255.Scalar with the zero value.
// runtime.KeepAlive prevents the compiler from eliminating the zeroing as dead writes.
func zeroScalar(s *ristretto255.Scalar) {
	if s != nil {
		s.Zero()
		runtime.KeepAlive(s)
	}
}

// NumSupportedAttrs is the maximum number of attribute points supported.
// This is 1 aggregate public + 3 two-point private = 7.
const NumSupportedAttrs = 7

// Credential is a credential created by the issuing server over a set of
// attributes, consisting of a MAC.
//
// Defined in Chase-Perrin-Zaverucha section 3.1.
type Credential struct {
	T *ristretto255.Scalar
	U *ristretto255.Element
	V *ristretto255.Element
}

// CredentialPrivateKey is a secret key used to compute a MAC over attributes.
//
// Defined in Chase-Perrin-Zaverucha section 3.1.
type CredentialPrivateKey struct {
	W      *ristretto255.Scalar
	Wprime *ristretto255.Scalar
	Wpoint *ristretto255.Element // W = w * G_w
	X0     *ristretto255.Scalar
	X1     *ristretto255.Scalar
	Y      [NumSupportedAttrs]*ristretto255.Scalar
}

// Generate creates a new CredentialPrivateKey from randomness.
func generateCredentialPrivateKey(randomness [RandomnessLen]byte) *CredentialPrivateKey {
	sho := NewShoHmacSha256Ext("Signal_ZKCredential_CredentialPrivateKey_generate_20230410")
	sho.AbsorbAndRatchet(randomness[:])

	system := GetSystemParams()
	w := sho.MustGetScalar()
	// W = w * G_w
	Wpoint := new(ristretto255.Element).ScalarMult(w, system.Gw)
	wprime := sho.MustGetScalar()
	x0 := sho.MustGetScalar()
	x1 := sho.MustGetScalar()

	var y [NumSupportedAttrs]*ristretto255.Scalar
	for i := range y {
		y[i] = sho.MustGetScalar()
	}

	return &CredentialPrivateKey{
		W:      w,
		Wprime: wprime,
		Wpoint: Wpoint,
		X0:     x0,
		X1:     x1,
		Y:      y,
	}
}

// Zeroize overwrites all private scalar fields with zeros.
// This should be called when the key is no longer needed to prevent
// sensitive key material from lingering in memory.
func (pk *CredentialPrivateKey) Zeroize() {
	zeroScalar(pk.W)
	zeroScalar(pk.Wprime)
	zeroScalar(pk.X0)
	zeroScalar(pk.X1)
	for i := range pk.Y {
		zeroScalar(pk.Y[i])
		pk.Y[i] = nil
	}
	pk.W = nil
	pk.Wprime = nil
	pk.Wpoint = nil
	pk.X0 = nil
	pk.X1 = nil
}

// CredentialCore computes the MAC over the given attribute points.
//
// Implements the credential computation from Chase-Perrin-Zaverucha section 3.1.
func (pk *CredentialPrivateKey) CredentialCore(
	M []*ristretto255.Element,
	sho *ShoExt,
) (*Credential, error) {
	if len(M) > NumSupportedAttrs {
		return nil, &ErrTooManyAttributes{Max: NumSupportedAttrs}
	}

	t, err := sho.GetScalar()
	if err != nil {
		return nil, &ErrDerivingScalar{Label: "scalar t", Err: err}
	}
	U, err := sho.GetPoint()
	if err != nil {
		return nil, &ErrDerivingPoint{Label: "point U", Err: err}
	}

	// V = W + (x0 + x1*t) * U
	x1t := new(ristretto255.Scalar).Multiply(pk.X1, t)
	x0x1t := new(ristretto255.Scalar).Add(pk.X0, x1t)
	V := new(ristretto255.Element).ScalarMult(x0x1t, U)
	V = V.Add(V, pk.Wpoint)

	// V += sum(yn * Mn)
	for i, Mn := range M {
		yMn := new(ristretto255.Element).ScalarMult(pk.Y[i], Mn)
		V = V.Add(V, yMn)
	}

	return &Credential{
		T: t,
		U: U,
		V: V,
	}, nil
}

// generateCredentialPrivateKeyFromSHO creates a new CredentialPrivateKey by
// drawing scalars from an existing SHO instance. Unlike generateCredentialPrivateKey,
// this does not create a new SHO — it consumes state from the provided one,
// allowing multiple key pairs to be chained through a single SHO.
func generateCredentialPrivateKeyFromSHO(sho *ShoExt) *CredentialPrivateKey {
	return generateCredentialPrivateKeyFromSHOWithStorage(sho, NumSupportedAttrs)
}

// generateCredentialPrivateKeyFromSHOWithStorage creates a new CredentialPrivateKey
// by drawing exactly storageLen y-scalars from the SHO. Legacy credential types
// in zkgroup use fewer y-scalars than the modern zkcredential system (7). The
// storageLen parameter controls how many scalars are drawn from the SHO, which
// is critical for keeping the SHO state aligned with the Rust reference
// implementation during chained key generation.
func generateCredentialPrivateKeyFromSHOWithStorage(sho *ShoExt, storageLen int) *CredentialPrivateKey {
	system := GetSystemParams()
	w := sho.MustGetScalar()
	Wpoint := new(ristretto255.Element).ScalarMult(w, system.Gw)
	wprime := sho.MustGetScalar()
	x0 := sho.MustGetScalar()
	x1 := sho.MustGetScalar()

	var y [NumSupportedAttrs]*ristretto255.Scalar
	for i := 0; i < storageLen; i++ {
		y[i] = sho.MustGetScalar()
	}

	return &CredentialPrivateKey{
		W:      w,
		Wprime: wprime,
		Wpoint: Wpoint,
		X0:     x0,
		X1:     x1,
		Y:      y,
	}
}

// generateCredentialPrivateKeyFromSHOWithLegacyParams creates a new CredentialPrivateKey
// using legacy system parameters for the W point computation. This matches the
// Rust reference implementation where legacy credential key pairs use the
// hardcoded legacy SystemParams generator points.
func generateCredentialPrivateKeyFromSHOWithLegacyParams(sho *ShoExt, storageLen int, legacy *LegacySystemParams) *CredentialPrivateKey {
	w := sho.MustGetScalar()
	Wpoint := new(ristretto255.Element).ScalarMult(w, legacy.Gw)
	wprime := sho.MustGetScalar()
	x0 := sho.MustGetScalar()
	x1 := sho.MustGetScalar()

	var y [NumSupportedAttrs]*ristretto255.Scalar
	for i := 0; i < storageLen; i++ {
		y[i] = sho.MustGetScalar()
	}

	return &CredentialPrivateKey{
		W:      w,
		Wprime: wprime,
		Wpoint: Wpoint,
		X0:     x0,
		X1:     x1,
		Y:      y,
	}
}

// legacyCredentialPublicKeyFromPrivate derives a CredentialPublicKey from a
// CredentialPrivateKey using the legacy hardcoded system parameters. This matches
// the Rust reference implementation where legacy credential public keys are
// computed using hardcoded generator points rather than SHO-derived ones.
func legacyCredentialPublicKeyFromPrivate(priv *CredentialPrivateKey, numAttrs int, legacy *LegacySystemParams) *CredentialPublicKey {
	// C_W = W + wprime * G_wprime  (using legacy G_wprime)
	wprimeGwp := new(ristretto255.Element).ScalarMult(priv.Wprime, legacy.Gwprime)
	CW := new(ristretto255.Element).Add(priv.Wpoint, wprimeGwp)

	// I_i = G_V - x0*G_x0 - x1*G_x1 - sum(yn*G_yn, n=0..i)  (using legacy points)
	x0Gx0 := new(ristretto255.Element).ScalarMult(priv.X0, legacy.Gx0)
	x1Gx1 := new(ristretto255.Element).ScalarMult(priv.X1, legacy.Gx1)
	Ii := new(ristretto255.Element).Subtract(legacy.GV, x0Gx0)
	Ii = Ii.Subtract(Ii, x1Gx1)

	// Subtract y0 * G_y0 first
	y0Gy0 := new(ristretto255.Element).ScalarMult(priv.Y[0], legacy.Gy[0])
	Ii = Ii.Subtract(Ii, y0Gy0)

	var I [NumSupportedAttrs - 1]*ristretto255.Element
	computeCount := numAttrs - 1
	if computeCount > NumSupportedAttrs-1 {
		computeCount = NumSupportedAttrs - 1
	}
	for n := 0; n < computeCount; n++ {
		// Subtract y_{n+1} * G_y_{n+1}
		yGy := new(ristretto255.Element).ScalarMult(priv.Y[n+1], legacy.Gy[n+1])
		Ii = new(ristretto255.Element).Subtract(Ii, yGy)
		I[n] = new(ristretto255.Element).Set(Ii)
	}

	return &CredentialPublicKey{
		CW: CW,
		I:  I,
	}
}

// GenerateCredentialKeyPairFromSHO generates a new key pair by drawing
// scalars from an existing SHO instance. This allows multiple key pair
// generations to be chained through a single SHO, matching the Rust
// reference implementation's ServerSecretParams::generate behavior.
func GenerateCredentialKeyPairFromSHO(sho *ShoExt) *CredentialKeyPair {
	return GenerateCredentialKeyPairFromSHOWithStorage(sho, NumSupportedAttrs, NumSupportedAttrs)
}

// GenerateCredentialKeyPairFromSHOWithStorage generates a key pair by drawing
// exactly storageLen y-scalars from the SHO and computing the public key I
// values using only numAttrs Gy points. This is required for legacy zkgroup
// credential types which use fewer y-scalars and Gy points than the modern
// zkcredential system.
//
// storageLen controls how many y-scalars are drawn from the SHO (affects SHO
// state advancement). numAttrs controls how many Gy points are used in the
// public key I computation.
func GenerateCredentialKeyPairFromSHOWithStorage(sho *ShoExt, storageLen int, numAttrs int) *CredentialKeyPair {
	if numAttrs <= LegacyNumSupportedAttrs {
		legacy := GetLegacySystemParams()
		priv := generateCredentialPrivateKeyFromSHOWithLegacyParams(sho, storageLen, legacy)
		pub := legacyCredentialPublicKeyFromPrivate(priv, numAttrs, legacy)
		return &CredentialKeyPair{
			privateKey: priv,
			publicKey:  pub,
		}
	}
	priv := generateCredentialPrivateKeyFromSHOWithStorage(sho, storageLen)
	pub := credentialPublicKeyFromPrivateWithAttrs(priv, numAttrs)
	return &CredentialKeyPair{
		privateKey: priv,
		publicKey:  pub,
	}
}

// CredentialPublicKey is a public key used by the client to receive and
// verify credentials.
//
// Defined in Chase-Perrin-Zaverucha section 3.1.
type CredentialPublicKey struct {
	CW *ristretto255.Element
	// I[i] corresponds to I_{i+2} (we skip I_0 and I_1).
	I [NumSupportedAttrs - 1]*ristretto255.Element
}

// GetI returns the I value for the given total number of attribute points.
func (cpk *CredentialPublicKey) GetI(numAttrs int) *ristretto255.Element {
	// -1 because one-based to zero-based
	// -1 because we skip I_0
	return cpk.I[numAttrs-2]
}

// CredentialPublicKeyFromPrivate derives a CredentialPublicKey from a
// CredentialPrivateKey using all NumSupportedAttrs Gy points.
func CredentialPublicKeyFromPrivate(priv *CredentialPrivateKey) *CredentialPublicKey {
	return credentialPublicKeyFromPrivateWithAttrs(priv, NumSupportedAttrs)
}

// credentialPublicKeyFromPrivateWithAttrs derives a CredentialPublicKey from a
// CredentialPrivateKey using only numAttrs Gy points for the I computation.
// Legacy credential types use fewer Gy points than the modern system.
//
// The I array always has NumSupportedAttrs-1 slots, but only the first
// numAttrs-1 entries are populated. Legacy credential consumers only access
// the entries they need via GetI(totalAttrCount).
func credentialPublicKeyFromPrivateWithAttrs(priv *CredentialPrivateKey, numAttrs int) *CredentialPublicKey {
	system := GetSystemParams()

	// C_W = W + wprime * G_wprime
	wprimeGwp := new(ristretto255.Element).ScalarMult(priv.Wprime, system.Gwprime)
	CW := new(ristretto255.Element).Add(priv.Wpoint, wprimeGwp)

	// I_i = G_V - x0*G_x0 - x1*G_x1 - sum(yn*G_yn, n=0..i)
	x0Gx0 := new(ristretto255.Element).ScalarMult(priv.X0, system.Gx0)
	x1Gx1 := new(ristretto255.Element).ScalarMult(priv.X1, system.Gx1)
	Ii := new(ristretto255.Element).Subtract(system.GV, x0Gx0)
	Ii = Ii.Subtract(Ii, x1Gx1)

	// Subtract y0 * G_y0 first
	y0Gy0 := new(ristretto255.Element).ScalarMult(priv.Y[0], system.Gy[0])
	Ii = Ii.Subtract(Ii, y0Gy0)

	var I [NumSupportedAttrs - 1]*ristretto255.Element
	computeCount := numAttrs - 1
	if computeCount > NumSupportedAttrs-1 {
		computeCount = NumSupportedAttrs - 1
	}
	for n := 0; n < computeCount; n++ {
		// Subtract y_{n+1} * G_y_{n+1}
		yGy := new(ristretto255.Element).ScalarMult(priv.Y[n+1], system.Gy[n+1])
		Ii = new(ristretto255.Element).Subtract(Ii, yGy)
		I[n] = new(ristretto255.Element).Set(Ii)
	}

	return &CredentialPublicKey{
		CW: CW,
		I:  I,
	}
}

// CredentialKeyPair is a key pair used by the issuing server to sign credentials.
//
// Defined in Chase-Perrin-Zaverucha section 3.1.
type CredentialKeyPair struct {
	privateKey *CredentialPrivateKey
	publicKey  *CredentialPublicKey
}

// Zeroize overwrites the private key material and nils all references.
// This should be called when the key pair is no longer needed.
func (ckp *CredentialKeyPair) Zeroize() {
	if ckp.privateKey != nil {
		ckp.privateKey.Zeroize()
		ckp.privateKey = nil
	}
	ckp.publicKey = nil
}

// GenerateCredentialKeyPair generates a new key pair from randomness.
func GenerateCredentialKeyPair(randomness [RandomnessLen]byte) *CredentialKeyPair {
	priv := generateCredentialPrivateKey(randomness)
	pub := CredentialPublicKeyFromPrivate(priv)
	return &CredentialKeyPair{
		privateKey: priv,
		publicKey:  pub,
	}
}

// PrivateKey returns the private key.
func (ckp *CredentialKeyPair) PrivateKey() *CredentialPrivateKey {
	return ckp.privateKey
}

// PublicKey returns the public key.
func (ckp *CredentialKeyPair) PublicKey() *CredentialPublicKey {
	return ckp.publicKey
}

// SystemParams contains parameters shared by the client and server.
// User code never needs to explicitly reference these.
//
// Defined in Chase-Perrin-Zaverucha section 3.1.
type SystemParams struct {
	Gw      *ristretto255.Element
	Gwprime *ristretto255.Element
	Gx0     *ristretto255.Element
	Gx1     *ristretto255.Element
	GV      *ristretto255.Element
	Gz      *ristretto255.Element
	Gy      [NumSupportedAttrs]*ristretto255.Element
}

var (
	systemParamsOnce sync.Once
	systemParamsVal  *SystemParams
)

// GetSystemParams returns the hardcoded system parameters, generating them
// on first call. These are deterministic and constant.
func GetSystemParams() *SystemParams {
	systemParamsOnce.Do(func() {
		systemParamsVal = generateSystemParams()
	})
	return systemParamsVal
}

func generateSystemParams() *SystemParams {
	sho := NewShoSha256Ext("Signal_ZKCredential_ConstantSystemParams_generate_20230410")

	Gw := sho.MustGetPoint()
	Gwprime := sho.MustGetPoint()
	Gx0 := sho.MustGetPoint()
	Gx1 := sho.MustGetPoint()
	GV := sho.MustGetPoint()
	Gz := sho.MustGetPoint()

	var Gy [NumSupportedAttrs]*ristretto255.Element
	for i := range Gy {
		Gy[i] = sho.MustGetPoint()
	}

	return &SystemParams{
		Gw:      Gw,
		Gwprime: Gwprime,
		Gx0:     Gx0,
		Gx1:     Gx1,
		GV:      GV,
		Gz:      Gz,
		Gy:      Gy,
	}
}

// LegacyNumSupportedAttrs is the number of attribute points supported by the
// legacy zkgroup credential system. The Rust reference implementation uses 6
// Gy points for legacy credentials, compared to 7 in the modern zkcredential
// system.
const LegacyNumSupportedAttrs = 6

// legacyCredentialSystemHardcoded contains the hardcoded system parameters from
// the Rust reference implementation. These are 17 Ristretto255 points (544 bytes)
// serialized in bincode struct field order:
// G_w, G_wprime, G_x0, G_x1, G_y1..G_y6, G_m1..G_m5, G_V, G_z
var legacyCredentialSystemHardcoded = [544]byte{
	// G_w (bytes 0-31)
	0x9a, 0xe7, 0xc8, 0xe5, 0xed, 0x77, 0x9b, 0x11, 0x4a, 0xe7, 0x70, 0x8a, 0xa2, 0xf7, 0x94, 0x67,
	0x0a, 0xdd, 0xa3, 0x24, 0x98, 0x7b, 0x65, 0x99, 0x13, 0x12, 0x2c, 0x35, 0x50, 0x5b, 0x10, 0x5e,
	// G_wprime (bytes 32-63)
	0x6c, 0xa3, 0x10, 0x25, 0xd2, 0xd7, 0x6b, 0xe7, 0xfd, 0x34, 0x94, 0x4f, 0x98, 0xf7, 0xfa, 0x0e,
	0x37, 0xba, 0xbb, 0x2c, 0x8b, 0x98, 0xbb, 0xbd, 0xbd, 0x3d, 0xd1, 0xbf, 0x13, 0x0c, 0xca, 0x2c,
	// G_x0 (bytes 64-95)
	0x8a, 0x9a, 0x3b, 0xdf, 0xaa, 0xa2, 0xb6, 0xb3, 0x22, 0xd4, 0x6b, 0x93, 0xec, 0xa7, 0xb0, 0xd5,
	0x1c, 0x86, 0xa3, 0xc8, 0x39, 0xe1, 0x14, 0x66, 0x35, 0x82, 0x58, 0xa6, 0xc1, 0x0c, 0x57, 0x7f,
	// G_x1 (bytes 96-127)
	0xc2, 0xbf, 0xfd, 0x34, 0xcd, 0x99, 0x16, 0x4c, 0x9a, 0x6c, 0xd2, 0x9f, 0xab, 0x55, 0xd9, 0x1f,
	0xf9, 0x26, 0x93, 0x22, 0xec, 0x34, 0x58, 0x60, 0x3c, 0xc9, 0x6a, 0x0d, 0x47, 0xf7, 0x04, 0x05,
	// G_y1 (bytes 128-159)
	0x82, 0x88, 0xf6, 0x2e, 0xe0, 0xac, 0xed, 0xb8, 0xaa, 0x23, 0x24, 0x21, 0x21, 0xd9, 0x89, 0x65,
	0xa9, 0xbb, 0x29, 0x91, 0x25, 0x0c, 0x11, 0x75, 0x80, 0x95, 0xec, 0xe0, 0xfd, 0x2b, 0x33, 0x28,
	// G_y2 (bytes 160-191)
	0x52, 0x86, 0xfe, 0x1f, 0xcb, 0x05, 0x61, 0x03, 0xb6, 0x08, 0x17, 0x44, 0xb9, 0x75, 0xf5, 0x50,
	0xd0, 0x85, 0x21, 0x56, 0x8d, 0xd3, 0xd8, 0x61, 0x8f, 0x25, 0xc1, 0x40, 0x37, 0x5a, 0x0f, 0x40,
	// G_y3 (bytes 192-223)
	0x24, 0xc3, 0xaa, 0x23, 0xbd, 0xff, 0xfb, 0x27, 0xfb, 0xd9, 0x82, 0x20, 0x8d, 0x3e, 0xcd, 0x1f,
	0xd3, 0xbc, 0xb7, 0xac, 0x0c, 0x3a, 0x14, 0xb1, 0x09, 0x80, 0x4f, 0xc7, 0x48, 0xd7, 0xfa, 0x45,
	// G_y4 (bytes 224-255)
	0x6c, 0xff, 0xb4, 0x93, 0x4f, 0x98, 0x0b, 0x6e, 0x09, 0xa2, 0x48, 0xa6, 0x0f, 0x44, 0xa6, 0x15,
	0x0a, 0xe6, 0xc1, 0x3d, 0x7e, 0x3c, 0x06, 0x26, 0x1d, 0x7e, 0x4e, 0xed, 0x37, 0xf3, 0x9f, 0x60,
	// G_y5 (bytes 256-287)
	0xb0, 0x4d, 0xd9, 0xd6, 0x07, 0xfd, 0x35, 0x70, 0x12, 0x27, 0x4d, 0x3c, 0x63, 0xdb, 0xb3, 0x8e,
	0x73, 0x78, 0x59, 0x9c, 0x9e, 0x97, 0xdf, 0xbb, 0x28, 0x84, 0x26, 0x94, 0x89, 0x1d, 0x5f, 0x0d,
	// G_y6 (bytes 288-319)
	0xdc, 0x72, 0x99, 0x19, 0xb7, 0x98, 0xb4, 0x13, 0x15, 0x03, 0x40, 0x8c, 0xc5, 0x7a, 0x9c, 0x53,
	0x2f, 0x44, 0x27, 0x63, 0x2c, 0x88, 0xf5, 0x4c, 0xea, 0x53, 0x86, 0x1a, 0x5b, 0xc4, 0x4c, 0x61,
	// G_m1 (bytes 320-351)
	0xcc, 0x60, 0x37, 0xdc, 0x31, 0xc2, 0xe8, 0xd4, 0x47, 0x4f, 0xb5, 0x19, 0x58, 0x7a, 0x44, 0x86,
	0x93, 0x18, 0x2a, 0xd9, 0xd6, 0xd8, 0x6b, 0x53, 0x59, 0x57, 0x85, 0x8f, 0x54, 0x7b, 0x93, 0x40,
	// G_m2 (bytes 352-383)
	0x12, 0x7d, 0xa7, 0x5f, 0x80, 0x74, 0xca, 0xee, 0x94, 0x4a, 0xc3, 0x6c, 0x0a, 0xc6, 0x62, 0xd3,
	0x8c, 0x9b, 0x3c, 0xcc, 0xe0, 0x3a, 0x09, 0x3f, 0xcd, 0x96, 0x44, 0x04, 0x73, 0x98, 0xb8, 0x6b,
	// G_m3 (bytes 384-415)
	0x6e, 0x83, 0x37, 0x2f, 0xf1, 0x4f, 0xb8, 0xbb, 0x0d, 0xea, 0x65, 0x53, 0x12, 0x52, 0xac, 0x70,
	0xd5, 0x8a, 0x4a, 0x08, 0x10, 0xd6, 0x82, 0xa0, 0xe7, 0x09, 0xc9, 0x22, 0x7b, 0x30, 0xef, 0x6c,
	// G_m4 (bytes 416-447)
	0x8e, 0x17, 0xc5, 0x91, 0x5d, 0x52, 0x72, 0x21, 0xbb, 0x00, 0xda, 0x81, 0x75, 0xcd, 0x64, 0x89,
	0xaa, 0x8a, 0xa4, 0x92, 0xa5, 0x00, 0xf9, 0xab, 0xee, 0x56, 0x90, 0xb9, 0xdf, 0xca, 0x88, 0x55,
	// G_m5 (bytes 448-479)
	0xdc, 0x0b, 0xd0, 0x2a, 0x7f, 0x27, 0x7a, 0xdd, 0x24, 0x0f, 0x63, 0x9a, 0xc1, 0x68, 0x01, 0xe8,
	0x15, 0x74, 0xaf, 0xb4, 0x68, 0x3e, 0xdf, 0xf6, 0x3b, 0x9a, 0x01, 0xe9, 0x3d, 0xbd, 0x86, 0x7a,
	// G_V (bytes 480-511)
	0x04, 0xb6, 0x16, 0xc7, 0x06, 0xc8, 0x0c, 0x75, 0x6c, 0x11, 0xa3, 0x01, 0x6b, 0xbf, 0xb6, 0x09,
	0x77, 0xf4, 0x64, 0x8b, 0x5f, 0x23, 0x95, 0xa4, 0xb4, 0x28, 0xb7, 0x21, 0x19, 0x40, 0x81, 0x3e,
	// G_z (bytes 512-543)
	0x3a, 0xfd, 0xe2, 0xb8, 0x7a, 0xa9, 0xc2, 0xc3, 0x7b, 0xf7, 0x16, 0xe2, 0x57, 0x8f, 0x95, 0x65,
	0x6d, 0xf1, 0x2c, 0x2f, 0xb6, 0xf5, 0xd0, 0x63, 0x1f, 0x6f, 0x71, 0xe2, 0xc3, 0x19, 0x3f, 0x6d,
}

// LegacySystemParams contains the system parameters used by the legacy zkgroup
// credential system. These are parsed from the hardcoded Rust reference
// implementation blob, containing 17 Ristretto255 points in bincode struct
// field order.
type LegacySystemParams struct {
	Gw      *ristretto255.Element
	Gwprime *ristretto255.Element
	Gx0     *ristretto255.Element
	Gx1     *ristretto255.Element
	Gy      [LegacyNumSupportedAttrs]*ristretto255.Element
	Gm      [5]*ristretto255.Element
	GV      *ristretto255.Element
	Gz      *ristretto255.Element
}

var (
	legacySystemParamsOnce sync.Once
	legacySystemParamsVal  *LegacySystemParams
)

// GetLegacySystemParams returns the legacy zkgroup system parameters,
// parsed from the hardcoded Rust reference implementation blob on first call.
func GetLegacySystemParams() *LegacySystemParams {
	legacySystemParamsOnce.Do(func() {
		legacySystemParamsVal = parseLegacySystemParams()
	})
	return legacySystemParamsVal
}

// parseLegacySystemParams parses the hardcoded 544-byte blob into
// LegacySystemParams. The blob contains 17 Ristretto255 points in bincode
// struct field order: G_w, G_wprime, G_x0, G_x1, G_y1..G_y6, G_m1..G_m5, G_V, G_z.
func parseLegacySystemParams() *LegacySystemParams {
	blob := legacyCredentialSystemHardcoded[:]
	offset := 0

	readPoint := func() *ristretto255.Element {
		p := ristretto255.NewIdentityElement()
		if _, err := p.SetCanonicalBytes(blob[offset : offset+32]); err != nil {
			panic(fmt.Sprintf("zkcredential: invalid hardcoded legacy system param at offset %d: %v", offset, err))
		}
		offset += 32
		return p
	}

	Gw := readPoint()
	Gwprime := readPoint()
	Gx0 := readPoint()
	Gx1 := readPoint()

	var Gy [LegacyNumSupportedAttrs]*ristretto255.Element
	for i := range Gy {
		Gy[i] = readPoint()
	}

	var Gm [5]*ristretto255.Element
	for i := range Gm {
		Gm[i] = readPoint()
	}

	GV := readPoint()
	Gz := readPoint()

	return &LegacySystemParams{
		Gw:      Gw,
		Gwprime: Gwprime,
		Gx0:     Gx0,
		Gx1:     Gx1,
		Gy:      Gy,
		Gm:      Gm,
		GV:      GV,
		Gz:      Gz,
	}
}

// EncodeCredential encodes a Credential to bytes.
func EncodeCredential(c *Credential) []byte {
	out := make([]byte, 0, 32+32+32)
	out = append(out, c.T.Bytes()...)
	out = append(out, c.U.Bytes()...)
	out = append(out, c.V.Bytes()...)
	return out
}

// DecodeCredential decodes a Credential from bytes.
func DecodeCredential(data []byte) (*Credential, error) {
	if len(data) != 96 {
		return nil, &ErrCredentialSize{Got: len(data)}
	}
	t := ristretto255.NewScalar()
	if _, err := t.SetCanonicalBytes(data[:32]); err != nil {
		return nil, &ErrInvalidEncoding{Field: "scalar t", Err: err}
	}
	U := ristretto255.NewIdentityElement()
	if _, err := U.SetCanonicalBytes(data[32:64]); err != nil {
		return nil, &ErrInvalidEncoding{Field: "point U", Err: err}
	}
	V := ristretto255.NewIdentityElement()
	if _, err := V.SetCanonicalBytes(data[64:96]); err != nil {
		return nil, &ErrInvalidEncoding{Field: "point V", Err: err}
	}
	return &Credential{T: t, U: U, V: V}, nil
}
