package kem

import (
	"errors"
	"strings"
	"testing"

	circlkem "github.com/cloudflare/circl/kem"
)

// errScheme is a test double for circl's kem.Scheme that returns
// configurable errors. It delegates to the real kyber1024 scheme for
// operations that are not configured to fail.
type errScheme struct {
	real           circlkem.Scheme
	generateErr    error
	marshalPKErr   error
	marshalSKErr   error
	encapsulateErr error
	decapsulateErr error
	unmarshalPKErr error
	unmarshalSKErr error
}

func (e *errScheme) Name() string { return e.real.Name() }

func (e *errScheme) GenerateKeyPair() (circlkem.PublicKey, circlkem.PrivateKey, error) {
	if e.generateErr != nil {
		return nil, nil, e.generateErr
	}
	pk, sk, err := e.real.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	if e.marshalPKErr != nil || e.marshalSKErr != nil {
		return &errKey{inner: pk, marshalErr: e.marshalPKErr},
			&errPrivKey{inner: sk, marshalErr: e.marshalSKErr}, nil
	}
	return pk, sk, nil
}

func (e *errScheme) Encapsulate(pk circlkem.PublicKey) (ct, ss []byte, err error) {
	if e.encapsulateErr != nil {
		return nil, nil, e.encapsulateErr
	}
	return e.real.Encapsulate(pk)
}

func (e *errScheme) Decapsulate(sk circlkem.PrivateKey, ct []byte) ([]byte, error) {
	if e.decapsulateErr != nil {
		return nil, e.decapsulateErr
	}
	return e.real.Decapsulate(sk, ct)
}

func (e *errScheme) UnmarshalBinaryPublicKey(data []byte) (circlkem.PublicKey, error) {
	if e.unmarshalPKErr != nil {
		return nil, e.unmarshalPKErr
	}
	return e.real.UnmarshalBinaryPublicKey(data)
}

func (e *errScheme) UnmarshalBinaryPrivateKey(data []byte) (circlkem.PrivateKey, error) {
	if e.unmarshalSKErr != nil {
		return nil, e.unmarshalSKErr
	}
	return e.real.UnmarshalBinaryPrivateKey(data)
}

func (e *errScheme) CiphertextSize() int        { return e.real.CiphertextSize() }
func (e *errScheme) SharedKeySize() int         { return e.real.SharedKeySize() }
func (e *errScheme) PrivateKeySize() int        { return e.real.PrivateKeySize() }
func (e *errScheme) PublicKeySize() int         { return e.real.PublicKeySize() }
func (e *errScheme) SeedSize() int              { return e.real.SeedSize() }
func (e *errScheme) EncapsulationSeedSize() int { return e.real.EncapsulationSeedSize() }

func (e *errScheme) DeriveKeyPair(seed []byte) (circlkem.PublicKey, circlkem.PrivateKey) {
	return e.real.DeriveKeyPair(seed)
}

func (e *errScheme) EncapsulateDeterministically(pk circlkem.PublicKey, seed []byte) (ct, ss []byte, err error) {
	return e.real.EncapsulateDeterministically(pk, seed)
}

// errKey wraps a public key to inject marshal errors.
type errKey struct {
	inner      circlkem.PublicKey
	marshalErr error
}

func (k *errKey) Scheme() circlkem.Scheme             { return k.inner.Scheme() }
func (k *errKey) Equal(other circlkem.PublicKey) bool { return k.inner.Equal(other) }

func (k *errKey) MarshalBinary() ([]byte, error) {
	if k.marshalErr != nil {
		return nil, k.marshalErr
	}
	return k.inner.MarshalBinary()
}

// errPrivKey wraps a private key to inject marshal errors.
type errPrivKey struct {
	inner      circlkem.PrivateKey
	marshalErr error
}

func (k *errPrivKey) Scheme() circlkem.Scheme              { return k.inner.Scheme() }
func (k *errPrivKey) Equal(other circlkem.PrivateKey) bool { return k.inner.Equal(other) }
func (k *errPrivKey) Public() circlkem.PublicKey           { return k.inner.Public() }

func (k *errPrivKey) MarshalBinary() ([]byte, error) {
	if k.marshalErr != nil {
		return nil, k.marshalErr
	}
	return k.inner.MarshalBinary()
}

var errInjected = errors.New("injected test error")

// panicScheme is a test double that panics during operations to test
// the defer/recover blocks in guarded KEM functions.
type panicScheme struct {
	real            circlkem.Scheme
	panicOnGenerate bool
	panicOnEncap    bool
	panicOnDecap    bool
}

func (p *panicScheme) Name() string { return p.real.Name() }

func (p *panicScheme) GenerateKeyPair() (circlkem.PublicKey, circlkem.PrivateKey, error) {
	if p.panicOnGenerate {
		panic("test panic in GenerateKeyPair")
	}
	return p.real.GenerateKeyPair()
}

func (p *panicScheme) Encapsulate(pk circlkem.PublicKey) (ct, ss []byte, err error) {
	if p.panicOnEncap {
		panic("test panic in Encapsulate")
	}
	return p.real.Encapsulate(pk)
}

func (p *panicScheme) Decapsulate(sk circlkem.PrivateKey, ct []byte) ([]byte, error) {
	if p.panicOnDecap {
		panic("test panic in Decapsulate")
	}
	return p.real.Decapsulate(sk, ct)
}

func (p *panicScheme) UnmarshalBinaryPublicKey(data []byte) (circlkem.PublicKey, error) {
	return p.real.UnmarshalBinaryPublicKey(data)
}

func (p *panicScheme) UnmarshalBinaryPrivateKey(data []byte) (circlkem.PrivateKey, error) {
	return p.real.UnmarshalBinaryPrivateKey(data)
}

func (p *panicScheme) CiphertextSize() int        { return p.real.CiphertextSize() }
func (p *panicScheme) SharedKeySize() int         { return p.real.SharedKeySize() }
func (p *panicScheme) PrivateKeySize() int        { return p.real.PrivateKeySize() }
func (p *panicScheme) PublicKeySize() int         { return p.real.PublicKeySize() }
func (p *panicScheme) SeedSize() int              { return p.real.SeedSize() }
func (p *panicScheme) EncapsulationSeedSize() int { return p.real.EncapsulationSeedSize() }

func (p *panicScheme) DeriveKeyPair(seed []byte) (circlkem.PublicKey, circlkem.PrivateKey) {
	return p.real.DeriveKeyPair(seed)
}

func (p *panicScheme) EncapsulateDeterministically(pk circlkem.PublicKey, seed []byte) (ct, ss []byte, err error) {
	return p.real.EncapsulateDeterministically(pk, seed)
}

// --- Kyber1024KEM error path tests ---

func TestKyber1024KEMGenerateKeyPairError(t *testing.T) {
	orig := kyber1024Scheme
	defer func() { kyber1024Scheme = orig }()

	kyber1024Scheme = &errScheme{real: orig, generateErr: errInjected}
	k := NewKyber1024KEM()
	_, err := k.Generate()
	if err == nil {
		t.Fatal("Generate() should return error when GenerateKeyPair fails")
	}
	if !strings.Contains(err.Error(), "key generation failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestKyber1024KEMGenerateMarshalPublicKeyError(t *testing.T) {
	orig := kyber1024Scheme
	defer func() { kyber1024Scheme = orig }()

	kyber1024Scheme = &errScheme{real: orig, marshalPKErr: errInjected}
	k := NewKyber1024KEM()
	_, err := k.Generate()
	if err == nil {
		t.Fatal("Generate() should return error when MarshalBinary(pk) fails")
	}
	if !strings.Contains(err.Error(), "marshal kyber1024 public key") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestKyber1024KEMGenerateMarshalSecretKeyError(t *testing.T) {
	orig := kyber1024Scheme
	defer func() { kyber1024Scheme = orig }()

	kyber1024Scheme = &errScheme{real: orig, marshalSKErr: errInjected}
	k := NewKyber1024KEM()
	_, err := k.Generate()
	if err == nil {
		t.Fatal("Generate() should return error when MarshalBinary(sk) fails")
	}
	if !strings.Contains(err.Error(), "marshal kyber1024 secret key") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestKyber1024KEMEncapsulateSchemeError(t *testing.T) {
	orig := kyber1024Scheme
	defer func() { kyber1024Scheme = orig }()

	// First generate a valid key pair with the real scheme.
	k := NewKyber1024KEM()
	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	// Now inject encapsulation error.
	kyber1024Scheme = &errScheme{real: orig, encapsulateErr: errInjected}
	_, _, err = k.Encapsulate(kp.Public)
	if err == nil {
		t.Fatal("Encapsulate() should return error when scheme.Encapsulate fails")
	}
	if !strings.Contains(err.Error(), "encapsulation failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestKyber1024KEMDecapsulateSchemeError(t *testing.T) {
	orig := kyber1024Scheme
	defer func() { kyber1024Scheme = orig }()

	k := NewKyber1024KEM()
	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	_, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	// Now inject decapsulation error.
	kyber1024Scheme = &errScheme{real: orig, decapsulateErr: errInjected}
	_, err = k.Decapsulate(kp.Secret, ct)
	if err == nil {
		t.Fatal("Decapsulate() should return error when scheme.Decapsulate fails")
	}
	if !strings.Contains(err.Error(), "decapsulation failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// --- GuardedKyber1024 error path tests ---

func TestGuardedKyber1024GenerateKeyPairError(t *testing.T) {
	orig := guardedKyber1024Scheme
	defer func() { guardedKyber1024Scheme = orig }()

	guardedKyber1024Scheme = &errScheme{real: orig, generateErr: errInjected}
	g := NewGuardedKyber1024()
	_, err := g.Generate()
	if err == nil {
		t.Fatal("Generate() should return error when GenerateKeyPair fails")
	}
	if !strings.Contains(err.Error(), "key generation failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGuardedKyber1024GenerateMarshalPublicKeyError(t *testing.T) {
	orig := guardedKyber1024Scheme
	defer func() { guardedKyber1024Scheme = orig }()

	guardedKyber1024Scheme = &errScheme{real: orig, marshalPKErr: errInjected}
	g := NewGuardedKyber1024()
	_, err := g.Generate()
	if err == nil {
		t.Fatal("Generate() should return error when MarshalBinary(pk) fails")
	}
	if !strings.Contains(err.Error(), "marshal kyber1024 public key") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGuardedKyber1024GenerateMarshalSecretKeyError(t *testing.T) {
	orig := guardedKyber1024Scheme
	defer func() { guardedKyber1024Scheme = orig }()

	guardedKyber1024Scheme = &errScheme{real: orig, marshalSKErr: errInjected}
	g := NewGuardedKyber1024()
	_, err := g.Generate()
	if err == nil {
		t.Fatal("Generate() should return error when MarshalBinary(sk) fails")
	}
	if !strings.Contains(err.Error(), "marshal kyber1024 secret key") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGuardedKyber1024EncapsulateSchemeError(t *testing.T) {
	orig := guardedKyber1024Scheme
	defer func() { guardedKyber1024Scheme = orig }()

	g := NewGuardedKyber1024()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	guardedKyber1024Scheme = &errScheme{real: orig, encapsulateErr: errInjected}
	_, _, err = g.Encapsulate(kp.Public)
	if err == nil {
		t.Fatal("Encapsulate() should return error when scheme.Encapsulate fails")
	}
	if !strings.Contains(err.Error(), "encapsulation failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGuardedKyber1024DecapsulateSchemeDecapError(t *testing.T) {
	orig := guardedKyber1024Scheme
	defer func() { guardedKyber1024Scheme = orig }()

	g := NewGuardedKyber1024()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	guardedKyber1024Scheme = &errScheme{real: orig, decapsulateErr: errInjected}
	_, err = g.Decapsulate(kp.Secret, ct)
	if err == nil {
		t.Fatal("Decapsulate() should return error when scheme.Decapsulate fails")
	}
	if !strings.Contains(err.Error(), "decapsulation failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGuardedKyber1024DecapsulateUnmarshalSKError(t *testing.T) {
	orig := guardedKyber1024Scheme
	defer func() { guardedKyber1024Scheme = orig }()

	g := NewGuardedKyber1024()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	guardedKyber1024Scheme = &errScheme{real: orig, unmarshalSKErr: errInjected}
	_, err = g.Decapsulate(kp.Secret, ct)
	if err == nil {
		t.Fatal("Decapsulate() should return error when UnmarshalBinaryPrivateKey fails")
	}
	if !strings.Contains(err.Error(), "unmarshal kyber1024 secret key") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGuardedKyber1024EncapsulateUnmarshalPKError(t *testing.T) {
	orig := guardedKyber1024Scheme
	defer func() { guardedKyber1024Scheme = orig }()

	g := NewGuardedKyber1024()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	guardedKyber1024Scheme = &errScheme{real: orig, unmarshalPKErr: errInjected}
	_, _, err = g.Encapsulate(kp.Public)
	if err == nil {
		t.Fatal("Encapsulate() should return error when UnmarshalBinaryPublicKey fails")
	}
	if !strings.Contains(err.Error(), "unmarshal kyber1024 public key") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// --- Panic recovery tests for GuardedKyber1024 defer/recover blocks ---

func TestGuardedKyber1024GeneratePanicRecovery(t *testing.T) {
	orig := guardedKyber1024Scheme
	defer func() { guardedKyber1024Scheme = orig }()

	guardedKyber1024Scheme = &panicScheme{real: orig, panicOnGenerate: true}
	g := NewGuardedKyber1024()
	_, err := g.Generate()
	if err == nil {
		t.Fatal("Generate() should return error when panic is recovered")
	}
	if !strings.Contains(err.Error(), "guarded kyber1024 key generation failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGuardedKyber1024EncapsulatePanicRecovery(t *testing.T) {
	orig := guardedKyber1024Scheme
	defer func() { guardedKyber1024Scheme = orig }()

	g := NewGuardedKyber1024()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	guardedKyber1024Scheme = &panicScheme{real: orig, panicOnEncap: true}
	_, _, err = g.Encapsulate(kp.Public)
	if err == nil {
		t.Fatal("Encapsulate() should return error when panic is recovered")
	}
	if !strings.Contains(err.Error(), "guarded kyber1024 encapsulation failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGuardedKyber1024DecapsulatePanicRecovery(t *testing.T) {
	orig := guardedKyber1024Scheme
	defer func() { guardedKyber1024Scheme = orig }()

	g := NewGuardedKyber1024()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	guardedKyber1024Scheme = &panicScheme{real: orig, panicOnDecap: true}
	_, err = g.Decapsulate(kp.Secret, ct)
	if err == nil {
		t.Fatal("Decapsulate() should return error when panic is recovered")
	}
	if !strings.Contains(err.Error(), "guarded kyber1024 decapsulation failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGuardedSecretKeyDecapsulateGuardedPanicRecovery(t *testing.T) {
	orig := guardedKyber1024Scheme
	defer func() { guardedKyber1024Scheme = orig }()

	g := NewGuardedKyber1024()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	guardedKyber1024Scheme = &panicScheme{real: orig, panicOnDecap: true}
	_, err = kp.Secret.DecapsulateGuarded(ct.Serialize())
	if err == nil {
		t.Fatal("DecapsulateGuarded() should return error when panic is recovered")
	}
	if !strings.Contains(err.Error(), "guarded") {
		t.Errorf("unexpected error message: %v", err)
	}
}
