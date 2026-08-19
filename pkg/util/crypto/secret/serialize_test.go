package secret

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestNewOptionalGuardsDataAndWipesSource(t *testing.T) {
	source := []byte{1, 2, 3, 4, 5}
	guarded, err := NewOptional(source)
	if err != nil {
		t.Fatalf("NewOptional: %v", err)
	}
	defer guarded.Destroy()

	if !guarded.EqualTo([]byte{1, 2, 3, 4, 5}) {
		t.Error("guarded secret does not hold the source bytes")
	}
	if !bytes.Equal(source, make([]byte, len(source))) {
		t.Errorf("source slice was not wiped: %v", source)
	}
}

func TestNewValueGuardsDataAndWipesSource(t *testing.T) {
	source := []byte{6, 7, 8}
	guarded, err := NewValue(source)
	if err != nil {
		t.Fatalf("NewValue: %v", err)
	}
	defer guarded.Destroy()

	if !guarded.EqualTo([]byte{6, 7, 8}) {
		t.Error("guarded secret does not hold the source bytes")
	}
	if !bytes.Equal(source, make([]byte, len(source))) {
		t.Errorf("source slice was not wiped: %v", source)
	}
}

func TestNewValueEmptyInputYieldsZeroSecret(t *testing.T) {
	for name, input := range map[string][]byte{
		"nil":   nil,
		"empty": {},
	} {
		t.Run(name, func(t *testing.T) {
			guarded, err := NewValue(input)
			if err != nil {
				t.Fatalf("NewValue: %v", err)
			}
			if !guarded.IsDestroyed() {
				t.Error("the zero Secret should report as holding no material")
			}
			if guarded.BytesOrNil() != nil {
				t.Error("BytesOrNil on the zero Secret should be nil")
			}
			// Destroying material that was never allocated is a no-op.
			guarded.Destroy()
		})
	}
}

func TestNewOptionalEmptyInputReturnsNil(t *testing.T) {
	for name, input := range map[string][]byte{
		"nil":   nil,
		"empty": {},
	} {
		t.Run(name, func(t *testing.T) {
			guarded, err := NewOptional(input)
			if err != nil {
				t.Fatalf("NewOptional: %v", err)
			}
			if guarded != nil {
				t.Fatal("expected nil secret for empty input")
			}
			// The nil secret must behave as "no material" rather than panic.
			if guarded.BytesOrNil() != nil {
				t.Error("BytesOrNil on nil secret should be nil")
			}
			if !guarded.IsDestroyed() {
				t.Error("nil secret should report as destroyed")
			}
			guarded.Destroy()
		})
	}
}

func TestBytesOrNilAfterDestroy(t *testing.T) {
	guarded, err := New([]byte{9, 9, 9})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := guarded.BytesOrNil(); !bytes.Equal(got, []byte{9, 9, 9}) {
		t.Fatalf("BytesOrNil = %v, want [9 9 9]", got)
	}

	guarded.Destroy()
	if got := guarded.BytesOrNil(); got != nil {
		t.Errorf("BytesOrNil after Destroy = %v, want nil", got)
	}
}

// TestMarshalJSONMatchesByteSlice pins the wire compatibility that persisted
// state depends on: a guarded secret must encode exactly as the []byte it
// replaced, so records written by earlier versions stay readable.
func TestMarshalJSONMatchesByteSlice(t *testing.T) {
	raw := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	want, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("json.Marshal([]byte): %v", err)
	}

	guarded, err := New(append([]byte(nil), raw...))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer guarded.Destroy()

	got, err := json.Marshal(guarded)
	if err != nil {
		t.Fatalf("json.Marshal(*Secret): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("MarshalJSON = %s, want %s", got, want)
	}
}

func TestMarshalJSONWithoutMaterialEmitsNull(t *testing.T) {
	destroyed, err := New([]byte{1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	destroyed.Destroy()

	for name, s := range map[string]*Secret{"nil": nil, "destroyed": destroyed} {
		t.Run(name, func(t *testing.T) {
			serialized, err := json.Marshal(struct {
				Key *Secret
			}{Key: s})
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if string(serialized) != `{"Key":null}` {
				t.Errorf("marshaled %s, want {\"Key\":null}", serialized)
			}
		})
	}
}

func TestUnmarshalJSONRoundTrip(t *testing.T) {
	type holder struct {
		Key *Secret
	}

	original := holder{}
	guarded, err := New([]byte{1, 2, 3})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	original.Key = guarded
	defer original.Key.Destroy()

	serialized, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded holder
	if err := json.Unmarshal(serialized, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	defer decoded.Key.Destroy()

	if !decoded.Key.EqualTo([]byte{1, 2, 3}) {
		t.Error("round-tripped secret does not match the original")
	}
	// The decoded material must live in its own guarded allocation.
	if decoded.Key == original.Key {
		t.Error("decoded secret aliases the original")
	}
}

func TestUnmarshalJSONAbsentMaterial(t *testing.T) {
	type holder struct {
		Key *Secret
	}

	t.Run("null leaves the field nil", func(t *testing.T) {
		var decoded holder
		if err := json.Unmarshal([]byte(`{"Key":null}`), &decoded); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		if decoded.Key != nil {
			t.Error("expected nil secret for null")
		}
	})

	t.Run("empty string holds no material", func(t *testing.T) {
		var decoded holder
		if err := json.Unmarshal([]byte(`{"Key":""}`), &decoded); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		if decoded.Key.BytesOrNil() != nil {
			t.Error("expected no material for an empty string")
		}
	})
}

func TestUnmarshalJSONRejectsInvalidInput(t *testing.T) {
	for name, input := range map[string]string{
		"not base64": `"not-valid-base64!!"`,
		"wrong type": `{"unexpected":"object"}`,
		"malformed":  `[`,
	} {
		t.Run(name, func(t *testing.T) {
			var s Secret
			if err := s.UnmarshalJSON([]byte(input)); err == nil {
				t.Fatalf("expected an error for %s", input)
			}
			if s.BytesOrNil() != nil {
				t.Error("a rejected decode must not leave material behind")
			}
		})
	}
}

// TestUnmarshalJSONReleasesReplacedMaterial pins the ownership rule that keeps
// repeated decodes from stranding locked memory: encoding/json reuses an
// existing pointer field, so the material being replaced has to be destroyed.
func TestUnmarshalJSONReleasesReplacedMaterial(t *testing.T) {
	for name, input := range map[string]string{
		"replaced by a value": `"AwQ="`,
		"replaced by empty":   `""`,
	} {
		t.Run(name, func(t *testing.T) {
			s, err := New([]byte{1, 2, 3})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			// A second handle on the same locked buffer, to observe its fate.
			previous := &Secret{buf: s.buf}

			if err := s.UnmarshalJSON([]byte(input)); err != nil {
				t.Fatalf("UnmarshalJSON: %v", err)
			}
			defer s.Destroy()

			if !previous.IsDestroyed() {
				t.Error("the replaced material was abandoned instead of destroyed")
			}
		})
	}
}

// TestUnmarshalJSONKeepsMaterialOnFailure verifies that a rejected decode does
// not take the existing material with it.
func TestUnmarshalJSONKeepsMaterialOnFailure(t *testing.T) {
	s, err := New([]byte{1, 2, 3})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Destroy()

	if err := s.UnmarshalJSON([]byte(`{"not":"base64"}`)); err == nil {
		t.Fatal("expected an error for a non-string value")
	}
	if !s.EqualTo([]byte{1, 2, 3}) {
		t.Error("a failed decode must leave the existing material intact")
	}
}

// TestValueFieldNullReleasesMaterial pins why persisted-state structures hold
// their guarded fields by value rather than by pointer: encoding/json sets a
// pointer field to nil for a null without calling UnmarshalJSON, abandoning
// whatever it allocated for an earlier occurrence of the same field. A value
// field routes that null through UnmarshalJSON, which destroys the material.
func TestValueFieldNullReleasesMaterial(t *testing.T) {
	type valueHolder struct {
		Key Secret
	}
	type pointerHolder struct {
		Key *Secret
	}

	var value valueHolder
	if err := json.Unmarshal([]byte(`{"Key":"AQID","Key":null}`), &value); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if !value.Key.IsDestroyed() {
		t.Error("the superseded material was not destroyed")
	}
	if value.Key.BytesOrNil() != nil {
		t.Error("expected no material after a null supersedes the value")
	}

	// The pointer form is the shape being avoided: json nils the field out from
	// under the codec, so nothing can release what it allocated.
	var pointer pointerHolder
	if err := json.Unmarshal([]byte(`{"Key":"AQID","Key":null}`), &pointer); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if pointer.Key != nil {
		t.Fatal("expected encoding/json to nil the pointer field for null")
	}
}

func TestFromSecret(t *testing.T) {
	material := []byte{0x01, 0x02, 0x03}
	guarded, err := New(append([]byte(nil), material...))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	value := FromSecret(guarded)
	if !value.EqualTo(material) {
		t.Error("FromSecret did not carry the guarded material over")
	}

	// Ownership moved: destroying the value releases the same buffer.
	value.Destroy()
	if !guarded.IsDestroyed() {
		t.Error("FromSecret copied the material instead of taking ownership")
	}
}

func TestFromSecretNil(t *testing.T) {
	value := FromSecret(nil)
	if value.BytesOrNil() != nil {
		t.Error("FromSecret(nil) should hold no material")
	}
	value.Destroy() // must not panic
}
