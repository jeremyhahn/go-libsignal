// Serializer fixtures shared by this package's tests.
//
// They live in their own file, untagged, because they perform no
// cryptography themselves -- tests that are excluded from the FIPS gate
// (docs/FIPS.md) and tests that are not both need them.

package record_test

import (
	"encoding/json"

	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

func newSerializer() *serialize.Serializer {
	return serialize.NewJSONSerializer()
}

type kyberPreKeySerializer struct{}

func (k *kyberPreKeySerializer) Serialize(preKey *record.KyberPreKeyStructure) ([]byte, error) {
	return json.Marshal(preKey)
}

func (k *kyberPreKeySerializer) Deserialize(serialized []byte) (*record.KyberPreKeyStructure, error) {
	var s record.KyberPreKeyStructure
	err := json.Unmarshal(serialized, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}
