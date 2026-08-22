package record

import "encoding/json"

// The JSON test serializers live here, in an UNTAGGED file, rather than beside
// the tests that first needed them.
//
// They were declared in SenderKeyState_test.go and SenderKeyRecord_test.go,
// both of which carry `//go:build !fips140only` because they also hold X25519
// tests. The serializers themselves are `encoding/json` and nothing else, so
// they have no business being dropped from the FIPS build — but while they sat
// in those files, any test that needed one had to be exempt too, whatever it
// was actually testing. Moving them here means the exemption covers only the
// tests that genuinely need it.

// jsonSenderKeyStateSerializer is a test serializer for SenderKeyState.
type jsonSenderKeyStateSerializer struct{}

func (s *jsonSenderKeyStateSerializer) Serialize(state *SenderKeyStateStructure) ([]byte, error) {
	return json.Marshal(state)
}

func (s *jsonSenderKeyStateSerializer) Deserialize(serialized []byte) (*SenderKeyStateStructure, error) {
	var structure SenderKeyStateStructure
	if err := json.Unmarshal(serialized, &structure); err != nil {
		return nil, err
	}
	return &structure, nil
}

func newTestStateSerializer() SenderKeyStateSerializer {
	return &jsonSenderKeyStateSerializer{}
}

// jsonSenderKeyRecordSerializer is a test serializer for SenderKey records.
type jsonSenderKeyRecordSerializer struct{}

func (s *jsonSenderKeyRecordSerializer) Serialize(record *SenderKeyStructure) ([]byte, error) {
	return json.Marshal(record)
}

func (s *jsonSenderKeyRecordSerializer) Deserialize(serialized []byte) (*SenderKeyStructure, error) {
	var structure SenderKeyStructure
	if err := json.Unmarshal(serialized, &structure); err != nil {
		return nil, err
	}
	return &structure, nil
}

func newTestRecordSerializer() SenderKeySerializer {
	return &jsonSenderKeyRecordSerializer{}
}
