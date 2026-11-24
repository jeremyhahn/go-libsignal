package record

import "encoding/json"

// The JSON test serializers live in this untagged file so FIPS builds keep the tests that use them.

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
