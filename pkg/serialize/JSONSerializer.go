package serialize

import (
	"encoding/json"
	groupRecord "github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/logger"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// NewJSONSerializer will return a serializer for all Signal objects that will
// be responsible for converting objects to and from JSON bytes.
func NewJSONSerializer() *Serializer {
	serializer := NewSerializer()

	serializer.SignalMessage = &JSONSignalMessageSerializer{}
	serializer.PreKeySignalMessage = &JSONPreKeySignalMessageSerializer{}
	serializer.SignedPreKeyRecord = &JSONSignedPreKeyRecordSerializer{}
	serializer.PreKeyRecord = &JSONPreKeyRecordSerializer{}
	serializer.State = &JSONStateSerializer{}
	serializer.Session = &JSONSessionSerializer{}
	serializer.SenderKeyMessage = &JSONSenderKeyMessageSerializer{}
	serializer.SenderKeyDistributionMessage = &JSONSenderKeyDistributionMessageSerializer{}
	serializer.SenderKeyRecord = &JSONSenderKeySessionSerializer{}
	serializer.SenderKeyState = &JSONSenderKeyStateSerializer{}

	return serializer
}

// JSONSignalMessageSerializer is a structure for serializing signal messages into
// and from JSON.
type JSONSignalMessageSerializer struct{}

// Serialize will take a signal message structure and convert it to JSON bytes.
func (j *JSONSignalMessageSerializer) Serialize(signalMessage *protocol.SignalMessageStructure) ([]byte, error) {
	serialized, err := json.Marshal(*signalMessage)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: JSON")

	return serialized, nil
}

// Deserialize will take in JSON bytes and return a signal message structure.
func (j *JSONSignalMessageSerializer) Deserialize(serialized []byte) (*protocol.SignalMessageStructure, error) {
	var signalMessage protocol.SignalMessageStructure
	err := json.Unmarshal(serialized, &signalMessage)
	if err != nil {
		logger.Error("Error deserializing signal message: ", err)
		return nil, err
	}

	return &signalMessage, nil
}

// JSONPreKeySignalMessageSerializer is a structure for serializing prekey signal messages
// into and from JSON.
type JSONPreKeySignalMessageSerializer struct{}

// Serialize will take a prekey signal message structure and convert it to JSON bytes.
func (j *JSONPreKeySignalMessageSerializer) Serialize(signalMessage *protocol.PreKeySignalMessageStructure) ([]byte, error) {
	serialized, err := json.Marshal(signalMessage)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: JSON")

	return serialized, nil
}

// Deserialize will take in JSON bytes and return a prekey signal message structure.
func (j *JSONPreKeySignalMessageSerializer) Deserialize(serialized []byte) (*protocol.PreKeySignalMessageStructure, error) {
	var preKeySignalMessage protocol.PreKeySignalMessageStructure
	err := json.Unmarshal(serialized, &preKeySignalMessage)
	if err != nil {
		logger.Error("Error deserializing prekey signal message: ", err)
		return nil, err
	}

	return &preKeySignalMessage, nil
}

// JSONSignedPreKeyRecordSerializer is a structure for serializing signed prekey records
// into and from JSON.
type JSONSignedPreKeyRecordSerializer struct{}

// Serialize will take a signed prekey record structure and convert it to JSON bytes.
func (j *JSONSignedPreKeyRecordSerializer) Serialize(signedPreKey *record.SignedPreKeyStructure) ([]byte, error) {
	serialized, err := json.Marshal(signedPreKey) // #nosec G117 -- serialization of pre-key structure is required by protocol
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: JSON")

	return serialized, nil
}

// Deserialize will take in JSON bytes and return a signed prekey record structure.
func (j *JSONSignedPreKeyRecordSerializer) Deserialize(serialized []byte) (*record.SignedPreKeyStructure, error) {
	var signedPreKeyStructure record.SignedPreKeyStructure
	err := json.Unmarshal(serialized, &signedPreKeyStructure)
	if err != nil {
		logger.Error("Error deserializing signed prekey record: ", err)
		return nil, err
	}

	return &signedPreKeyStructure, nil
}

// JSONPreKeyRecordSerializer is a structure for serializing prekey records
// into and from JSON.
type JSONPreKeyRecordSerializer struct{}

// Serialize will take a prekey record structure and convert it to JSON bytes.
func (j *JSONPreKeyRecordSerializer) Serialize(preKey *record.PreKeyStructure) ([]byte, error) {
	serialized, err := json.Marshal(preKey) // #nosec G117 -- serialization of pre-key structure is required by protocol
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: JSON")

	return serialized, nil
}

// Deserialize will take in JSON bytes and return a prekey record structure.
func (j *JSONPreKeyRecordSerializer) Deserialize(serialized []byte) (*record.PreKeyStructure, error) {
	var preKeyStructure record.PreKeyStructure
	err := json.Unmarshal(serialized, &preKeyStructure)
	if err != nil {
		logger.Error("Error deserializing prekey record: ", err)
		return nil, err
	}

	return &preKeyStructure, nil
}

// JSONStateSerializer is a structure for serializing session states into
// and from JSON.
type JSONStateSerializer struct{}

// Serialize will take a session state structure and convert it to JSON bytes.
func (j *JSONStateSerializer) Serialize(state *record.StateStructure) ([]byte, error) {
	serialized, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: JSON")

	return serialized, nil
}

// Deserialize will take in JSON bytes and return a session state structure.
func (j *JSONStateSerializer) Deserialize(serialized []byte) (*record.StateStructure, error) {
	var stateStructure record.StateStructure
	err := json.Unmarshal(serialized, &stateStructure)
	if err != nil {
		logger.Error("Error deserializing session state: ", err)
		return nil, err
	}

	return &stateStructure, nil
}

// JSONSessionSerializer is a structure for serializing session records into
// and from JSON.
type JSONSessionSerializer struct{}

// Serialize will take a session structure and convert it to JSON bytes.
func (j *JSONSessionSerializer) Serialize(session *record.SessionStructure) ([]byte, error) {
	serialized, err := json.Marshal(session)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: JSON")

	return serialized, nil
}

// Deserialize will take in JSON bytes and return a session structure, which can be
// used to create a new Session Record object.
func (j *JSONSessionSerializer) Deserialize(serialized []byte) (*record.SessionStructure, error) {
	var sessionStructure record.SessionStructure
	err := json.Unmarshal(serialized, &sessionStructure)
	if err != nil {
		logger.Error("Error deserializing session: ", err)
		return nil, err
	}

	return &sessionStructure, nil
}

// JSONSenderKeyDistributionMessageSerializer is a structure for serializing senderkey
// distribution records to and from JSON.
type JSONSenderKeyDistributionMessageSerializer struct{}

// Serialize will take a senderkey distribution message and convert it to JSON bytes.
func (j *JSONSenderKeyDistributionMessageSerializer) Serialize(message *protocol.SenderKeyDistributionMessageStructure) ([]byte, error) {
	serialized, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: JSON")

	return serialized, nil
}

// Deserialize will take in JSON bytes and return a message structure, which can be
// used to create a new SenderKey Distribution object.
func (j *JSONSenderKeyDistributionMessageSerializer) Deserialize(serialized []byte) (*protocol.SenderKeyDistributionMessageStructure, error) {
	var msgStructure protocol.SenderKeyDistributionMessageStructure
	err := json.Unmarshal(serialized, &msgStructure)
	if err != nil {
		logger.Error("Error deserializing senderkey distribution message: ", err)
		return nil, err
	}

	return &msgStructure, nil
}

// JSONSenderKeyMessageSerializer is a structure for serializing senderkey
// messages to and from JSON.
type JSONSenderKeyMessageSerializer struct{}

// Serialize will take a senderkey message and convert it to JSON bytes.
func (j *JSONSenderKeyMessageSerializer) Serialize(message *protocol.SenderKeyMessageStructure) ([]byte, error) {
	serialized, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: JSON")

	return serialized, nil
}

// Deserialize will take in JSON bytes and return a message structure, which can be
// used to create a new SenderKey message object.
func (j *JSONSenderKeyMessageSerializer) Deserialize(serialized []byte) (*protocol.SenderKeyMessageStructure, error) {
	var msgStructure protocol.SenderKeyMessageStructure
	err := json.Unmarshal(serialized, &msgStructure)
	if err != nil {
		logger.Error("Error deserializing senderkey message: ", err)
		return nil, err
	}

	return &msgStructure, nil
}

// JSONSenderKeyStateSerializer is a structure for serializing group session states into
// and from JSON.
type JSONSenderKeyStateSerializer struct{}

// Serialize will take a session state structure and convert it to JSON bytes.
func (j *JSONSenderKeyStateSerializer) Serialize(state *groupRecord.SenderKeyStateStructure) ([]byte, error) {
	serialized, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: JSON")

	return serialized, nil
}

// Deserialize will take in JSON bytes and return a session state structure.
func (j *JSONSenderKeyStateSerializer) Deserialize(serialized []byte) (*groupRecord.SenderKeyStateStructure, error) {
	var stateStructure groupRecord.SenderKeyStateStructure
	err := json.Unmarshal(serialized, &stateStructure)
	if err != nil {
		logger.Error("Error deserializing session state: ", err)
		return nil, err
	}

	return &stateStructure, nil
}

// JSONSenderKeySessionSerializer is a structure for serializing session records into
// and from JSON.
type JSONSenderKeySessionSerializer struct{}

// Serialize will take a session structure and convert it to JSON bytes.
func (j *JSONSenderKeySessionSerializer) Serialize(session *groupRecord.SenderKeyStructure) ([]byte, error) {
	serialized, err := json.Marshal(session)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: JSON")

	return serialized, nil
}

// Deserialize will take in JSON bytes and return a session structure, which can be
// used to create a new Session Record object.
func (j *JSONSenderKeySessionSerializer) Deserialize(serialized []byte) (*groupRecord.SenderKeyStructure, error) {
	var sessionStructure groupRecord.SenderKeyStructure
	err := json.Unmarshal(serialized, &sessionStructure)
	if err != nil {
		logger.Error("Error deserializing session: ", err)
		return nil, err
	}

	return &sessionStructure, nil
}
