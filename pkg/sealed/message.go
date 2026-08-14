package sealed

import (
	"github.com/jeremyhahn/go-libsignal/pkg/proto/sealedpb"
	"google.golang.org/protobuf/proto"
)

// UnidentifiedSenderMessageContent holds the inner content of a sealed
// sender message, including the message type, sender certificate,
// encrypted content, content hint, and optional group ID.
type UnidentifiedSenderMessageContent struct {
	serialized  []byte
	msgType     uint32
	sender      *SenderCertificate
	contents    []byte
	contentHint ContentHint
	groupID     []byte
}

// NewUnidentifiedSenderMessageContent creates a new USMC and serializes
// it to protobuf.
func NewUnidentifiedSenderMessageContent(
	msgType uint32,
	sender *SenderCertificate,
	contents []byte,
	contentHint ContentHint,
	groupID []byte,
) (*UnidentifiedSenderMessageContent, error) {
	if sender == nil {
		return nil, &CertificateError{Detail: "sender certificate must not be nil"}
	}

	pbType := sealedpb.UnidentifiedSenderMessage_Message_Type(msgType)
	pbMsg := &sealedpb.UnidentifiedSenderMessage_Message{
		Type:              pbType.Enum(),
		SenderCertificate: sender.Serialize(),
		Content:           contents,
	}

	if contentHint != ContentHintDefault {
		pbHint := sealedpb.UnidentifiedSenderMessage_Message_ContentHint(contentHint)
		pbMsg.ContentHint = pbHint.Enum()
	}
	if len(groupID) > 0 {
		pbMsg.GroupId = groupID
	}

	serialized, err := proto.Marshal(pbMsg)
	if err != nil {
		return nil, err
	}

	return &UnidentifiedSenderMessageContent{
		serialized:  serialized,
		msgType:     msgType,
		sender:      sender,
		contents:    contents,
		contentHint: contentHint,
		groupID:     groupID,
	}, nil
}

// DeserializeUnidentifiedSenderMessageContent reconstructs a USMC from
// protobuf-encoded bytes.
func DeserializeUnidentifiedSenderMessageContent(data []byte) (*UnidentifiedSenderMessageContent, error) {
	pbMsg := &sealedpb.UnidentifiedSenderMessage_Message{}
	if err := proto.Unmarshal(data, pbMsg); err != nil {
		return nil, err
	}

	senderCertBytes := pbMsg.GetSenderCertificate()
	if senderCertBytes == nil {
		return nil, &CertificateError{Detail: "USMC missing sender certificate"}
	}

	sender, err := DeserializeSenderCertificate(senderCertBytes)
	if err != nil {
		return nil, err
	}

	// Validate that the protobuf Type field corresponds to a known message type.
	msgType := uint32(pbMsg.GetType())
	if _, known := sealedpb.UnidentifiedSenderMessage_Message_Type_name[int32(msgType)]; !known {
		return nil, ErrUnknownUSMCType
	}

	// Rust: rust/protocol/src/sealed_sender.rs:526-528 returns
	// InvalidProtobufEncoding when the content field is absent. Enforce the
	// same check here so malformed USMCs without a payload are rejected
	// rather than silently accepted with nil contents.
	if pbMsg.Content == nil {
		return nil, &CertificateError{Detail: "USMC missing required content field"}
	}

	var hint ContentHint
	if pbMsg.ContentHint != nil {
		hint = ContentHint(pbMsg.GetContentHint())
	}

	return &UnidentifiedSenderMessageContent{
		serialized:  data,
		msgType:     msgType,
		sender:      sender,
		contents:    pbMsg.GetContent(),
		contentHint: hint,
		groupID:     pbMsg.GetGroupId(),
	}, nil
}

// Type returns the message type (1=PreKey, 2=Whisper, 7=SenderKey, 8=Plaintext).
func (u *UnidentifiedSenderMessageContent) Type() uint32 {
	return u.msgType
}

// Sender returns the sender certificate.
func (u *UnidentifiedSenderMessageContent) Sender() *SenderCertificate {
	return u.sender
}

// Contents returns the inner encrypted message bytes.
func (u *UnidentifiedSenderMessageContent) Contents() []byte {
	return u.contents
}

// ContentHint returns the content hint for error handling.
func (u *UnidentifiedSenderMessageContent) ContentHint() ContentHint {
	return u.contentHint
}

// GroupID returns the optional group ID.
func (u *UnidentifiedSenderMessageContent) GroupID() []byte {
	return u.groupID
}

// Serialize returns the protobuf-encoded USMC bytes.
func (u *UnidentifiedSenderMessageContent) Serialize() []byte {
	return u.serialized
}
