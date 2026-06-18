package protocol

// SerializeAddresses encodes (sender, recipient) SignalAddresses as the
// 36-byte buffer carried in SignalMessage.addresses (proto field 6).
// Returns nil if either address name is not a valid ServiceId string, or if
// either device ID is outside the valid range [1, 127].
//
// Wire layout (matching Rust serialize_addresses in protocol.rs:250-263):
//
//	[sender_service_id_fixed_width_binary(17)][sender_device_id_u8(1)]
//	[recipient_service_id_fixed_width_binary(17)][recipient_device_id_u8(1)]
//
// Device IDs fit in u8 by Signal protocol convention; the uint32 → byte
// truncation is intentional and matches Rust's DeviceId::into() call.
func SerializeAddresses(sender, recipient *SignalAddress) []byte {
	if sender == nil || recipient == nil {
		return nil
	}
	if sender.DeviceID() == 0 || sender.DeviceID() > 127 {
		return nil
	}
	if recipient.DeviceID() == 0 || recipient.DeviceID() > 127 {
		return nil
	}
	senderSID, err := ServiceIdFromServiceIdString(sender.Name())
	if err != nil {
		return nil
	}
	recipientSID, err := ServiceIdFromServiceIdString(recipient.Name())
	if err != nil {
		return nil
	}

	buf := make([]byte, 36)
	senderFW := senderSID.FixedWidthBinary()
	copy(buf[0:17], senderFW[:])
	buf[17] = byte(sender.DeviceID())
	recipientFW := recipientSID.FixedWidthBinary()
	copy(buf[18:35], recipientFW[:])
	buf[35] = byte(recipient.DeviceID())
	return buf
}
