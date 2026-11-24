package protocol

// SerializeAddresses encodes sender and recipient as the 36-byte SignalMessage.addresses field (17-byte ServiceId, 1-byte device each); nil for invalid input.
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
