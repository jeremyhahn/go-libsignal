// Package backup implements reading, writing, and validating Signal message
// backup files. It provides key derivation from account entropy pools,
// frame-level encryption and decryption using AES-256-CBC with HMAC-SHA256,
// and varint-delimited protobuf frame parsing.
//
// This is a port of the Rust libsignal message-backup module.
package backup

import "fmt"

// Purpose describes the intended use of a backup file.
type Purpose int

const (
	// PurposeDeviceTransfer indicates the backup is used for device-to-device transfer.
	PurposeDeviceTransfer Purpose = 0
	// PurposeRemoteBackup indicates the backup is stored remotely.
	PurposeRemoteBackup Purpose = 1
)

// String returns a human-readable representation of the Purpose.
func (p Purpose) String() string {
	switch p {
	case PurposeDeviceTransfer:
		return "DeviceTransfer"
	case PurposeRemoteBackup:
		return "RemoteBackup"
	default:
		return fmt.Sprintf("Purpose(%d)", int(p))
	}
}

// ParsePurpose parses a purpose string into a Purpose value.
// It accepts "backup", "remote_backup", "remote-backup" for RemoteBackup,
// and "transfer", "device_transfer", "device-transfer" for DeviceTransfer.
func ParsePurpose(s string) (Purpose, error) {
	switch s {
	case "backup", "remote_backup", "remote-backup":
		return PurposeRemoteBackup, nil
	case "transfer", "device_transfer", "device-transfer":
		return PurposeDeviceTransfer, nil
	default:
		return 0, &ErrUnknownPurpose{Value: s}
	}
}
