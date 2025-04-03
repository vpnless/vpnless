package vpnless

import "github.com/vpnless/vpnless/devicestore"

// Type aliases and forwards so the Caddy module can keep using familiar names without pulling
// store types into this file repeatedly. The slim CLI links only devicestore.

type (
	DeviceStore           = devicestore.DeviceStore
	DeviceInfo            = devicestore.DeviceInfo
	PendingDevice         = devicestore.PendingDevice
	PendingClientInfo     = devicestore.PendingClientInfo
	AdminAuthSettings     = devicestore.AdminAuthSettings
	AuthorizedAuthTouch   = devicestore.AuthorizedAuthTouch
)

// Auth touch kinds for telemetry (cookie vs session proof vs Ed25519).
const (
	AuthTouchCookie       = devicestore.AuthTouchCookie
	AuthTouchSessionProof = devicestore.AuthTouchSessionProof
	AuthTouchSignature    = devicestore.AuthTouchSignature
)

// ErrPendingDeviceNotFound is re-exported for handlers that compare with errors.Is.
var ErrPendingDeviceNotFound = devicestore.ErrPendingDeviceNotFound

// ErrPairingPermanentlyBlocked is returned when pairing register must be rejected after repeated admin denials.
var ErrPairingPermanentlyBlocked = devicestore.ErrPairingPermanentlyBlocked

// MaxPairingDenyStrikes matches devicestore (admin denials before pairing is closed for that key).
const MaxPairingDenyStrikes = devicestore.MaxPairingDenyStrikes

// MaxPairingSnarkIndex matches devicestore (bounds for admin-selected deny line index).
const MaxPairingSnarkIndex = devicestore.MaxPairingSnarkIndex

// SessionSecretRandomBytes matches the entropy used when approving devices (see devicestore).
const SessionSecretRandomBytes = devicestore.SessionSecretRandomBytes

func NewDeviceStore(path string) (*DeviceStore, error) {
	return devicestore.NewDeviceStore(path)
}

func GenerateDeviceToken(pubKey string) string {
	return devicestore.GenerateDeviceToken(pubKey)
}
