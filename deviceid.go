package vpnless

import "github.com/vpnless/vpnless/devicestore"

func (*DeviceAuth) computeDeviceID(pubKey string) string {
	return devicestore.ComputeStableDeviceID(pubKey)
}
