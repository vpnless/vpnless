namespace Vpnless;

/// <summary>
/// HTTP header names for device session HMAC — must match <c>vpnless.go</c> and <c>vpnless-client-auth.js</c>.
/// </summary>
public static class SessionAuthHeaders
{
    public const string SessionProof = "X-Session-Proof";

    public const string SessionTimestamp = "X-Session-Timestamp";

    public const string DevicePublicKey = "X-Device-Public-Key";

    public const string DeviceSig = "X-Device-Sig";

    public const string DeviceTimestamp = "X-Device-Timestamp";
}
