using System.Security.Cryptography;
using System.Text;

namespace Vpnless;

/// <summary>
/// HMAC-SHA256 session proofs keyed by the pairing-issued session secret (never sent on the wire).
/// Wire format matches Go <c>vpnless.ComputeSessionProof</c> and JS <c>computeClientSessionProof</c>.
/// </summary>
public static class SessionProof
{
    /// <summary>Prefix for the signed message (versioned).</summary>
    public const string SchemeV1Prefix = "v1|";

    /// <summary>Default clock skew — matches <c>vpnless.DefaultSessionProofSkew</c>.</summary>
    public static readonly TimeSpan DefaultSkew = TimeSpan.FromMinutes(5);

    /// <summary>Builds UTF-8 message bytes: <c>v1|</c> + timestamp string.</summary>
    public static byte[] MessageV1(string timestamp) => Encoding.UTF8.GetBytes(SchemeV1Prefix + timestamp);

    /// <summary>Returns base64(HMAC-SHA256(secretRaw, "v1|"+timestamp)).</summary>
    /// <param name="secretBase64">Pairing-stored session secret (standard base64).</param>
    /// <param name="timestamp">Unix seconds as decimal string (same as JS).</param>
    public static string ComputeProofBase64(string secretBase64, string timestamp)
    {
        if (string.IsNullOrEmpty(secretBase64) || string.IsNullOrEmpty(timestamp))
        {
            throw new ArgumentException("secret and timestamp are required");
        }

        var secret = Convert.FromBase64String(secretBase64);
        if (secret.Length == 0)
        {
            throw new ArgumentException("empty session secret");
        }

        var mac = HMACSHA256.HashData(secret, MessageV1(timestamp));
        return Convert.ToBase64String(mac);
    }

    /// <summary>Verifies proof; uses constant-time comparison on decoded MAC bytes.</summary>
    public static bool Verify(
        string secretBase64,
        string timestamp,
        string proofBase64,
        DateTimeOffset now,
        TimeSpan maxSkew)
    {
        if (string.IsNullOrEmpty(secretBase64)
            || string.IsNullOrEmpty(timestamp)
            || string.IsNullOrEmpty(proofBase64))
        {
            return false;
        }

        if (!long.TryParse(timestamp, System.Globalization.NumberStyles.Integer, null, out var unixSec))
        {
            return false;
        }

        var ts = DateTimeOffset.FromUnixTimeSeconds(unixSec);
        var delta = now - ts;
        if (delta > maxSkew || delta < -maxSkew)
        {
            return false;
        }

        byte[] wantMac;
        byte[] gotMac;
        try
        {
            wantMac = Convert.FromBase64String(ComputeProofBase64(secretBase64, timestamp));
            gotMac = Convert.FromBase64String(proofBase64);
        }
        catch
        {
            return false;
        }

        return wantMac.Length == gotMac.Length && CryptographicOperations.FixedTimeEquals(wantMac, gotMac);
    }

    /// <summary>
    /// Builds the three headers a browser or native client sends after pairing (<c>localStorage</c> / secure store).
    /// </summary>
    /// <param name="devicePublicKeyBase64">From stored keypair JSON <c>publicKey</c>.</param>
    /// <param name="sessionSecretBase64">From <c>device_auth_session_secret</c>.</param>
    public static IReadOnlyDictionary<string, string> BuildRequestHeaders(
        string devicePublicKeyBase64,
        string sessionSecretBase64,
        DateTimeOffset? now = null)
    {
        now ??= DateTimeOffset.UtcNow;
        var ts = now.Value.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var proof = ComputeProofBase64(sessionSecretBase64, ts);
        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [SessionAuthHeaders.DevicePublicKey] = devicePublicKeyBase64,
            [SessionAuthHeaders.SessionTimestamp] = ts,
            [SessionAuthHeaders.SessionProof] = proof
        };
    }
}
