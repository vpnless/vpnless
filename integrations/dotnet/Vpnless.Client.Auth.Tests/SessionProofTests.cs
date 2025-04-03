using Xunit;

namespace Vpnless.Client.Auth.Tests;

public class SessionProofTests
{
    [Fact]
    public void ComputeThenVerify_RoundTrip()
    {
        var secret = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes("01234567890123456789012345678901")); // 32 bytes
        const string ts = "1739000000";
        var proof = SessionProof.ComputeProofBase64(secret, ts);
        Assert.False(string.IsNullOrEmpty(proof));
        Assert.True(SessionProof.Verify(secret, ts, proof, DateTimeOffset.FromUnixTimeSeconds(1739000000), SessionProof.DefaultSkew));
    }

    [Fact]
    public void Verify_WrongSecret_Fails()
    {
        var secretA = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        var secretB = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
        const string ts = "1739000000";
        var proof = SessionProof.ComputeProofBase64(secretA, ts);
        Assert.False(SessionProof.Verify(secretB, ts, proof, DateTimeOffset.FromUnixTimeSeconds(1739000000), SessionProof.DefaultSkew));
    }

    [Fact]
    public void Verify_WrongTimestamp_Fails()
    {
        var secret = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
        const string ts = "1739000000";
        var proof = SessionProof.ComputeProofBase64(secret, ts);
        Assert.False(SessionProof.Verify(secret, "1739000001", proof, DateTimeOffset.FromUnixTimeSeconds(1739000000), SessionProof.DefaultSkew));
    }

    [Fact]
    public void Verify_ClockSkew_Fails()
    {
        var secret = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
        const string ts = "1739000000";
        var proof = SessionProof.ComputeProofBase64(secret, ts);
        var now = DateTimeOffset.FromUnixTimeSeconds(1739000000).AddMinutes(-10);
        Assert.False(SessionProof.Verify(secret, ts, proof, now, SessionProof.DefaultSkew));
    }

    [Fact]
    public void MessageV1_MatchesGo()
    {
        var got = System.Text.Encoding.UTF8.GetString(SessionProof.MessageV1("123"));
        Assert.Equal(SessionProof.SchemeV1Prefix + "123", got);
    }

    [Fact]
    public void BuildRequestHeaders_HasThreeHeaders()
    {
        var secret = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("01234567890123456789012345678901"));
        const string pub = "dGVzdC1rZXk="; // arbitrary valid b64
        var now = DateTimeOffset.FromUnixTimeSeconds(1739000000);
        var h = SessionProof.BuildRequestHeaders(pub, secret, now);
        Assert.Equal(pub, h[SessionAuthHeaders.DevicePublicKey]);
        Assert.Equal("1739000000", h[SessionAuthHeaders.SessionTimestamp]);
        Assert.True(SessionProof.Verify(secret, h[SessionAuthHeaders.SessionTimestamp]!, h[SessionAuthHeaders.SessionProof]!, now, SessionProof.DefaultSkew));
    }
}
