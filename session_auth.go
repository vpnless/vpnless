package vpnless

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"
)

// SessionProofScheme is the prefix for the HMAC message (versioned for future changes).
const SessionProofScheme = "v1|"

func SessionProofMessageV1(timestamp string) []byte {
	return []byte(SessionProofScheme + timestamp)
}

// ComputeSessionProof returns base64(HMAC-SHA256(secret, "v1|"+timestamp)).
// secretB64 is the device session secret (never sent on the wire; only this proof is sent).
func ComputeSessionProof(secretB64, timestamp string) (string, error) {
	secret, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		return "", fmt.Errorf("invalid session secret encoding: %w", err)
	}
	if len(secret) == 0 {
		return "", fmt.Errorf("empty session secret")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(SessionProofMessageV1(timestamp))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// DefaultSessionProofSkew is the allowed clock skew for session timestamp verification.
const DefaultSessionProofSkew = 5 * time.Minute

func VerifySessionProof(secretB64, timestamp, proofB64 string, now time.Time, maxSkew time.Duration) bool {
	if secretB64 == "" || timestamp == "" || proofB64 == "" {
		return false
	}
	tsUnix, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	ts := time.Unix(tsUnix, 0)
	if now.Sub(ts) > maxSkew || ts.Sub(now) > maxSkew {
		return false
	}
	expected, err := ComputeSessionProof(secretB64, timestamp)
	if err != nil {
		return false
	}
	got, err := base64.StdEncoding.DecodeString(proofB64)
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(expected)
	if err != nil {
		return false
	}
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}
