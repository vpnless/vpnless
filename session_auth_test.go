package vpnless

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestComputeSessionProofRoundTrip(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901")) // 32 bytes
	ts := "1739000000"

	proof, err := ComputeSessionProof(secret, ts)
	if err != nil {
		t.Fatal(err)
	}
	if proof == "" {
		t.Fatal("empty proof")
	}

	if !VerifySessionProof(secret, ts, proof, time.Unix(1739000000, 0), DefaultSessionProofSkew) {
		t.Fatal("VerifySessionProof should accept valid proof")
	}
}

func TestVerifySessionProofWrongSecret(t *testing.T) {
	secretA := base64.StdEncoding.EncodeToString([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	secretB := base64.StdEncoding.EncodeToString([]byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	ts := "1739000000"
	proof, err := ComputeSessionProof(secretA, ts)
	if err != nil {
		t.Fatal(err)
	}
	if VerifySessionProof(secretB, ts, proof, time.Unix(1739000000, 0), DefaultSessionProofSkew) {
		t.Fatal("wrong secret must fail")
	}
}

func TestVerifySessionProofWrongTimestamp(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	ts := "1739000000"
	proof, err := ComputeSessionProof(secret, ts)
	if err != nil {
		t.Fatal(err)
	}
	if VerifySessionProof(secret, "1739000001", proof, time.Unix(1739000000, 0), DefaultSessionProofSkew) {
		t.Fatal("timestamp mismatch must fail")
	}
}

func TestVerifySessionProofClockSkew(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	ts := "1739000000"
	proof, err := ComputeSessionProof(secret, ts)
	if err != nil {
		t.Fatal(err)
	}
	// 10 minutes in the past vs 5 minute skew
	old := time.Unix(1739000000, 0).Add(-10 * time.Minute)
	if VerifySessionProof(secret, ts, proof, old, DefaultSessionProofSkew) {
		t.Fatal("expired skew must fail")
	}
}

func TestVerifySessionProofEmptyInputs(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	if VerifySessionProof("", "1", "x", time.Now(), DefaultSessionProofSkew) {
		t.Fatal("empty secret")
	}
	if VerifySessionProof(secret, "", "x", time.Now(), DefaultSessionProofSkew) {
		t.Fatal("empty timestamp")
	}
	if VerifySessionProof(secret, "1", "", time.Now(), DefaultSessionProofSkew) {
		t.Fatal("empty proof")
	}
}

func TestSessionProofMessageV1(t *testing.T) {
	got := string(SessionProofMessageV1("123"))
	want := SessionProofScheme + "123"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
