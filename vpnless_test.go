package vpnless

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"go.uber.org/zap"
)

func testStore(t *testing.T) *DeviceStore {
	t.Helper()
	ds, err := NewDeviceStore(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ds.Close() })
	return ds
}

func seedAuthorizedDevices(t *testing.T, ds *DeviceStore, devices ...DeviceInfo) {
	t.Helper()
	ctx := context.Background()
	for _, d := range devices {
		ts := d.ApprovedAt.Unix()
		if ts == 0 {
			ts = time.Now().Unix()
		}
		var raddr any
		if d.RemoteAddr != "" {
			raddr = d.RemoteAddr
		}
		_, err := ds.RawExec(ctx, `
INSERT INTO authorized_devices (public_key, device_id, approved_at, remote_addr, session_secret)
VALUES (?,?,?,?,?)`,
			d.PublicKey, d.DeviceID, ts, raddr, d.SessionSecret)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func seedTokens(t *testing.T, ds *DeviceStore, tokens ...string) {
	t.Helper()
	ctx := context.Background()
	for _, tok := range tokens {
		_, err := ds.RawExec(ctx, `INSERT OR IGNORE INTO authorized_tokens (token) VALUES (?)`, tok)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func testDeviceAuthWithStore(ds *DeviceStore) *DeviceAuth {
	return &DeviceAuth{
		store:      ds,
		CookieName: "device_auth_token",
		logger:     zap.NewNop(),
	}
}

func TestCheckAuthentication_SessionProofAndCookie(t *testing.T) {
	t.Run("session_secret_hmac_without_cookie", func(t *testing.T) {
		secretB64 := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
		pubKey := "test-public-key-b64"
		ds := testStore(t)
		seedAuthorizedDevices(t, ds, DeviceInfo{
			PublicKey: pubKey, DeviceID: "dev1", SessionSecret: secretB64,
		})
		m := testDeviceAuthWithStore(ds)

		ts := strconv.FormatInt(time.Now().Unix(), 10)
		proof, err := ComputeSessionProof(secretB64, ts)
		if err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(HeaderDevicePublicKey, pubKey)
		req.Header.Set(HeaderSessionTimestamp, ts)
		req.Header.Set(HeaderSessionProof, proof)

		ok, err := m.checkAuthentication(httptest.NewRecorder(), req)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatal("session HMAC (secret key proof) should authenticate")
		}
	})

	t.Run("http_only_cookie_without_session_headers", func(t *testing.T) {
		token := "test-token-value"
		ds := testStore(t)
		seedTokens(t, ds, token)
		m := testDeviceAuthWithStore(ds)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "device_auth_token", Value: token})

		ok, err := m.checkAuthentication(httptest.NewRecorder(), req)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatal("valid cookie should authenticate")
		}
	})
}

func TestCheckAuthentication_SessionPreferredOverBadCookie(t *testing.T) {
	secretB64 := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	pubKey := "pk1"

	ds := testStore(t)
	seedAuthorizedDevices(t, ds, DeviceInfo{
		PublicKey: pubKey, DeviceID: "d1", SessionSecret: secretB64,
	})

	m := testDeviceAuthWithStore(ds)

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	proof, _ := ComputeSessionProof(secretB64, ts)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(HeaderDevicePublicKey, pubKey)
	req.Header.Set(HeaderSessionTimestamp, ts)
	req.Header.Set(HeaderSessionProof, proof)
	req.AddCookie(&http.Cookie{Name: "device_auth_token", Value: "not-in-store"})

	ok, err := m.checkAuthentication(httptest.NewRecorder(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("valid session should win")
	}
}

func TestCheckAuthentication_InvalidCookieNoSession(t *testing.T) {
	ds := testStore(t)
	seedTokens(t, ds, "good")

	m := testDeviceAuthWithStore(ds)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "device_auth_token", Value: "wrong"})

	ok, err := m.checkAuthentication(httptest.NewRecorder(), req)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("invalid cookie should not authenticate")
	}
}

func TestCheckAuthentication_SessionWrongProofFallsBackToCookie(t *testing.T) {
	secretB64 := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	pubKey := "pk1"
	token := "valid-token"

	ds := testStore(t)
	seedAuthorizedDevices(t, ds, DeviceInfo{
		PublicKey: pubKey, DeviceID: "d1", SessionSecret: secretB64,
	})
	seedTokens(t, ds, token)

	m := testDeviceAuthWithStore(ds)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(HeaderDevicePublicKey, pubKey)
	req.Header.Set(HeaderSessionTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set(HeaderSessionProof, "wrongproof")
	req.AddCookie(&http.Cookie{Name: "device_auth_token", Value: token})

	ok, err := m.checkAuthentication(httptest.NewRecorder(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("bad session proof should fall through to cookie")
	}
}

func TestCheckAuthentication_Ed25519WhenNoSessionOrCookie(t *testing.T) {
	ds := testStore(t)
	m := testDeviceAuthWithStore(ds)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ok, err := m.checkAuthentication(httptest.NewRecorder(), req)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("empty request should not authenticate")
	}
}

func TestTouchAuthorizedAuthTelemetry(t *testing.T) {
	ds := testStore(t)
	pub := "pk-telemetry"
	seedAuthorizedDevices(t, ds, DeviceInfo{
		PublicKey: pub, DeviceID: "dev-t", SessionSecret: "x",
	})
	ds.TouchAuthorizedAuth(pub, AuthTouchCookie)
	list, err := ds.GetAuthorized()
	if err != nil || len(list) != 1 {
		t.Fatalf("GetAuthorized: %v %#v", err, list)
	}
	if list[0].LastSeenCookie.IsZero() || !list[0].LastSeenSessionProof.IsZero() {
		t.Fatalf("expected cookie touch only: cookie=%v proof=%v", list[0].LastSeenCookie, list[0].LastSeenSessionProof)
	}
	ds.TouchAuthorizedAuth(pub, AuthTouchSessionProof)
	list, err = ds.GetAuthorized()
	if err != nil || len(list) != 1 {
		t.Fatalf("GetAuthorized 2: %v", err)
	}
	if list[0].LastSeenSessionProof.IsZero() {
		t.Fatal("expected session proof timestamp after strong touch")
	}
}

func TestUpdateAuthorizedDisplayName(t *testing.T) {
	ds := testStore(t)
	pub := "pk-auth-rename"
	devID := "device-rename"
	seedAuthorizedDevices(t, ds, DeviceInfo{
		PublicKey: pub, DeviceID: devID, SessionSecret: "x",
	})
	if !ds.UpdateAuthorizedDisplayName(pub, "Kitchen tablet") {
		t.Fatal("expected update by public key to succeed")
	}
	list, err := ds.GetAuthorized()
	if err != nil || len(list) != 1 {
		t.Fatalf("GetAuthorized: %v err %v", list, err)
	}
	if list[0].ClientInfo == nil || list[0].ClientInfo.DisplayName != "Kitchen tablet" {
		t.Fatalf("display name not set: %#v", list[0].ClientInfo)
	}
	if !ds.UpdateAuthorizedDisplayName(devID, "Work laptop") {
		t.Fatal("expected update by device_id to succeed")
	}
	list, err = ds.GetAuthorized()
	if err != nil || len(list) != 1 {
		t.Fatalf("GetAuthorized (2): %v err %v", list, err)
	}
	if list[0].ClientInfo == nil || list[0].ClientInfo.DisplayName != "Work laptop" {
		t.Fatalf("display name not updated: %#v", list[0].ClientInfo)
	}
}

func TestDeviceAuth_clientIP_spoofedXFFIgnoredUnlessPeerTrusted(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "198.51.100.22:4444"
	r.Header.Set("X-Forwarded-For", "203.0.113.50")

	m := &DeviceAuth{}
	nets, err := parseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	m.trustedProxyNets = nets
	if got := m.clientIP(r); got != "198.51.100.22" {
		t.Fatalf("direct client with untrusted peer: want 198.51.100.22, got %q", got)
	}

	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "10.1.2.3:9999"
	r2.Header.Set("X-Forwarded-For", "203.0.113.77, 10.1.2.3")
	m2 := &DeviceAuth{trustedProxyNets: nets}
	if got := m2.clientIP(r2); got != "203.0.113.77" {
		t.Fatalf("behind trusted proxy: want 203.0.113.77, got %q", got)
	}

	r3 := httptest.NewRequest("GET", "/", nil)
	r3.RemoteAddr = "198.51.100.5:1"
	r3.Header.Set("X-Forwarded-For", "203.0.113.99")
	m3 := &DeviceAuth{} // no trustedProxyNets — legacy trust
	if got := m3.clientIP(r3); got != "203.0.113.99" {
		t.Fatalf("legacy trust XFF: want 203.0.113.99, got %q", got)
	}
}
