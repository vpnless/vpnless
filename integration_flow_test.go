package vpnless

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

type protectedNext struct{}

func (protectedNext) ServeHTTP(w http.ResponseWriter, _ *http.Request) error {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("protected-ok"))
	return nil
}

func newIntegrationMiddleware(t *testing.T) *DeviceAuth {
	t.Helper()

	tmpDir := t.TempDir()
	storage := filepath.Join(tmpDir, "vpnless.db")

	m := &DeviceAuth{
		StoragePath:         storage,
		PairingPath:         "/pair",
		ApprovalPath:        "/caddy-auth",
		CookieName:          "device_auth_token",
		RateLimitPairing:    "off",
		RateLimitApproval:   "off",
		ApprovalBasicAuth:   "",
		ApprovalIPWhitelist: nil,
		logger:              zap.NewNop(),
	}
	store, err := NewDeviceStore(storage)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	m.store = store
	return m
}

func performThroughMiddleware(t *testing.T, m *DeviceAuth, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	if err := m.ServeHTTP(rr, req, protectedNext{}); err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}
	return rr
}

func TestIntegration_PairApprove_SessionAndCookieAuth(t *testing.T) {
	m := newIntegrationMiddleware(t)

	pubKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	// 1) Unauthenticated access should redirect to pairing.
	rr := performThroughMiddleware(t, m, httptest.NewRequest(http.MethodGet, "http://example.local/", nil))
	if rr.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307 redirect, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/pair" {
		t.Fatalf("expected redirect to /pair, got %q", loc)
	}

	// 2) Register device (pending).
	registerReq := map[string]any{
		"action":     "register",
		"public_key": pubKey,
		"device_id":  "client-suggested-id",
		"signature":  "",
		"timestamp":  strconv.FormatInt(time.Now().Unix(), 10),
		"client_info": map[string]string{
			"display_name": "Lab gizmo",
		},
	}
	regBody, _ := json.Marshal(registerReq)
	rr = performThroughMiddleware(t, m, httptest.NewRequest(http.MethodPost, "http://example.local/pair/api", bytes.NewReader(regBody)))
	if rr.Code != http.StatusOK {
		t.Fatalf("register expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	var regResp PairingResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &regResp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	if regResp.Status != "pending" {
		t.Fatalf("register expected pending, got %q", regResp.Status)
	}
	if regResp.DeviceID == "" {
		t.Fatal("register response missing device_id")
	}

	pending := m.store.GetPending()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending device, got %d", len(pending))
	}
	if pending[0].ClientInfo == nil || pending[0].ClientInfo.DisplayName != "Lab gizmo" {
		t.Fatalf("pending display_name not stored: %#v", pending[0].ClientInfo)
	}

	// 3) Approve device.
	approveReq := map[string]string{
		"public_key": pubKey,
		"device_id":  regResp.DeviceID,
	}
	appBody, _ := json.Marshal(approveReq)
	rr = performThroughMiddleware(t, m, httptest.NewRequest(http.MethodPost, "http://example.local/caddy-auth/approve", bytes.NewReader(appBody)))
	if rr.Code != http.StatusOK {
		t.Fatalf("approve expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	// 4) Check after approval should return authorized + cookie + session secret.
	checkReq := map[string]string{
		"action":     "check",
		"public_key": pubKey,
		"device_id":  regResp.DeviceID,
		"signature":  "",
		"timestamp":  strconv.FormatInt(time.Now().Unix(), 10),
	}
	checkBody, _ := json.Marshal(checkReq)
	rr = performThroughMiddleware(t, m, httptest.NewRequest(http.MethodPost, "http://example.local/pair/api", bytes.NewReader(checkBody)))
	if rr.Code != http.StatusOK {
		t.Fatalf("check expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	var checkResp PairingResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &checkResp); err != nil {
		t.Fatalf("decode check response: %v", err)
	}
	if checkResp.Status != "authorized" {
		t.Fatalf("check expected authorized, got %q", checkResp.Status)
	}
	if checkResp.SessionSecret == "" {
		t.Fatal("expected session_secret in authorized check response")
	}

	setCookies := rr.Result().Cookies()
	if len(setCookies) == 0 {
		t.Fatal("expected Set-Cookie on authorized check response")
	}
	var authCookie *http.Cookie
	for _, c := range setCookies {
		if c.Name == m.CookieName {
			authCookie = c
			break
		}
	}
	if authCookie == nil || authCookie.Value == "" {
		t.Fatal("missing auth cookie")
	}

	// 5) Session-secret auth should grant access without cookie.
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	proof, err := ComputeSessionProof(checkResp.SessionSecret, ts)
	if err != nil {
		t.Fatalf("compute session proof: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.local/", nil)
	req.Header.Set(HeaderDevicePublicKey, pubKey)
	req.Header.Set(HeaderSessionTimestamp, ts)
	req.Header.Set(HeaderSessionProof, proof)

	rr = performThroughMiddleware(t, m, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "protected-ok") {
		t.Fatalf("session auth expected protected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	// 6) Cookie fallback should also grant access without session headers.
	req = httptest.NewRequest(http.MethodGet, "http://example.local/", nil)
	req.AddCookie(authCookie)

	rr = performThroughMiddleware(t, m, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "protected-ok") {
		t.Fatalf("cookie auth expected protected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestIntegration_InvalidSessionProofIsRejectedWithoutCookie(t *testing.T) {
	m := newIntegrationMiddleware(t)

	pubKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	ctx := context.Background()
	_, err = m.store.RawExec(ctx, `
INSERT INTO authorized_devices (public_key, device_id, approved_at, remote_addr, session_secret)
VALUES (?,?,?,?,?)`,
		pubKey, "dev-reject", time.Now().Unix(), nil, "c29tZS1zZWNyZXQ=")
	if err != nil {
		t.Fatalf("seed authorized device: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.local/", nil)
	req.Header.Set(HeaderDevicePublicKey, pubKey)
	req.Header.Set(HeaderSessionTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set(HeaderSessionProof, "not-a-valid-proof")

	rr := performThroughMiddleware(t, m, req)
	if rr.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected unauthenticated redirect (307), got %d body=%s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); loc != "/pair" {
		t.Fatalf("expected redirect to /pair, got %q", loc)
	}
}

var _ caddyhttp.Handler = protectedNext{}
