//go:build xcaddye2e

package vpnless

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func getFreePort(tb testing.TB) int {
	tb.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitHTTPReady(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("server did not become ready in time")
}

func TestE2E_XCaddyBinary_DeviceAuthAndCookieFlow(t *testing.T) {
	if _, err := exec.LookPath("xcaddy"); err != nil {
		t.Skip("xcaddy not found in PATH")
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("pwd: %v", err)
	}

	tmp := t.TempDir()
	caddyBin := filepath.Join(tmp, "caddy-e2e")
	storagePath := filepath.Join(tmp, "vpnless.db")

	// Build a real Caddy binary with both modules:
	// - this module from local workspace
	// - caddy-docker-proxy (as requested for build compatibility coverage)
	build := exec.Command("xcaddy", "build",
		"--output", caddyBin,
		"--with", "github.com/vpnless/vpnless="+wd,
		"--with", "github.com/lucaslorentz/caddy-docker-proxy/v2",
	)
	build.Dir = tmp
	buildOut, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("xcaddy build failed: %v\n%s", err, string(buildOut))
	}

	port := getFreePort(t)
	caddyfile := fmt.Sprintf(`{
	admin off
	auto_https off
}

http://127.0.0.1:%d {
	device_auth {
		storage_path %s
		pairing_path /pair
		approval_path /caddy-auth
		cookie_name device_auth_token
		rate_limit_pairing off
		rate_limit_approval off
	}

	respond "protected-ok"
}
`, port, storagePath)

	caddyfilePath := filepath.Join(tmp, "Caddyfile")
	if err := os.WriteFile(caddyfilePath, []byte(caddyfile), 0644); err != nil {
		t.Fatalf("write caddyfile: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	run := exec.CommandContext(ctx, caddyBin, "run", "--config", caddyfilePath, "--adapter", "caddyfile")
	run.Dir = tmp
	var runLog bytes.Buffer
	run.Stdout = &runLog
	run.Stderr = &runLog
	if err := run.Start(); err != nil {
		t.Fatalf("start caddy: %v", err)
	}
	defer func() {
		cancel()
		_ = run.Wait()
	}()

	baseURL := "http://127.0.0.1:" + strconv.Itoa(port)
	if err := waitHTTPReady(baseURL+"/pair", 20*time.Second); err != nil {
		t.Fatalf("caddy not ready: %v\nlogs:\n%s", err, runLog.String())
	}

	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 1) unauthenticated should redirect to /pair
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || resp.Header.Get("Location") != "/pair" {
		t.Fatalf("expected 307 to /pair, got %d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// 2) register pending
	pubKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	register := map[string]string{
		"action":     "register",
		"public_key": pubKey,
		"device_id":  "client-ignored",
		"signature":  "",
		"timestamp":  strconv.FormatInt(time.Now().Unix(), 10),
	}
	regBody, _ := json.Marshal(register)
	resp, err = client.Post(baseURL+"/pair/api", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("register status=%d body=%s", resp.StatusCode, string(b))
	}
	var reg PairingResponse
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		t.Fatalf("decode register: %v", err)
	}
	if reg.Status != "pending" || reg.DeviceID == "" {
		t.Fatalf("unexpected register response: %+v", reg)
	}

	// 3) approve
	approve := map[string]string{"public_key": pubKey, "device_id": reg.DeviceID}
	appBody, _ := json.Marshal(approve)
	resp, err = client.Post(baseURL+"/caddy-auth/approve", "application/json", bytes.NewReader(appBody))
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve status=%d", resp.StatusCode)
	}

	// 4) check => authorized + session secret + cookie
	check := map[string]string{
		"action":     "check",
		"public_key": pubKey,
		"device_id":  reg.DeviceID,
		"signature":  "",
		"timestamp":  strconv.FormatInt(time.Now().Unix(), 10),
	}
	checkBody, _ := json.Marshal(check)
	resp, err = client.Post(baseURL+"/pair/api", "application/json", bytes.NewReader(checkBody))
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("check status=%d body=%s", resp.StatusCode, string(bodyBytes))
	}
	var chk PairingResponse
	if err := json.Unmarshal(bodyBytes, &chk); err != nil {
		t.Fatalf("decode check: %v body=%s", err, string(bodyBytes))
	}
	if chk.Status != "authorized" || chk.SessionSecret == "" {
		t.Fatalf("expected authorized with session secret, got %+v", chk)
	}
	var authCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "device_auth_token" {
			authCookie = c
			break
		}
	}
	if authCookie == nil || authCookie.Value == "" {
		t.Fatalf("expected auth cookie in check response, cookies=%v", resp.Cookies())
	}

	// 5) session-secret headers only -> access protected
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	proof, err := ComputeSessionProof(chk.SessionSecret, ts)
	if err != nil {
		t.Fatalf("ComputeSessionProof: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/", nil)
	req.Header.Set(HeaderDevicePublicKey, pubKey)
	req.Header.Set(HeaderSessionTimestamp, ts)
	req.Header.Set(HeaderSessionProof, proof)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("session auth request: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(b)) != "protected-ok" {
		t.Fatalf("session-auth expected 200/protected-ok, got %d %q", resp.StatusCode, string(b))
	}

	// 6) cookie fallback only -> access protected
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/", nil)
	req.AddCookie(authCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("cookie request: %v", err)
	}
	b, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(b)) != "protected-ok" {
		t.Fatalf("cookie-auth expected 200/protected-ok, got %d %q", resp.StatusCode, string(b))
	}
}

