package vpnless

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

func pairingWriteJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func pairingWriteJSONErrorWithCode(w http.ResponseWriter, status int, message, code string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message, "code": code})
}

func pairingWriteJSON(w http.ResponseWriter, v any) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(v)
}

// PairingResponse: JSON for the pairing SPA poll/register endpoints.
type PairingResponse struct {
	PublicKey string `json:"public_key"`
	DeviceID  string `json:"device_id"`
	Status    string `json:"status"`
	Token     string `json:"token,omitempty"`
	// SessionSecret is the per-device shared secret for HMAC auth (store client-side only; never send raw on requests).
	SessionSecret string `json:"session_secret,omitempty"`
	// DenyMessage is set when Status is "denied" and the admin supplied a custom message.
	DenyMessage string `json:"deny_message,omitempty"`
	// CanRetry is true when Status is "denied" and the user may request access one more time.
	CanRetry bool `json:"can_retry,omitempty"`
	// SnarkIndex selects DENY_SNARKS[snark_index] on the pairing page when the admin picked a line (omit = random).
	SnarkIndex *int `json:"snark_index,omitempty"`
}

func applyPairingSnarkIndex(resp *PairingResponse, sn sql.NullInt64) {
	if !sn.Valid {
		return
	}
	if sn.Int64 < 0 || sn.Int64 > int64(MaxPairingSnarkIndex) {
		return
	}
	v := int(sn.Int64)
	resp.SnarkIndex = &v
}

func (m *DeviceAuth) handlePairingAPI(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		pairingWriteJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return nil
	}

	var req struct {
		Action     string         `json:"action"`
		PublicKey  string         `json:"public_key"`
		DeviceID   string         `json:"device_id"`
		Signature  string         `json:"signature"`
		Timestamp  string         `json:"timestamp"`
		ClientInfo map[string]any `json:"client_info"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		pairingWriteJSONError(w, http.StatusBadRequest, "Invalid JSON request body")
		return nil
	}

	switch req.Action {
	case "register":
		return m.handlePairingRegister(w, r, &req)
	case "check":
		return m.handlePairingCheck(w, r, &req)
	default:
		pairingWriteJSONError(w, http.StatusBadRequest, "Unknown action")
		return nil
	}
}

func (m *DeviceAuth) handlePairingRegister(w http.ResponseWriter, r *http.Request, req *struct {
	Action     string         `json:"action"`
	PublicKey  string         `json:"public_key"`
	DeviceID   string         `json:"device_id"`
	Signature  string         `json:"signature"`
	Timestamp  string         `json:"timestamp"`
	ClientInfo map[string]any `json:"client_info"`
}) error {
	// Verify signature (allow empty signature for initial registration)
	if req.Signature != "" && !m.verifySignature(req.PublicKey, req.Signature, req.Timestamp) {
		pairingWriteJSONError(w, http.StatusUnauthorized, "Invalid signature")
		return nil
	}

	deviceID := m.computeDeviceID(req.PublicKey)
	pendingClientInfo := buildPendingClientInfo(r, req.ClientInfo)
	resolvedClientIP := m.clientIP(r)

	var resp PairingResponse
	var cookieToken string

	err := m.store.ApplyTransactional(func(work *DeviceStore) error {
		if work.IsAuthorized(req.PublicKey) {
			token := GenerateDeviceToken(req.PublicKey)
			work.AddAuthorizedToken(token)
			cookieToken = token
			resp = PairingResponse{
				PublicKey:     req.PublicKey,
				DeviceID:      deviceID,
				Status:        "authorized",
				Token:         token,
				SessionSecret: work.SessionSecretForPublicKey(req.PublicKey),
			}
			return nil
		}
		if work.PairingPermanentlyBlocked(req.PublicKey) {
			return ErrPairingPermanentlyBlocked
		}
		work.DeactivatePairingDenial(req.PublicKey)
		merged := pendingClientInfo
		if merged != nil && merged.DisplayName == "" && work.IsPending(req.PublicKey) {
			if cur := work.PendingClientInfoForPublicKey(req.PublicKey); cur != nil && cur.DisplayName != "" {
				merged.DisplayName = cur.DisplayName
			}
		}
		work.AddPending(req.PublicKey, deviceID, resolvedClientIP, merged)
		resp = PairingResponse{
			PublicKey: req.PublicKey,
			DeviceID:  deviceID,
			Status:    "pending",
		}
		return nil
	})
	if errors.Is(err, ErrPairingPermanentlyBlocked) {
		pairingWriteJSONErrorWithCode(w, http.StatusForbidden, "Pairing is no longer allowed for this device.", "pairing_exhausted")
		return nil
	}
	if err != nil {
		m.logger.Error("pairing register failed", zap.Error(err))
		pairingWriteJSONError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil
	}

	if resp.Status == "authorized" && cookieToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     m.CookieName,
			Value:    cookieToken,
			Path:     "/",
			Domain:   m.cookieDomainForRequest(r),
			MaxAge:   DeviceAuthCookieMaxAgeSec,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteStrictMode,
		})
	}

	return pairingWriteJSON(w, resp)
}

func buildPendingClientInfo(r *http.Request, clientInfo map[string]any) *PendingClientInfo {
	ua := stringFromAny(clientInfo["user_agent"])
	if ua == "" {
		ua = r.UserAgent()
	}
	browser, browserVer, osName, osVer := parseUserAgent(ua)

	info := &PendingClientInfo{
		UserAgent:           ua,
		Browser:             browser,
		BrowserVersion:      browserVer,
		OS:                  osName,
		OSVersion:           osVer,
		Screen:              stringFromAny(clientInfo["screen"]),
		Timezone:            stringFromAny(clientInfo["timezone"]),
		Languages:           stringFromAny(clientInfo["languages"]),
		HardwareConcurrency: stringFromAny(clientInfo["hardware_concurrency"]),
		XForwardedFor:       r.Header.Get("X-Forwarded-For"),
		XRealIP:             r.Header.Get("X-Real-IP"),
		Forwarded:           r.Header.Get("Forwarded"),
		PeerRemoteAddr:      r.RemoteAddr,
		DisplayName:         SanitizeDisplayName(stringFromAny(clientInfo["display_name"])),
	}
	return info
}

func stringFromAny(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(s), 'f', -1, 32)
	case int:
		return strconv.Itoa(s)
	case int32:
		return strconv.FormatInt(int64(s), 10)
	case int64:
		return strconv.FormatInt(s, 10)
	case uint:
		return strconv.FormatUint(uint64(s), 10)
	case uint32:
		return strconv.FormatUint(uint64(s), 10)
	case uint64:
		return strconv.FormatUint(s, 10)
	case bool:
		if s {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func (m *DeviceAuth) handlePairingCheck(w http.ResponseWriter, r *http.Request, req *struct {
	Action     string         `json:"action"`
	PublicKey  string         `json:"public_key"`
	DeviceID   string         `json:"device_id"`
	Signature  string         `json:"signature"`
	Timestamp  string         `json:"timestamp"`
	ClientInfo map[string]any `json:"client_info"`
}) error {
	if err := m.store.Load(); err != nil {
		m.logger.Warn("pairing check reload failed", zap.Error(err))
	}

	m.mu.RLock()
	pub := req.PublicKey
	authorized := m.store.IsAuthorized(pub)
	pending := false
	denyMsg := ""
	activeDenied := false
	strikes := 0
	var snarkIdx sql.NullInt64
	if !authorized {
		pending = m.store.IsPending(pub)
		denyMsg, activeDenied, strikes, snarkIdx = m.store.GetPairingDenialState(pub)
	}
	m.mu.RUnlock()

	if !authorized {
		if pending {
			return pairingWriteJSON(w, PairingResponse{
				PublicKey: pub,
				DeviceID:  req.DeviceID,
				Status:    "pending",
			})
		}
		if strikes >= MaxPairingDenyStrikes {
			resp := PairingResponse{PublicKey: pub, DeviceID: req.DeviceID, Status: "permanently_denied"}
			if strings.TrimSpace(denyMsg) != "" {
				resp.DenyMessage = denyMsg
			}
			applyPairingSnarkIndex(&resp, snarkIdx)
			return pairingWriteJSON(w, resp)
		}
		if activeDenied {
			resp := PairingResponse{
				PublicKey: pub,
				DeviceID:  req.DeviceID,
				Status:    "denied",
				CanRetry:  strikes < MaxPairingDenyStrikes,
			}
			if strings.TrimSpace(denyMsg) != "" {
				resp.DenyMessage = denyMsg
			}
			applyPairingSnarkIndex(&resp, snarkIdx)
			return pairingWriteJSON(w, resp)
		}
		return pairingWriteJSON(w, PairingResponse{
			PublicKey: pub,
			DeviceID:  req.DeviceID,
			Status:    "pending",
		})
	}

	var token, sessionSecret string
	if err := m.store.ApplyTransactional(func(work *DeviceStore) error {
		if !work.IsAuthorized(req.PublicKey) {
			return nil
		}
		token = GenerateDeviceToken(req.PublicKey)
		work.AddAuthorizedToken(token)
		sessionSecret = work.SessionSecretForPublicKey(req.PublicKey)
		return nil
	}); err != nil {
		m.logger.Error("pairing check token persist failed", zap.Error(err))
		pairingWriteJSONError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil
	}

	if token == "" {
		return pairingWriteJSON(w, PairingResponse{
			PublicKey: req.PublicKey,
			DeviceID:  req.DeviceID,
			Status:    "pending",
		})
	}

	http.SetCookie(w, &http.Cookie{
		Name:     m.CookieName,
		Value:    token,
		Path:     "/",
		Domain:   m.cookieDomainForRequest(r),
		MaxAge:   DeviceAuthCookieMaxAgeSec,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})

	return pairingWriteJSON(w, PairingResponse{
		PublicKey:     req.PublicKey,
		DeviceID:      req.DeviceID,
		Status:        "authorized",
		Token:         token,
		SessionSecret: sessionSecret,
	})
}

func GenerateKeyPair() (publicKey, privateKey string, err error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate key pair: %w", err)
	}

	publicKey = base64.StdEncoding.EncodeToString(pubKey)
	privateKey = base64.StdEncoding.EncodeToString(privKey)

	return publicKey, privateKey, nil
}

func SignMessage(privateKeyB64, message string) (string, error) {
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %w", err)
	}

	if len(privateKeyBytes) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key size")
	}

	signature := ed25519.Sign(privateKeyBytes, []byte(message))
	return base64.StdEncoding.EncodeToString(signature), nil
}
