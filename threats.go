package vpnless

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/vpnless/vpnless/devicestore"
	"go.uber.org/zap"
)

type ThreatState struct {
	IP          string    `json:"ip"`
	Mode        string    `json:"mode"`
	SetAt       time.Time `json:"set_at,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	Hits        int       `json:"hits"`
	LastPath    string    `json:"last_path,omitempty"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
	StrikeCount int       `json:"strike_count"`
}

func threatFromPersisted(p devicestore.ThreatPersisted) ThreatState {
	st := ThreatState{
		IP:          p.IP,
		Mode:        p.Mode,
		Hits:        p.Hits,
		LastPath:    p.LastPath,
		StrikeCount: p.StrikeCount,
	}
	if !p.SetAt.IsZero() {
		st.SetAt = p.SetAt
	}
	if !p.ExpiresAt.IsZero() {
		st.ExpiresAt = p.ExpiresAt
	}
	if !p.LastSeen.IsZero() {
		st.LastSeen = p.LastSeen
	}
	return st
}

func (m *DeviceAuth) recordUnauthorizedAttempt(ip, path string) {
	if strings.TrimSpace(ip) == "" {
		return
	}
	m.store.ThreatTouchUnauthorized(ip, path)
}

func (m *DeviceAuth) applyThreatPolicy(w http.ResponseWriter, r *http.Request, ip string) (bool, error) {
	if strings.TrimSpace(ip) == "" {
		return false, nil
	}
	now := time.Now()
	st := m.store.ThreatResolve(ip, now)

	switch st.Mode {
	case "blacklist":
		m.logger.Info("blocked unauthenticated request",
			zap.String("reason", "threat_blacklist"),
			zap.String("client_ip", ip),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("strike_count", st.StrikeCount),
			zap.Int("threat_hits", st.Hits))
		http.Error(w, "Temporarily banned", http.StatusForbidden)
		return true, nil
	case "tarpit":
		m.logger.Info("blocked unauthenticated request",
			zap.String("reason", "threat_tarpit"),
			zap.String("client_ip", ip),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("strike_count", st.StrikeCount))
		var ts *tortureSession
		if m.torture != nil {
			ts = m.torture.begin(ip, "tarpit", r)
		}
		ww := tortureWrapResponseWriter(w, m.torture, ts)
		writeSlowUnauthorized(ww, r)
		if m.torture != nil && ts != nil {
			m.torture.end(ts)
		}
		return true, nil
	case "honeypot":
		m.logger.Info("blocked unauthenticated request",
			zap.String("reason", "threat_honeypot"),
			zap.String("client_ip", ip),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("strike_count", st.StrikeCount))
		var ts *tortureSession
		if m.torture != nil {
			ts = m.torture.begin(ip, "honeypot", r)
		}
		ww := tortureWrapResponseWriter(w, m.torture, ts)
		writeHoneypotSlow(ww, r)
		if m.torture != nil && ts != nil {
			m.torture.end(ts)
		}
		return true, nil
	case "slop":
		m.logger.Info("blocked unauthenticated request",
			zap.String("reason", "threat_slop"),
			zap.String("client_ip", ip),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("strike_count", st.StrikeCount))
		var ts *tortureSession
		if m.torture != nil {
			ts = m.torture.begin(ip, "slop", r)
		}
		ww := tortureWrapResponseWriter(w, m.torture, ts)
		writeEndlessSlopPage(ww, r)
		if m.torture != nil && ts != nil {
			m.torture.end(ts)
		}
		return true, nil
	default:
		if st.StrikeCount >= 10 {
			time.Sleep(3 * time.Second)
		} else if st.StrikeCount >= 5 {
			time.Sleep(1200 * time.Millisecond)
		}
		return false, nil
	}
}

func (m *DeviceAuth) handleThreatList(w http.ResponseWriter, r *http.Request) {
	rows, err := m.store.ThreatList(time.Now())
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	out := make([]ThreatState, 0, len(rows))
	for _, p := range rows {
		out = append(out, threatFromPersisted(p))
	}
	writeAdminJSON(w, out)
}

func (m *DeviceAuth) handleThreatAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IP       string `json:"ip"`
		Action   string `json:"action"`   // tarpit|honeypot|slop|blacklist|clear
		Duration string `json:"duration"` // optional, e.g. 1h
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	ip := strings.TrimSpace(req.IP)
	if ip == "" {
		http.Error(w, "ip is required", http.StatusBadRequest)
		return
	}
	ip = devicestore.NormalizeThreatIP(ip)
	if ip == "" {
		http.Error(w, "ip is required", http.StatusBadRequest)
		return
	}
	action := strings.TrimSpace(strings.ToLower(req.Action))
	if action == "" {
		http.Error(w, "action is required", http.StatusBadRequest)
		return
	}
	dur := time.Duration(0)
	if s := strings.TrimSpace(req.Duration); s != "" {
		if parsed, err := time.ParseDuration(s); err == nil && parsed > 0 {
			dur = parsed
		}
	}
	if err := m.store.ThreatAdminSet(ip, action, dur, time.Now()); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}
