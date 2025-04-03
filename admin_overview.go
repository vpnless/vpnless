package vpnless

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

const overviewNewAppMaxAge = 24 * time.Hour

// containerCreatedAge interprets Docker's container Summary.Created value against now (Unix seconds).
// The Engine API documents Created as Unix seconds, but some compatible runtimes return
// milliseconds. Comparing ms to now in seconds makes (now-created) negative, so the 24h cutoff
// never fires and apps stay in "new" forever.
func containerCreatedAge(created, nowUnixSec int64) (age time.Duration, ok bool) {
	if created <= 0 {
		return 0, false
	}
	c := created
	if nowUnixSec > 1_000_000 && created > nowUnixSec*100 {
		c = created / 1000
	}
	sec := nowUnixSec - c
	if sec < 0 {
		return 0, false
	}
	return time.Duration(sec) * time.Second, true
}

// activityAdminJSON is one merged row (like `vpnless list all`).
type activityAdminJSON struct {
	EventTime time.Time `json:"event_time"`
	Status    string    `json:"status"` // pending | authorized | denied | threat
	DeviceID  string    `json:"device_id"`
	PublicKey string    `json:"public_key"`
	Remote    string    `json:"remote,omitempty"`
	Note      string    `json:"note,omitempty"`
}

// pairingDenialAdminJSON is one pairing_denials row for the admin API.
type pairingDenialAdminJSON struct {
	PublicKey     string    `json:"public_key"`
	CustomMessage string    `json:"custom_message,omitempty"`
	DeniedAt      time.Time `json:"denied_at"`
	StrikeCount   int       `json:"strike_count"`
	Active        bool      `json:"active"`
	SnarkIndex    *int      `json:"snark_index,omitempty"`
}

func (m *DeviceAuth) handleOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := m.store.Load(); err != nil {
		m.logger.Error("failed to reload device store", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	m.mu.RLock()
	pending := m.store.GetPending()
	m.mu.RUnlock()
	certRows, certWarn := m.collectAdminCertificates()
	var certProblems []adminCertHostJSON
	for _, row := range certRows {
		if row.Status != "ok" {
			certProblems = append(certProblems, row)
		}
	}

	groups, dockerWarn := m.collectDockerApps(r.Context())
	now := time.Now().Unix()
	var newApps []adminAppJSON
	for _, g := range groups {
		for _, a := range g.Apps {
			age, ok := containerCreatedAge(a.ContainerCreatedUnix, now)
			if !ok || age >= overviewNewAppMaxAge {
				continue
			}
			newApps = append(newApps, a)
		}
	}
	sort.SliceStable(newApps, func(i, j int) bool {
		return strings.ToLower(newApps[i].Name) < strings.ToLower(newApps[j].Name)
	})

	recentThreats := m.buildOverviewThreatRows(4)

	payload := map[string]any{
		"pending":           pending,
		"new_apps":          newApps,
		"certificates":      certProblems,
		"recent_threats":    recentThreats,
		"sorting_hint_apps": "Groups are sorted A–Z by homepage.group. Tiles use homepage.weight (Get Homepage default 0; lower = earlier, ties by name).",
	}
	var warns []string
	if certWarn != "" {
		warns = append(warns, certWarn)
	}
	if dockerWarn != "" {
		warns = append(warns, dockerWarn)
	}
	if len(warns) > 0 {
		payload["warning"] = strings.Join(warns, "; ")
	}
	writeAdminJSON(w, payload)
}

func (m *DeviceAuth) handleDeniedList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := m.store.Load(); err != nil {
		m.logger.Error("failed to reload device store", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	rows, err := m.store.ListPairingDenials()
	if err != nil {
		m.logger.Error("failed to list pairing denials", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	out := make([]pairingDenialAdminJSON, 0, len(rows))
	for _, d := range rows {
		out = append(out, pairingDenialAdminJSON{
			PublicKey:     d.PublicKey,
			CustomMessage: d.CustomMessage,
			DeniedAt:      d.DeniedAt,
			StrikeCount:   d.StrikeCount,
			Active:        d.Active,
			SnarkIndex:    d.SnarkIndex,
		})
	}
	writeAdminJSON(w, out)
}

func (m *DeviceAuth) handleDeniedRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PublicKey string `json:"public_key"`
		DeviceID  string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(req.PublicKey)
	if key == "" {
		key = strings.TrimSpace(req.DeviceID)
	}
	if key == "" {
		http.Error(w, "public_key or device_id is required", http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.store.RemovePairingDenial(key) {
		http.Error(w, "pairing denial not found", http.StatusNotFound)
		return
	}
	writeAdminJSON(w, map[string]any{"ok": true})
}

func (m *DeviceAuth) handleActivityList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := m.store.Load(); err != nil {
		m.logger.Error("failed to reload device store", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	rows := m.buildActivityRows()
	writeAdminJSON(w, rows)
}

func (m *DeviceAuth) buildActivityRows() []activityAdminJSON {
	pending := m.store.GetPending()
	authorized, err := m.store.GetAuthorized()
	if err != nil {
		m.logger.Error("failed to read authorized for activity", zap.Error(err))
		authorized = nil
	}
	denied, err := m.store.ListPairingDenials()
	if err != nil {
		m.logger.Error("failed to read denied for activity", zap.Error(err))
		denied = nil
	}
	threats, err := m.store.ThreatList(time.Now())
	if err != nil {
		m.logger.Error("failed to read threat rows for activity", zap.Error(err))
		threats = nil
	}

	var rows []activityAdminJSON
	for _, p := range pending {
		rows = append(rows, activityAdminJSON{
			EventTime: p.PendingAt,
			Status:    "pending",
			DeviceID:  p.DeviceID,
			PublicKey: p.PublicKey,
			Remote:    p.RemoteAddr,
			Note:      "awaiting admin approval",
		})
	}
	for _, a := range authorized {
		t := a.ApprovedAt
		if !a.LastSeen.IsZero() && a.LastSeen.After(t) {
			t = a.LastSeen
		}
		if !a.LastSeenSessionProof.IsZero() && a.LastSeenSessionProof.After(t) {
			t = a.LastSeenSessionProof
		}
		if !a.LastSeenCookie.IsZero() && a.LastSeenCookie.After(t) {
			t = a.LastSeenCookie
		}
		note := "approved"
		if !a.LastSeen.IsZero() {
			note = "last activity " + humanizeSinceAdmin(a.LastSeen)
		}
		rows = append(rows, activityAdminJSON{
			EventTime: t,
			Status:    "authorized",
			DeviceID:  a.DeviceID,
			PublicKey: a.PublicKey,
			Remote:    a.RemoteAddr,
			Note:      note,
		})
	}
	for _, d := range denied {
		note := fmt.Sprintf("strikes=%d", d.StrikeCount)
		if d.Active {
			note += ", active denial"
		} else {
			note += ", inactive"
		}
		rows = append(rows, activityAdminJSON{
			EventTime: d.DeniedAt,
			Status:    "denied",
			DeviceID:  "—",
			PublicKey: d.PublicKey,
			Remote:    "—",
			Note:      note,
		})
	}
	for _, th := range threats {
		t := th.LastSeen
		if t.IsZero() {
			t = th.SetAt
		}
		if t.IsZero() {
			t = time.Now()
		}
		note := fmt.Sprintf("mode=%s, hits=%d, strikes=%d", th.Mode, th.Hits, th.StrikeCount)
		if th.LastPath != "" {
			note += ", path=" + th.LastPath
		}
		if !th.ExpiresAt.IsZero() {
			note += ", expires " + th.ExpiresAt.Format(time.RFC3339)
		}
		rows = append(rows, activityAdminJSON{
			EventTime: t,
			Status:    "threat",
			DeviceID:  "naked@" + th.IP,
			PublicKey: "—",
			Remote:    th.IP,
			Note:      note,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].EventTime.After(rows[j].EventTime)
	})
	return rows
}

func shortPublicKey(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 28 {
		return s
	}
	return s[:28] + "…"
}

func humanizeSinceAdmin(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func (m *DeviceAuth) buildOverviewThreatRows(limit int) []ThreatState {
	if limit <= 0 {
		return nil
	}
	rows, err := m.store.ThreatList(time.Now())
	if err != nil {
		m.logger.Error("failed to read threat telemetry for overview", zap.Error(err))
		return nil
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	out := make([]ThreatState, 0, len(rows))
	for _, p := range rows {
		out = append(out, threatFromPersisted(p))
	}
	return out
}
