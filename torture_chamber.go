package vpnless

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	tortureMaxSessions     = 120
	tortureMaxLinesPerSess = 2000
	tortureMaxChunkRunes   = 8192
	tortureBodyPeek        = 4096
	tortureSubChanBuf      = 64
)

type transcriptLine struct {
	T    time.Time `json:"t"`
	Kind string    `json:"kind"` // in | out
	Text string    `json:"text"`
}

type tortureSession struct {
	id        string
	ip        string
	mode      string
	startedAt time.Time
	updatedAt time.Time
	active    bool
	lines     []transcriptLine
}

type tortureChamber struct {
	mu       sync.Mutex
	byID     map[string]*tortureSession
	order    []*tortureSession // newest first
	maxSess  int
	subs     map[string][]chan transcriptLine
	maxLines int
}

func newTortureChamber(maxSessions int) *tortureChamber {
	if maxSessions <= 0 {
		maxSessions = tortureMaxSessions
	}
	return &tortureChamber{
		byID:     make(map[string]*tortureSession),
		maxSess:  maxSessions,
		subs:     make(map[string][]chan transcriptLine),
		maxLines: tortureMaxLinesPerSess,
	}
}

func randomTortureSessionID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func clipTortureText(s string, maxRunes int) string {
	if maxRunes <= 0 || s == "" {
		return s
	}
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes]) + "… [truncated]"
}

// summarizeTortureRequest logs client input; restores r.Body after a limited read.
func summarizeTortureRequest(r *http.Request) []string {
	if r == nil {
		return nil
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("→ %s %s", r.Method, r.URL.RequestURI()))
	if ra := strings.TrimSpace(r.RemoteAddr); ra != "" {
		lines = append(lines, "→ RemoteAddr: "+ra)
	}
	if ua := strings.TrimSpace(r.Header.Get("User-Agent")); ua != "" {
		lines = append(lines, "→ User-Agent: "+clipTortureText(ua, 400))
	}
	if ref := strings.TrimSpace(r.Header.Get("Referer")); ref != "" {
		lines = append(lines, "→ Referer: "+clipTortureText(ref, 400))
	}
	if ct := strings.TrimSpace(r.Header.Get("Content-Type")); ct != "" {
		lines = append(lines, "→ Content-Type: "+clipTortureText(ct, 200))
	}
	if r.ContentLength > 0 {
		lines = append(lines, fmt.Sprintf("→ Content-Length: %d", r.ContentLength))
	}
	if r.Body != nil {
		peek, err := io.ReadAll(io.LimitReader(r.Body, int64(tortureBodyPeek)))
		r.Body = io.NopCloser(bytes.NewReader(peek))
		if err == nil && len(peek) > 0 {
			lines = append(lines, "→ body:\n"+clipTortureText(string(peek), tortureBodyPeek))
		}
	}
	return lines
}

func (c *tortureChamber) begin(ip, mode string, r *http.Request) *tortureSession {
	if c == nil {
		return nil
	}
	s := &tortureSession{
		id:        randomTortureSessionID(),
		ip:        ip,
		mode:      mode,
		startedAt: time.Now(),
		updatedAt: time.Now(),
		active:    true,
	}
	c.mu.Lock()
	for _, line := range summarizeTortureRequest(r) {
		s.lines = append(s.lines, transcriptLine{T: time.Now(), Kind: "in", Text: line})
	}
	c.byID[s.id] = s
	c.order = append([]*tortureSession{s}, c.order...)
	c.pruneLocked()
	c.mu.Unlock()
	return s
}

func (c *tortureChamber) end(s *tortureSession) {
	if c == nil || s == nil {
		return
	}
	c.mu.Lock()
	s.active = false
	s.updatedAt = time.Now()
	done := transcriptLine{T: time.Now(), Kind: "out", Text: "← [session end]"}
	s.lines = append(s.lines, done)
	if len(s.lines) > c.maxLines {
		s.lines = s.lines[len(s.lines)-c.maxLines:]
	}
	chans := c.detachSubsLocked(s.id)
	c.mu.Unlock()
	for _, ch := range chans {
		select {
		case ch <- done:
		default:
		}
		close(ch)
	}
}

func (c *tortureChamber) pruneLocked() {
	for len(c.order) > c.maxSess {
		old := c.order[len(c.order)-1]
		c.order = c.order[:len(c.order)-1]
		delete(c.byID, old.id)
		for _, ch := range c.subs[old.id] {
			close(ch)
		}
		delete(c.subs, old.id)
	}
}

func (c *tortureChamber) appendOut(s *tortureSession, raw string) {
	if c == nil || s == nil || raw == "" {
		return
	}
	text := strings.ReplaceAll(raw, "\r", "")
	text = clipTortureText(text, tortureMaxChunkRunes)
	if strings.TrimSpace(text) == "" {
		return
	}
	line := transcriptLine{T: time.Now(), Kind: "out", Text: "← " + text}

	c.mu.Lock()
	if !s.active {
		c.mu.Unlock()
		return
	}
	s.lines = append(s.lines, line)
	s.updatedAt = time.Now()
	if len(s.lines) > c.maxLines {
		s.lines = s.lines[len(s.lines)-c.maxLines:]
	}
	chans := append([]chan transcriptLine(nil), c.subs[s.id]...)
	c.mu.Unlock()

	for _, ch := range chans {
		select {
		case ch <- line:
		default:
		}
	}
}

func (c *tortureChamber) detachSubsLocked(id string) []chan transcriptLine {
	out := c.subs[id]
	delete(c.subs, id)
	return out
}

func (c *tortureChamber) unsubscribe(s *tortureSession, ch chan transcriptLine) {
	if c == nil || s == nil || ch == nil {
		return
	}
	c.mu.Lock()
	list := c.subs[s.id]
	if len(list) == 0 {
		c.mu.Unlock()
		return
	}
	for i, v := range list {
		if v == ch {
			c.subs[s.id] = append(list[:i], list[i+1:]...)
			break
		}
	}
	c.mu.Unlock()
}

// openStream returns a snapshot, a subscriber channel, and whether the session is still active.
// Caller must call unsubscribe(sess, ch) when done.
func (c *tortureChamber) openStream(id string) (sess *tortureSession, snapshot []transcriptLine, ch chan transcriptLine, active bool, found bool) {
	if c == nil {
		return nil, nil, nil, false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	sess = c.byID[strings.TrimSpace(id)]
	if sess == nil {
		return nil, nil, nil, false, false
	}
	snapshot = append([]transcriptLine(nil), sess.lines...)
	active = sess.active
	if active {
		ch = make(chan transcriptLine, tortureSubChanBuf)
		c.subs[sess.id] = append(c.subs[sess.id], ch)
	}
	return sess, snapshot, ch, active, true
}

// tortureListRowJSON is one row per IP (latest session only), newest torture first.
type tortureListRowJSON struct {
	SessionID    string    `json:"session_id"`
	IP           string    `json:"ip"`
	Mode         string    `json:"mode"`
	StartedAt    time.Time `json:"started_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Active       bool      `json:"active"`
	PreviewOut   []string  `json:"preview_out_lines"`
	OutLineCount int       `json:"out_line_count"`
	InLineCount  int       `json:"in_line_count"`
}

func (c *tortureChamber) listByIPLatest() []tortureListRowJSON {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	latest := make(map[string]*tortureSession)
	for _, s := range c.order {
		if _, ok := latest[s.ip]; !ok {
			latest[s.ip] = s
		}
	}
	rows := make([]*tortureSession, 0, len(latest))
	for _, s := range latest {
		rows = append(rows, s)
	}
	// Most recently tortured first
	for i := 0; i < len(rows); i++ {
		for j := i + 1; j < len(rows); j++ {
			if rows[j].updatedAt.After(rows[i].updatedAt) {
				rows[i], rows[j] = rows[j], rows[i]
			}
		}
	}

	out := make([]tortureListRowJSON, 0, len(rows))
	for _, s := range rows {
		var outs []string
		inN, outN := 0, 0
		for _, ln := range s.lines {
			switch ln.Kind {
			case "in":
				inN++
			case "out":
				outN++
				t := strings.TrimPrefix(ln.Text, "← ")
				t = strings.TrimSpace(t)
				if t != "" && t != "[session end]" {
					outs = append(outs, clipTortureText(t, 160))
				}
			}
		}
		preview := outs
		if len(preview) > 4 {
			preview = preview[len(preview)-4:]
		}
		out = append(out, tortureListRowJSON{
			SessionID:    s.id,
			IP:           s.ip,
			Mode:         s.mode,
			StartedAt:    s.startedAt,
			UpdatedAt:    s.updatedAt,
			Active:       s.active,
			PreviewOut:   preview,
			OutLineCount: outN,
			InLineCount:  inN,
		})
	}
	return out
}

// tortureCaptureWriter records response bytes as torture output.
type tortureCaptureWriter struct {
	http.ResponseWriter
	c *tortureChamber
	s *tortureSession
}

func (tw *tortureCaptureWriter) Unwrap() http.ResponseWriter {
	return tw.ResponseWriter
}

func (tw *tortureCaptureWriter) Write(p []byte) (int, error) {
	n, err := tw.ResponseWriter.Write(p)
	if n > 0 && tw.c != nil && tw.s != nil {
		tw.c.appendOut(tw.s, string(p[:n]))
	}
	return n, err
}

func tortureWrapResponseWriter(w http.ResponseWriter, c *tortureChamber, s *tortureSession) http.ResponseWriter {
	if c == nil || s == nil {
		return w
	}
	return &tortureCaptureWriter{ResponseWriter: w, c: c, s: s}
}

func (m *DeviceAuth) handleTortureList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var rows []tortureListRowJSON
	if m.torture != nil {
		rows = m.torture.listByIPLatest()
	}
	writeAdminJSON(w, map[string]any{"sessions": rows})
}

func (m *DeviceAuth) handleTortureStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("session_id"))
	if id == "" {
		http.Error(w, "session_id required", http.StatusBadRequest)
		return
	}
	if m.torture == nil {
		http.Error(w, "torture recorder unavailable", http.StatusServiceUnavailable)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	sess, snapshot, ch, active, found := m.torture.openStream(id)
	if !found {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if ch != nil {
		defer m.torture.unsubscribe(sess, ch)
	}

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	b, _ := json.Marshal(snapshot)
	fmt.Fprintf(w, "event: snapshot\ndata: %s\n\n", b)
	fl.Flush()

	if !active || ch == nil {
		fmt.Fprintf(w, "event: done\ndata: {}\n\n")
		fl.Flush()
		return
	}

	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()

	for {
		select {
		case line, ok := <-ch:
			if !ok {
				fmt.Fprintf(w, "event: done\ndata: {}\n\n")
				fl.Flush()
				return
			}
			lb, err := json.Marshal(line)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: line\ndata: %s\n\n", lb)
			fl.Flush()
		case <-tick.C:
			fmt.Fprintf(w, ": ping\n\n")
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
