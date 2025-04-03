package vpnless

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	tarpitStreamTotal     = 45 * time.Second
	tarpitWriteInterval   = 2 * time.Second
	honeypotStreamTotal   = 90 * time.Second
	honeypotWriteInterval = 3 * time.Second
)

// writeSlowUnauthorized streams a trickle response so the client holds a connection open
// without relying on a single long sleep that ignores client disconnect.
func writeSlowUnauthorized(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	rc := http.NewResponseController(w)
	deadline := time.Now().Add(tarpitStreamTotal)
	buf := []byte(".")
	for time.Now().Before(deadline) {
		select {
		case <-r.Context().Done():
			return
		default:
		}
		if _, err := w.Write(buf); err != nil {
			return
		}
		if err := rc.Flush(); err != nil {
			return
		}
		time.Sleep(tarpitWriteInterval)
	}
	msg := []byte("\nUnauthorized\n")
	if _, err := w.Write(msg); err != nil {
		return
	}
	_ = rc.Flush()
}

// writeHoneypotSlow streams plausible-looking junk as 200 OK to waste scraper/bot time.
func writeHoneypotSlow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	deadline := time.Now().Add(honeypotStreamTotal)
	n := 0
	for time.Now().Before(deadline) {
		select {
		case <-r.Context().Done():
			return
		default:
		}
		line := fmt.Sprintf("status=ok chunk=%d ts=%d\n", n, time.Now().Unix())
		if _, err := io.WriteString(w, line); err != nil {
			return
		}
		if err := rc.Flush(); err != nil {
			return
		}
		n++
		time.Sleep(honeypotWriteInterval)
	}
	if _, err := io.WriteString(w, "done=maybe\n"); err != nil {
		return
	}
	_ = rc.Flush()
}
