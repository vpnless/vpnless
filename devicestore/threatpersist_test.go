package devicestore

import (
	"path/filepath"
	"testing"
	"time"
)

func TestThreatPersistMultiStep(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.db")
	ds, err := NewDeviceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ds.Close()

	ds.ThreatTouchUnauthorized("203.0.113.50", "/nope")
	st := ds.ThreatResolve("203.0.113.50", time.Now())
	if st.Hits != 1 || st.StrikeCount != 1 || st.Mode != "default" {
		t.Fatalf("after touch: %+v", st)
	}

	if err := ds.ThreatAdminSet("203.0.113.50", "tarpit", time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	st = ds.ThreatResolve("203.0.113.50", time.Now())
	if st.Mode != "tarpit" {
		t.Fatalf("want tarpit, got %+v", st)
	}

	list, err := ds.ThreatList(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list len %d", len(list))
	}

	if err := ds.ThreatAdminSet("203.0.113.50", "clear", 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	list, err = ds.ThreatList(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("after clear, want no threat rows, got %+v", list)
	}
}
