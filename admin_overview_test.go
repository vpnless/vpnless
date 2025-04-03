package vpnless

import (
	"testing"
	"time"
)

func TestContainerCreatedAgeSecondsVsMilliseconds(t *testing.T) {
	now := int64(1_800_000_000) // arbitrary "now" in seconds
	twentyFiveHours := int64((25 * time.Hour).Seconds())

	t.Run("unix seconds fresh", func(t *testing.T) {
		created := now - int64((1 * time.Hour).Seconds())
		age, ok := containerCreatedAge(created, now)
		if !ok || age < time.Hour || age >= overviewNewAppMaxAge {
			t.Fatalf("expected ~1h age and new-app eligible, got ok=%v age=%v", ok, age)
		}
	})
	t.Run("unix seconds older than 24h", func(t *testing.T) {
		created := now - twentyFiveHours
		age, ok := containerCreatedAge(created, now)
		if !ok || age < overviewNewAppMaxAge {
			t.Fatalf("expected ok and age >= 24h, got ok=%v age=%v", ok, age)
		}
	})
	t.Run("milliseconds same instant", func(t *testing.T) {
		createdMs := now * 1000
		age, ok := containerCreatedAge(createdMs, now)
		if !ok || age != 0 {
			t.Fatalf("expected ok and age 0, got ok=%v age=%v", ok, age)
		}
	})
	t.Run("milliseconds older than 24h", func(t *testing.T) {
		createdMs := (now - twentyFiveHours) * 1000
		age, ok := containerCreatedAge(createdMs, now)
		if !ok || age < overviewNewAppMaxAge {
			t.Fatalf("expected ok and age >= 24h, got ok=%v age=%v", ok, age)
		}
	})
	t.Run("zero or negative age after normalize", func(t *testing.T) {
		if _, ok := containerCreatedAge(0, now); ok {
			t.Fatal("expected !ok for created=0")
		}
		// Far future as "seconds" — no ms heuristic, should reject
		if _, ok := containerCreatedAge(now+3600, now); ok {
			t.Fatal("expected !ok for created in the future")
		}
	})
}

func TestBuildActivityRowsIncludesThreatTelemetry(t *testing.T) {
	ds := testStore(t)
	m := testDeviceAuthWithStore(ds)

	ds.AddPending("pk-p", "dev-p", "198.51.100.10", nil)
	ds.AddPending("pk-a", "dev-a", "198.51.100.11", nil)
	if !ds.ApproveDevice("pk-a", "dev-a") {
		t.Fatal("failed to approve seeded pending device")
	}
	ds.AddPending("pk-d", "dev-d", "198.51.100.12", nil)
	if err := ds.DenyPendingDevice("pk-d", "", nil); err != nil {
		t.Fatalf("failed to deny seeded pending device: %v", err)
	}
	ds.ThreatTouchUnauthorized("203.0.113.7", "/vpnless/admin")

	rows := m.buildActivityRows()
	if len(rows) < 4 {
		t.Fatalf("expected at least 4 rows (pending/authorized/denied/threat), got %d", len(rows))
	}

	var hasPending, hasAuthorized, hasDenied, hasThreat bool
	for _, r := range rows {
		switch r.Status {
		case "pending":
			hasPending = true
		case "authorized":
			hasAuthorized = true
		case "denied":
			hasDenied = true
		case "threat":
			if r.Remote != "203.0.113.7" {
				t.Fatalf("unexpected threat remote: %q", r.Remote)
			}
			hasThreat = true
		}
	}
	if !hasPending || !hasAuthorized || !hasDenied || !hasThreat {
		t.Fatalf("status coverage missing: pending=%v authorized=%v denied=%v threat=%v", hasPending, hasAuthorized, hasDenied, hasThreat)
	}
}
