package devicestore

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"strings"
	"time"
)

// ThreatPersisted is SQLite-backed threat target state (shared across Caddy workers).
type ThreatPersisted struct {
	IP          string
	Mode        string
	SetAt       time.Time
	ExpiresAt   time.Time
	Hits        int
	LastPath    string
	LastSeen    time.Time
	StrikeCount int
}

// NormalizeThreatIP trims host/port and canonicalizes IPs so admin "Send to tarpit" matches clientIP() lookups.
func NormalizeThreatIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(s)
	if err == nil && host != "" {
		s = host
	}
	if ip := net.ParseIP(strings.Trim(s, "[]")); ip != nil {
		return ip.String()
	}
	return s
}

func migrateThreatTargets(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS threat_targets (
	ip TEXT NOT NULL PRIMARY KEY,
	mode TEXT NOT NULL DEFAULT 'default',
	set_at INTEGER,
	expires_at INTEGER,
	hits INTEGER NOT NULL DEFAULT 0,
	strike_count INTEGER NOT NULL DEFAULT 0,
	last_path TEXT,
	last_seen INTEGER
)`)
	return err
}

// ThreatTouchUnauthorized increments hit counters after a failed vpnless auth check.
func (ds *DeviceStore) ThreatTouchUnauthorized(ip, path string) {
	ip = NormalizeThreatIP(ip)
	if ip == "" {
		return
	}
	ctx := context.Background()
	now := time.Now().Unix()
	pathArg := any(path)
	if strings.TrimSpace(path) == "" {
		pathArg = nil
	}
	_, _ = ds.conn().ExecContext(ctx, `
INSERT INTO threat_targets (ip, mode, hits, strike_count, last_path, last_seen)
VALUES (?, 'default', 1, 1, ?, ?)
ON CONFLICT(ip) DO UPDATE SET
	hits = threat_targets.hits + 1,
	strike_count = threat_targets.strike_count + 1,
	last_path = COALESCE(excluded.last_path, threat_targets.last_path),
	last_seen = excluded.last_seen`,
		ip, pathArg, now)
}

// ThreatResolve returns current mode after clearing expired admin actions and applying auto-blacklist rules.
func (ds *DeviceStore) ThreatResolve(ip string, now time.Time) ThreatPersisted {
	ip = NormalizeThreatIP(ip)
	out := ThreatPersisted{IP: ip, Mode: "default"}
	if ip == "" {
		return out
	}
	ctx := context.Background()
	c := ds.conn()
	nowUnix := now.Unix()

	_, _ = c.ExecContext(ctx, `
UPDATE threat_targets SET mode = 'default', expires_at = NULL
WHERE ip = ? AND expires_at IS NOT NULL AND expires_at < ?`,
		ip, nowUnix)

	_, _ = c.ExecContext(ctx, `
UPDATE threat_targets SET mode = 'blacklist', set_at = ?, expires_at = ?
WHERE ip = ? AND mode = 'default' AND strike_count >= 20 AND (expires_at IS NULL OR expires_at < ?)`,
		nowUnix, now.Add(30*time.Minute).Unix(), ip, nowUnix)

	var mode string
	var setAt, expAt, lastSeen sql.NullInt64
	var hits, strikes int
	var lastPath sql.NullString
	err := c.QueryRowContext(ctx, `
SELECT mode, set_at, expires_at, hits, strike_count, last_path, last_seen
FROM threat_targets WHERE ip = ?`, ip).Scan(&mode, &setAt, &expAt, &hits, &strikes, &lastPath, &lastSeen)
	if err != nil {
		return out
	}
	out.Mode = mode
	out.Hits = hits
	out.StrikeCount = strikes
	if lastPath.Valid {
		out.LastPath = lastPath.String
	}
	if setAt.Valid && setAt.Int64 > 0 {
		out.SetAt = time.Unix(setAt.Int64, 0)
	}
	if expAt.Valid && expAt.Int64 > 0 {
		out.ExpiresAt = time.Unix(expAt.Int64, 0)
	}
	if lastSeen.Valid && lastSeen.Int64 > 0 {
		out.LastSeen = time.Unix(lastSeen.Int64, 0)
	}
	return out
}

// ThreatAdminSet applies an admin threat action (tarpit, honeypot, blacklist, clear).
func (ds *DeviceStore) ThreatAdminSet(ip, action string, duration time.Duration, now time.Time) error {
	ip = NormalizeThreatIP(ip)
	if ip == "" {
		return sql.ErrNoRows
	}
	ctx := context.Background()
	c := ds.conn()
	nowUnix := now.Unix()
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "tarpit":
		if duration <= 0 {
			duration = 6 * time.Hour
		}
		exp := now.Add(duration).Unix()
		_, err := c.ExecContext(ctx, `
INSERT INTO threat_targets (ip, mode, set_at, expires_at, hits, strike_count, last_path, last_seen)
VALUES (?, 'tarpit', ?, ?, 0, 0, NULL, NULL)
ON CONFLICT(ip) DO UPDATE SET
	mode = 'tarpit', set_at = excluded.set_at, expires_at = excluded.expires_at`,
			ip, nowUnix, exp)
		return err
	case "honeypot":
		if duration <= 0 {
			duration = 6 * time.Hour
		}
		exp := now.Add(duration).Unix()
		_, err := c.ExecContext(ctx, `
INSERT INTO threat_targets (ip, mode, set_at, expires_at, hits, strike_count, last_path, last_seen)
VALUES (?, 'honeypot', ?, ?, 0, 0, NULL, NULL)
ON CONFLICT(ip) DO UPDATE SET
	mode = 'honeypot', set_at = excluded.set_at, expires_at = excluded.expires_at`,
			ip, nowUnix, exp)
		return err
	case "slop":
		if duration <= 0 {
			duration = 6 * time.Hour
		}
		exp := now.Add(duration).Unix()
		_, err := c.ExecContext(ctx, `
INSERT INTO threat_targets (ip, mode, set_at, expires_at, hits, strike_count, last_path, last_seen)
VALUES (?, 'slop', ?, ?, 0, 0, NULL, NULL)
ON CONFLICT(ip) DO UPDATE SET
	mode = 'slop', set_at = excluded.set_at, expires_at = excluded.expires_at`,
			ip, nowUnix, exp)
		return err
	case "blacklist":
		if duration <= 0 {
			duration = 24 * time.Hour
		}
		exp := now.Add(duration).Unix()
		_, err := c.ExecContext(ctx, `
INSERT INTO threat_targets (ip, mode, set_at, expires_at, hits, strike_count, last_path, last_seen)
VALUES (?, 'blacklist', ?, ?, 0, 0, NULL, NULL)
ON CONFLICT(ip) DO UPDATE SET
	mode = 'blacklist', set_at = excluded.set_at, expires_at = excluded.expires_at`,
			ip, nowUnix, exp)
		return err
	case "clear":
		// Full reset so the row drops out of ThreatList (hits > 0 OR mode != 'default') unless
		// new traffic appears; fixes "cleared blacklist but IP still stuck in monitor" confusion.
		_, err := c.ExecContext(ctx, `
UPDATE threat_targets SET mode = 'default', expires_at = NULL, strike_count = 0, set_at = NULL,
	hits = 0, last_path = NULL, last_seen = NULL WHERE ip = ?`, ip)
		return err
	default:
		return errors.New("unknown threat action")
	}
}

// ThreatList returns all threat rows with any activity or non-default mode (for admin / CLI).
func (ds *DeviceStore) ThreatList(now time.Time) ([]ThreatPersisted, error) {
	ctx := context.Background()
	c := ds.conn()
	nowUnix := now.Unix()
	_, _ = c.ExecContext(ctx, `UPDATE threat_targets SET mode = 'default', expires_at = NULL WHERE expires_at IS NOT NULL AND expires_at < ?`, nowUnix)

	rows, err := c.QueryContext(ctx, `
SELECT ip, mode, set_at, expires_at, hits, strike_count, last_path, last_seen
FROM threat_targets
WHERE hits > 0 OR mode != 'default'
ORDER BY COALESCE(last_seen, set_at, 0) DESC, ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ThreatPersisted
	for rows.Next() {
		var p ThreatPersisted
		var setAt, expAt, lastSeen sql.NullInt64
		var lastPath sql.NullString
		if err := rows.Scan(&p.IP, &p.Mode, &setAt, &expAt, &p.Hits, &p.StrikeCount, &lastPath, &lastSeen); err != nil {
			return nil, err
		}
		if lastPath.Valid {
			p.LastPath = lastPath.String
		}
		if setAt.Valid && setAt.Int64 > 0 {
			p.SetAt = time.Unix(setAt.Int64, 0)
		}
		if expAt.Valid && expAt.Int64 > 0 {
			p.ExpiresAt = time.Unix(expAt.Int64, 0)
		}
		if lastSeen.Valid && lastSeen.Int64 > 0 {
			p.LastSeen = time.Unix(lastSeen.Int64, 0)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
