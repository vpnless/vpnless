// Package devicestore: SQLite for pending/authorized devices, threats, pairing denials, and the vpnless CLI.
package devicestore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ErrPendingDeviceNotFound is returned by HTTP/transactional approve when the device is not pending.
var ErrPendingDeviceNotFound = errors.New("device not found in pending list")

// ErrPairingPermanentlyBlocked is returned when a public key has been denied too many times to register again.
var ErrPairingPermanentlyBlocked = errors.New("pairing permanently blocked for this device")

// MaxPairingDenyStrikes is how many times an admin may deny the same public key before pairing registration is rejected.
// Flow: 1st deny → user may request access once more; 2nd deny → no further pairing for this key.
const MaxPairingDenyStrikes = 2

// MaxPairingSnarkIndex is the largest allowed admin-selected deny snark line index (client lists must stay in sync).
const MaxPairingSnarkIndex = 127

// SessionSecretRandomBytes is how many cryptographically random bytes each device session secret
// is drawn from (before base64 encoding for JSON). 64 bytes = 512 bits of entropy.
const SessionSecretRandomBytes = 64

// AuthorizedAuthTouch records how a request authenticated (cookie vs proof vs signature).
type AuthorizedAuthTouch int

const (
	// AuthTouchCookie is the HTTP-only device token (replayable until revoked).
	AuthTouchCookie AuthorizedAuthTouch = iota
	// AuthTouchSessionProof is HMAC(session_secret, "v1|"+timestamp) — preferred for clients that can attach headers.
	AuthTouchSessionProof
	// AuthTouchSignature is per-request Ed25519 (native/API clients).
	AuthTouchSignature
)

// DeviceInfo: one approved device row (session secret + telemetry may be filled in).
type DeviceInfo struct {
	PublicKey     string    `json:"public_key"`
	DeviceID      string    `json:"device_id"`
	ApprovedAt    time.Time `json:"approved_at"`
	RemoteAddr    string    `json:"remote_addr,omitempty"`
	PendingAt     time.Time `json:"pending_at,omitempty"`
	SessionSecret string    `json:"session_secret,omitempty"`
	LastSeen      time.Time `json:"last_seen,omitempty"`
	// LastSeenSessionProof is the last time this device authenticated with session HMAC or Ed25519 (telemetry).
	LastSeenSessionProof time.Time `json:"last_seen_session_proof,omitempty"`
	// LastSeenCookie is the last time this device authenticated with only the device cookie (weaker).
	LastSeenCookie time.Time          `json:"last_seen_cookie,omitempty"`
	ClientInfo     *PendingClientInfo `json:"client_info,omitempty"`
}

// PendingDevice: waiting in the approval queue.
type PendingDevice struct {
	PublicKey  string             `json:"public_key"`
	DeviceID   string             `json:"device_id"`
	RemoteAddr string             `json:"remote_addr"`
	PendingAt  time.Time          `json:"pending_at"`
	ClientInfo *PendingClientInfo `json:"client_info,omitempty"`
}

// PendingClientInfo: browser metadata we got at pairing time (best-effort).
type PendingClientInfo struct {
	UserAgent           string `json:"user_agent,omitempty"`
	Browser             string `json:"browser,omitempty"`
	BrowserVersion      string `json:"browser_version,omitempty"`
	OS                  string `json:"os,omitempty"`
	OSVersion           string `json:"os_version,omitempty"`
	Screen              string `json:"screen,omitempty"`
	Timezone            string `json:"timezone,omitempty"`
	Languages           string `json:"languages,omitempty"`
	HardwareConcurrency string `json:"hardware_concurrency,omitempty"`
	XForwardedFor       string `json:"x_forwarded_for,omitempty"`
	XRealIP             string `json:"x_real_ip,omitempty"`
	Forwarded           string `json:"forwarded,omitempty"`
	PeerRemoteAddr      string `json:"peer_remote_addr,omitempty"`
	DisplayName         string `json:"display_name,omitempty"`
}

type AdminAuthSettings struct {
	OTPSecret  string `json:"otp_secret,omitempty"`
	OTPEnabled bool   `json:"otp_enabled"`
}

// PairingDenialRecord is one persisted pairing denial row (admin denied this device key).
type PairingDenialRecord struct {
	PublicKey     string
	CustomMessage string
	DeniedAt      time.Time
	StrikeCount   int
	Active        bool
	SnarkIndex    *int
}

type sqlConn interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// DeviceStore persists devices in SQLite with WAL and busy_timeout for safe multi-process access.
type DeviceStore struct {
	db   *sql.DB
	tx   *sql.Tx // non-nil only inside ApplyTransactional mutator
	path string
}

func sqliteDSN(path string) string {
	clean := filepath.Clean(path)
	const pragma = "_pragma=busy_timeout(30000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)"
	if filepath.IsAbs(clean) {
		return "file:" + filepath.ToSlash(clean) + "?" + pragma
	}
	return clean + "?" + pragma
}

func migrate(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS authorized_devices (
	public_key TEXT NOT NULL PRIMARY KEY,
	device_id TEXT NOT NULL,
	approved_at INTEGER NOT NULL,
	remote_addr TEXT,
	session_secret TEXT,
	client_info_json TEXT
);
CREATE TABLE IF NOT EXISTS pending_devices (
	public_key TEXT NOT NULL PRIMARY KEY,
	device_id TEXT NOT NULL,
	remote_addr TEXT NOT NULL,
	pending_at INTEGER NOT NULL,
	client_info_json TEXT
);
CREATE TABLE IF NOT EXISTS authorized_tokens (
	token TEXT NOT NULL PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS admin_auth_settings (
	id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
	otp_secret TEXT NOT NULL DEFAULT '',
	otp_enabled INTEGER NOT NULL DEFAULT 0
);
`)
	if err != nil {
		return err
	}
	// Keep existing databases forward-compatible with new metadata.
	_, err = db.ExecContext(ctx, `ALTER TABLE pending_devices ADD COLUMN client_info_json TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return err
	}
	_, err = db.ExecContext(ctx, `ALTER TABLE authorized_devices ADD COLUMN last_seen INTEGER`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return err
	}
	if err := migrateAuthorizedDevicesClientInfo(ctx, db); err != nil {
		return err
	}
	if err := migrateAuthorizedDevicesAuthTelemetry(ctx, db); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO admin_auth_settings (id, otp_secret, otp_enabled)
VALUES (1, '', 0)
ON CONFLICT(id) DO NOTHING`)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS pairing_denials (
	public_key TEXT NOT NULL PRIMARY KEY,
	custom_message TEXT,
	denied_at INTEGER NOT NULL,
	strike_count INTEGER NOT NULL DEFAULT 1,
	active INTEGER NOT NULL DEFAULT 1,
	snark_index INTEGER
)`)
	if err != nil {
		return err
	}
	if err := migratePairingDenialsColumns(ctx, db); err != nil {
		return err
	}
	if err := migrateThreatTargets(ctx, db); err != nil {
		return err
	}
	return nil
}

func migrateAuthorizedDevicesClientInfo(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(authorized_devices)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	has := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == "client_info_json" {
			has = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !has {
		if _, err := db.ExecContext(ctx, `ALTER TABLE authorized_devices ADD COLUMN client_info_json TEXT`); err != nil {
			return fmt.Errorf("add authorized_devices.client_info_json: %w", err)
		}
	}
	return nil
}

func migrateAuthorizedDevicesAuthTelemetry(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(authorized_devices)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	hasProof, hasCookie := false, false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		switch name {
		case "last_seen_session_proof":
			hasProof = true
		case "last_seen_cookie":
			hasCookie = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasProof {
		if _, err := db.ExecContext(ctx, `ALTER TABLE authorized_devices ADD COLUMN last_seen_session_proof INTEGER`); err != nil {
			return fmt.Errorf("add authorized_devices.last_seen_session_proof: %w", err)
		}
	}
	if !hasCookie {
		if _, err := db.ExecContext(ctx, `ALTER TABLE authorized_devices ADD COLUMN last_seen_cookie INTEGER`); err != nil {
			return fmt.Errorf("add authorized_devices.last_seen_cookie: %w", err)
		}
	}
	return nil
}

func migratePairingDenialsColumns(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(pairing_denials)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	hasStrike, hasActive, hasSnark := false, false, false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		switch name {
		case "strike_count":
			hasStrike = true
		case "active":
			hasActive = true
		case "snark_index":
			hasSnark = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasStrike {
		if _, err := db.ExecContext(ctx, `ALTER TABLE pairing_denials ADD COLUMN strike_count INTEGER NOT NULL DEFAULT 1`); err != nil {
			return fmt.Errorf("add pairing_denials.strike_count: %w", err)
		}
	}
	if !hasActive {
		if _, err := db.ExecContext(ctx, `ALTER TABLE pairing_denials ADD COLUMN active INTEGER NOT NULL DEFAULT 1`); err != nil {
			return fmt.Errorf("add pairing_denials.active: %w", err)
		}
	}
	if !hasSnark {
		if _, err := db.ExecContext(ctx, `ALTER TABLE pairing_denials ADD COLUMN snark_index INTEGER`); err != nil {
			return fmt.Errorf("add pairing_denials.snark_index: %w", err)
		}
	}
	return nil
}

// NewDeviceStore opens the SQLite database at path (created if missing).
func NewDeviceStore(path string) (*DeviceStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("device store path is required")
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("create device store directory: %w", err)
		}
	}
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(25)

	ctx := context.Background()
	if err := migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate device store: %w", err)
	}

	return &DeviceStore{db: db, path: path}, nil
}

func (ds *DeviceStore) conn() sqlConn {
	if ds.tx != nil {
		return ds.tx
	}
	return ds.db
}

// Close releases database connections.
func (ds *DeviceStore) Close() error {
	if ds.db == nil {
		return nil
	}
	return ds.db.Close()
}

// RawExec runs SQL against the store connection (same semantics as sql.DB.ExecContext). Used by tests and one-off tooling; prefer the typed store API for product code.
func (ds *DeviceStore) RawExec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return ds.conn().ExecContext(ctx, query, args...)
}

// Load is a no-op for SQLite (reads always query the DB). Kept for API compatibility.
func (ds *DeviceStore) Load() error {
	return nil
}

// Save is a no-op for SQLite. Kept for API compatibility.
func (ds *DeviceStore) Save() error {
	return nil
}

// ApplyTransactional runs mutator inside a single SQLite transaction so concurrent writers
// (other goroutines or processes) wait via busy_timeout instead of corrupting state.
func (ds *DeviceStore) ApplyTransactional(mutator func(*DeviceStore) error) error {
	ctx := context.Background()
	tx, err := ds.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	work := &DeviceStore{db: ds.db, tx: tx, path: ds.path}
	if err := mutator(work); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// IsAuthorized: pubkey in authorized_devices?
func (ds *DeviceStore) IsAuthorized(pubKey string) bool {
	ctx := context.Background()
	var n int
	err := ds.conn().QueryRowContext(ctx, `SELECT 1 FROM authorized_devices WHERE public_key = ? LIMIT 1`, pubKey).Scan(&n)
	return err == nil
}

// IsPending: still in pending_devices?
func (ds *DeviceStore) IsPending(pubKey string) bool {
	ctx := context.Background()
	var n int
	err := ds.conn().QueryRowContext(ctx, `SELECT 1 FROM pending_devices WHERE public_key = ? LIMIT 1`, pubKey).Scan(&n)
	return err == nil
}

// AddPending inserts or updates a pending device. On conflict, refreshes client metadata and remote_addr
// but keeps the original pending_at so queue ordering is stable.
func (ds *DeviceStore) AddPending(pubKey, deviceID, remoteAddr string, clientInfo *PendingClientInfo) {
	ctx := context.Background()
	var clientInfoJSON any
	if clientInfo != nil {
		if b, err := json.Marshal(clientInfo); err == nil {
			clientInfoJSON = string(b)
		}
	}
	_, _ = ds.conn().ExecContext(ctx, `
INSERT INTO pending_devices (public_key, device_id, remote_addr, pending_at, client_info_json)
VALUES (?,?,?,?,?)
ON CONFLICT(public_key) DO UPDATE SET
	device_id = excluded.device_id,
	remote_addr = excluded.remote_addr,
	client_info_json = excluded.client_info_json`,
		pubKey, deviceID, remoteAddr, time.Now().Unix(), clientInfoJSON)
}

// PendingClientInfoForPublicKey returns parsed client info for a pending row, or nil.
func (ds *DeviceStore) PendingClientInfoForPublicKey(pubKey string) *PendingClientInfo {
	ctx := context.Background()
	var raw sql.NullString
	err := ds.conn().QueryRowContext(ctx,
		`SELECT client_info_json FROM pending_devices WHERE public_key = ? LIMIT 1`, pubKey).Scan(&raw)
	if err != nil || !raw.Valid || strings.TrimSpace(raw.String) == "" {
		return nil
	}
	var ci PendingClientInfo
	if err := json.Unmarshal([]byte(raw.String), &ci); err != nil {
		return nil
	}
	return &ci
}

// UpdatePendingDisplayName sets display_name in client_info_json for a pending device (by public key or device id).
func (ds *DeviceStore) UpdatePendingDisplayName(pubKeyOrDeviceID, displayName string) bool {
	ctx := context.Background()
	c := ds.conn()
	var pk string
	var raw sql.NullString
	err := c.QueryRowContext(ctx,
		`SELECT public_key, client_info_json FROM pending_devices WHERE public_key = ? OR device_id = ? LIMIT 1`,
		pubKeyOrDeviceID, pubKeyOrDeviceID).Scan(&pk, &raw)
	if err != nil {
		return false
	}
	var ci PendingClientInfo
	if raw.Valid && strings.TrimSpace(raw.String) != "" {
		_ = json.Unmarshal([]byte(raw.String), &ci)
	}
	ci.DisplayName = displayName
	b, err := json.Marshal(&ci)
	if err != nil {
		return false
	}
	res, err := c.ExecContext(ctx, `UPDATE pending_devices SET client_info_json = ? WHERE public_key = ?`, string(b), pk)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// UpdateAuthorizedDisplayName sets display_name in client_info_json for an authorized device (by public key or device id).
func (ds *DeviceStore) UpdateAuthorizedDisplayName(pubKeyOrDeviceID, displayName string) bool {
	ctx := context.Background()
	c := ds.conn()
	var pk string
	var raw sql.NullString
	err := c.QueryRowContext(ctx,
		`SELECT public_key, client_info_json FROM authorized_devices WHERE public_key = ? OR device_id = ? LIMIT 1`,
		pubKeyOrDeviceID, pubKeyOrDeviceID).Scan(&pk, &raw)
	if err != nil {
		return false
	}
	var ci PendingClientInfo
	if raw.Valid && strings.TrimSpace(raw.String) != "" {
		_ = json.Unmarshal([]byte(raw.String), &ci)
	}
	ci.DisplayName = displayName
	b, err := json.Marshal(&ci)
	if err != nil {
		return false
	}
	res, err := c.ExecContext(ctx, `UPDATE authorized_devices SET client_info_json = ? WHERE public_key = ?`, string(b), pk)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// RemovePending deletes a pending row by public key or device id. Returns true if a row was removed.
func (ds *DeviceStore) RemovePending(pubKeyOrDeviceID string) bool {
	ctx := context.Background()
	res, err := ds.conn().ExecContext(ctx,
		`DELETE FROM pending_devices WHERE public_key = ? OR device_id = ?`,
		pubKeyOrDeviceID, pubKeyOrDeviceID)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// DenyPendingDevice removes a pending device and records a pairing denial (optional custom message for the user).
// customMessage must already be sanitized; empty means "use default random client message".
// snarkIndex, when non-nil and in range 0..MaxPairingSnarkIndex, selects which canned deny line the pairing UI shows; nil means random line on the client.
func (ds *DeviceStore) DenyPendingDevice(pubKeyOrDeviceID, customMessage string, snarkIndex *int) error {
	return ds.ApplyTransactional(func(work *DeviceStore) error {
		ctx := context.Background()
		c := work.conn()
		var pk string
		err := c.QueryRowContext(ctx,
			`SELECT public_key FROM pending_devices WHERE public_key = ? OR device_id = ? LIMIT 1`,
			pubKeyOrDeviceID, pubKeyOrDeviceID).Scan(&pk)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrPendingDeviceNotFound
			}
			return err
		}
		res, err := c.ExecContext(ctx, `DELETE FROM pending_devices WHERE public_key = ?`, pk)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrPendingDeviceNotFound
		}
		var msgArg any
		if strings.TrimSpace(customMessage) == "" {
			msgArg = nil
		} else {
			msgArg = customMessage
		}
		var snArg any
		if snarkIndex != nil && *snarkIndex >= 0 && *snarkIndex <= MaxPairingSnarkIndex {
			snArg = *snarkIndex
		} else {
			snArg = nil
		}
		_, err = c.ExecContext(ctx, `
INSERT INTO pairing_denials (public_key, custom_message, denied_at, strike_count, active, snark_index)
VALUES (?,?,?,1,1,?)
ON CONFLICT(public_key) DO UPDATE SET
	strike_count = pairing_denials.strike_count + 1,
	custom_message = excluded.custom_message,
	denied_at = excluded.denied_at,
	active = 1,
	snark_index = excluded.snark_index`,
			pk, msgArg, time.Now().Unix(), snArg)
		return err
	})
}

// GetPairingDenialState: denial row for pubkey — message, whether denial UI is active, strike count, optional snark line index.
func (ds *DeviceStore) GetPairingDenialState(pubKey string) (customMessage string, active bool, strikeCount int, snarkIndex sql.NullInt64) {
	ctx := context.Background()
	var msg sql.NullString
	var act, sc int
	err := ds.conn().QueryRowContext(ctx,
		`SELECT custom_message, active, strike_count, snark_index FROM pairing_denials WHERE public_key = ?`, pubKey).Scan(&msg, &act, &sc, &snarkIndex)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, 0, sql.NullInt64{}
		}
		return "", false, 0, sql.NullInt64{}
	}
	strikeCount = sc
	active = act != 0
	if msg.Valid {
		customMessage = msg.String
	}
	return
}

// GetPairingDenial returns whether this public key has an active denial and any custom admin message.
func (ds *DeviceStore) GetPairingDenial(pubKey string) (customMessage string, denied bool) {
	msg, active, _, _ := ds.GetPairingDenialState(pubKey)
	if !active {
		return "", false
	}
	return msg, true
}

// PairingPermanentlyBlocked reports whether this public key may no longer call pairing register.
func (ds *DeviceStore) PairingPermanentlyBlocked(pubKey string) bool {
	_, _, strikes, _ := ds.GetPairingDenialState(pubKey)
	return strikes >= MaxPairingDenyStrikes
}

// DeactivatePairingDenial clears the active denial so the user can submit one more pairing request (if strikes allow).
func (ds *DeviceStore) DeactivatePairingDenial(pubKey string) {
	ctx := context.Background()
	_, _ = ds.conn().ExecContext(ctx,
		`UPDATE pairing_denials SET active = 0 WHERE public_key = ? AND strike_count < ?`,
		pubKey, MaxPairingDenyStrikes)
}

// ListPairingDenials returns all pairing denial rows, newest denied_at first.
func (ds *DeviceStore) ListPairingDenials() ([]PairingDenialRecord, error) {
	ctx := context.Background()
	rows, err := ds.conn().QueryContext(ctx, `
SELECT public_key, custom_message, denied_at, strike_count, active, snark_index
FROM pairing_denials ORDER BY denied_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PairingDenialRecord
	for rows.Next() {
		var r PairingDenialRecord
		var msg sql.NullString
		var deniedAt int64
		var act int
		var sn sql.NullInt64
		if err := rows.Scan(&r.PublicKey, &msg, &deniedAt, &r.StrikeCount, &act, &sn); err != nil {
			return nil, err
		}
		r.DeniedAt = time.Unix(deniedAt, 0)
		r.Active = act != 0
		if msg.Valid {
			r.CustomMessage = msg.String
		}
		if sn.Valid {
			v := int(sn.Int64)
			r.SnarkIndex = &v
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RemovePairingDenial deletes a pairing_denials row by public key or by device ID (word-token-word form).
func (ds *DeviceStore) RemovePairingDenial(pubKeyOrDeviceID string) bool {
	ctx := context.Background()
	c := ds.conn()
	res, err := c.ExecContext(ctx, `DELETE FROM pairing_denials WHERE public_key = ?`, pubKeyOrDeviceID)
	if err != nil {
		return false
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true
	}
	rows, err := c.QueryContext(ctx, `SELECT public_key FROM pairing_denials`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var pk string
		if err := rows.Scan(&pk); err != nil {
			continue
		}
		if ComputeStableDeviceID(pk) == pubKeyOrDeviceID {
			res2, err := c.ExecContext(ctx, `DELETE FROM pairing_denials WHERE public_key = ?`, pk)
			if err != nil {
				return false
			}
			n, _ := res2.RowsAffected()
			return n > 0
		}
	}
	return false
}

// ApproveDevice moves a device from pending to authorized.
func (ds *DeviceStore) ApproveDevice(pubKey, deviceID string) bool {
	ctx := context.Background()
	c := ds.conn()

	var row struct {
		pk, did, raddr string
		pendingAt      int64
		clientInfoRaw  sql.NullString
	}
	err := c.QueryRowContext(ctx, `
SELECT public_key, device_id, remote_addr, pending_at, client_info_json FROM pending_devices
WHERE public_key = ? OR device_id = ? LIMIT 1`,
		pubKey, deviceID).Scan(&row.pk, &row.did, &row.raddr, &row.pendingAt, &row.clientInfoRaw)
	if err != nil {
		return false
	}

	secret := make([]byte, SessionSecretRandomBytes)
	if _, err := rand.Read(secret); err != nil {
		return false
	}
	sessionSecret := base64.StdEncoding.EncodeToString(secret)

	res, err := c.ExecContext(ctx, `DELETE FROM pending_devices WHERE public_key = ?`, row.pk)
	if err != nil {
		return false
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false
	}

	var ciArg any
	if row.clientInfoRaw.Valid && strings.TrimSpace(row.clientInfoRaw.String) != "" {
		ciArg = row.clientInfoRaw.String
	} else {
		ciArg = nil
	}
	_, err = c.ExecContext(ctx, `
INSERT INTO authorized_devices (public_key, device_id, approved_at, remote_addr, session_secret, client_info_json)
VALUES (?,?,?,?,?,?)`,
		row.pk, row.did, time.Now().Unix(), nullIfEmpty(row.raddr), sessionSecret, ciArg)
	return err == nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// SessionSecretForPublicKey: HMAC secret for this pubkey, or "" if none.
func (ds *DeviceStore) SessionSecretForPublicKey(pubKey string) string {
	ctx := context.Background()
	var sec sql.NullString
	err := ds.conn().QueryRowContext(ctx, `SELECT session_secret FROM authorized_devices WHERE public_key = ?`, pubKey).Scan(&sec)
	if err != nil || !sec.Valid {
		return ""
	}
	return sec.String
}

// GetAuthorized returns authorized devices ordered by approved_at.
func (ds *DeviceStore) GetAuthorized() ([]DeviceInfo, error) {
	ctx := context.Background()
	rows, err := ds.conn().QueryContext(ctx, `SELECT public_key, device_id, approved_at, remote_addr, session_secret, last_seen, last_seen_session_proof, last_seen_cookie, client_info_json FROM authorized_devices ORDER BY approved_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DeviceInfo
	for rows.Next() {
		var di DeviceInfo
		var approved int64
		var raddr, sec sql.NullString
		var seen, seenProof, seenCookie sql.NullInt64
		var clientRaw sql.NullString
		if err := rows.Scan(&di.PublicKey, &di.DeviceID, &approved, &raddr, &sec, &seen, &seenProof, &seenCookie, &clientRaw); err != nil {
			return nil, err
		}
		di.ApprovedAt = time.Unix(approved, 0)
		if raddr.Valid {
			di.RemoteAddr = raddr.String
		}
		if sec.Valid {
			di.SessionSecret = sec.String
		}
		if seen.Valid && seen.Int64 > 0 {
			di.LastSeen = time.Unix(seen.Int64, 0)
		}
		if seenProof.Valid && seenProof.Int64 > 0 {
			di.LastSeenSessionProof = time.Unix(seenProof.Int64, 0)
		}
		if seenCookie.Valid && seenCookie.Int64 > 0 {
			di.LastSeenCookie = time.Unix(seenCookie.Int64, 0)
		}
		if clientRaw.Valid && strings.TrimSpace(clientRaw.String) != "" {
			var ci PendingClientInfo
			if err := json.Unmarshal([]byte(clientRaw.String), &ci); err == nil {
				di.ClientInfo = &ci
			}
		}
		out = append(out, di)
	}
	return out, rows.Err()
}

// TouchAuthorizedAuth updates last_seen and the per-channel telemetry column (each throttled to at most once per minute).
func (ds *DeviceStore) TouchAuthorizedAuth(pubKey string, touch AuthorizedAuthTouch) {
	if pubKey == "" {
		return
	}
	ctx := context.Background()
	now := time.Now().Unix()
	thresh := now - 60
	var cookieFlag, proofFlag int64
	switch touch {
	case AuthTouchCookie:
		cookieFlag = 1
	case AuthTouchSessionProof, AuthTouchSignature:
		proofFlag = 1
	default:
		return
	}
	_, _ = ds.conn().ExecContext(ctx, `
UPDATE authorized_devices SET
	last_seen = CASE WHEN last_seen IS NULL OR last_seen < ? THEN ? ELSE last_seen END,
	last_seen_cookie = CASE WHEN ? != 0 AND (last_seen_cookie IS NULL OR last_seen_cookie < ?) THEN ? ELSE last_seen_cookie END,
	last_seen_session_proof = CASE WHEN ? != 0 AND (last_seen_session_proof IS NULL OR last_seen_session_proof < ?) THEN ? ELSE last_seen_session_proof END
WHERE public_key = ?`,
		thresh, now,
		cookieFlag, thresh, now,
		proofFlag, thresh, now,
		pubKey)
}

// GetPending returns pending devices ordered by pending_at (newest first).
func (ds *DeviceStore) GetPending() []PendingDevice {
	ctx := context.Background()
	rows, err := ds.conn().QueryContext(ctx, `SELECT public_key, device_id, remote_addr, pending_at, client_info_json FROM pending_devices ORDER BY pending_at DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []PendingDevice
	for rows.Next() {
		var p PendingDevice
		var ts int64
		var clientInfoJSON sql.NullString
		if err := rows.Scan(&p.PublicKey, &p.DeviceID, &p.RemoteAddr, &ts, &clientInfoJSON); err != nil {
			return nil
		}
		p.PendingAt = time.Unix(ts, 0)
		if clientInfoJSON.Valid && strings.TrimSpace(clientInfoJSON.String) != "" {
			var ci PendingClientInfo
			if err := json.Unmarshal([]byte(clientInfoJSON.String), &ci); err == nil {
				p.ClientInfo = &ci
			}
		}
		out = append(out, p)
	}
	return out
}

// IsTokenAuthorized: device_auth cookie value still valid?
func (ds *DeviceStore) IsTokenAuthorized(token string) bool {
	ctx := context.Background()
	var n int
	err := ds.conn().QueryRowContext(ctx, `SELECT 1 FROM authorized_tokens WHERE token = ? LIMIT 1`, token).Scan(&n)
	return err == nil
}

// AddAuthorizedToken adds a token to the authorized tokens list.
func (ds *DeviceStore) AddAuthorizedToken(token string) {
	ctx := context.Background()
	_, _ = ds.conn().ExecContext(ctx, `INSERT OR IGNORE INTO authorized_tokens (token) VALUES (?)`, token)
}

// RemoveAuthorizedDevice removes a device from the authorized list and revokes its tokens.
func (ds *DeviceStore) RemoveAuthorizedDevice(pubKeyOrDeviceID string) bool {
	ctx := context.Background()
	c := ds.conn()

	var pubKey string
	err := c.QueryRowContext(ctx, `SELECT public_key FROM authorized_devices WHERE public_key = ? OR device_id = ? LIMIT 1`, pubKeyOrDeviceID, pubKeyOrDeviceID).Scan(&pubKey)
	if err != nil {
		return false
	}

	res, err := c.ExecContext(ctx, `DELETE FROM authorized_devices WHERE public_key = ?`, pubKey)
	if err != nil {
		return false
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false
	}

	rows, err := c.QueryContext(ctx, `SELECT token FROM authorized_tokens`)
	if err != nil {
		return true
	}
	defer rows.Close()

	prefix := pubKey + ":"
	var keep []string
	for rows.Next() {
		var tok string
		if err := rows.Scan(&tok); err != nil {
			continue
		}
		decoded, err := base64.URLEncoding.DecodeString(tok)
		if err != nil {
			keep = append(keep, tok)
			continue
		}
		if !strings.HasPrefix(string(decoded), prefix) {
			keep = append(keep, tok)
		}
	}
	_, _ = c.ExecContext(ctx, `DELETE FROM authorized_tokens`)
	for _, t := range keep {
		_, _ = c.ExecContext(ctx, `INSERT OR IGNORE INTO authorized_tokens (token) VALUES (?)`, t)
	}

	return true
}

// SnapshotJSON exports the store in the legacy JSON shape (CLI export / backups).
func (ds *DeviceStore) SnapshotJSON() ([]byte, error) {
	auth, err := ds.GetAuthorized()
	if err != nil {
		return nil, err
	}
	snap := struct {
		AuthorizedDevices []DeviceInfo    `json:"authorized_devices"`
		PendingDevices    []PendingDevice `json:"pending_devices"`
		AuthorizedTokens  []string        `json:"authorized_tokens"`
	}{
		AuthorizedDevices: auth,
		PendingDevices:    ds.GetPending(),
		AuthorizedTokens:  nil,
	}
	ctx := context.Background()
	rows, err := ds.conn().QueryContext(ctx, `SELECT token FROM authorized_tokens ORDER BY token`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		snap.AuthorizedTokens = append(snap.AuthorizedTokens, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(snap, "", "  ")
}

// GenerateDeviceToken generates a secure token for a device.
func GenerateDeviceToken(pubKey string) string {
	tokenData := fmt.Sprintf("%s:%d", pubKey, time.Now().Unix())
	return base64.URLEncoding.EncodeToString([]byte(tokenData))
}

// PublicKeyFromDeviceToken extracts the device public key from a token from GenerateDeviceToken (cookie payload).
func PublicKeyFromDeviceToken(token string) (pubKey string, ok bool) {
	b, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return "", false
	}
	s := string(b)
	i := strings.IndexByte(s, ':')
	if i <= 0 {
		return "", false
	}
	return s[:i], true
}

func (ds *DeviceStore) GetAdminAuthSettings() (AdminAuthSettings, error) {
	ctx := context.Background()
	var out AdminAuthSettings
	var enabled int
	err := ds.conn().QueryRowContext(ctx, `SELECT otp_secret, otp_enabled FROM admin_auth_settings WHERE id = 1`).Scan(&out.OTPSecret, &enabled)
	if err != nil {
		return AdminAuthSettings{}, err
	}
	out.OTPEnabled = enabled != 0
	return out, nil
}

func (ds *DeviceStore) SaveAdminOTPSetup(secret string, enabled bool) error {
	ctx := context.Background()
	v := 0
	if enabled {
		v = 1
	}
	_, err := ds.conn().ExecContext(ctx, `
INSERT INTO admin_auth_settings (id, otp_secret, otp_enabled)
VALUES (1, ?, ?)
ON CONFLICT(id) DO UPDATE SET otp_secret = excluded.otp_secret, otp_enabled = excluded.otp_enabled`,
		secret, v)
	return err
}
