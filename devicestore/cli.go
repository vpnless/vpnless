package devicestore

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

func CLIApprove(storagePath, publicKeyOrDeviceID string) error {
	store, err := NewDeviceStore(storagePath)
	if err != nil {
		return err
	}
	defer store.Close()

	var foundPubKey, foundDeviceID string
	err = store.ApplyTransactional(func(work *DeviceStore) error {
		for _, pending := range work.GetPending() {
			if pending.PublicKey == publicKeyOrDeviceID || pending.DeviceID == publicKeyOrDeviceID {
				foundPubKey = pending.PublicKey
				foundDeviceID = pending.DeviceID
				break
			}
		}
		if foundPubKey == "" {
			return fmt.Errorf("device not found in pending list: %s", publicKeyOrDeviceID)
		}
		if !work.ApproveDevice(foundPubKey, foundDeviceID) {
			return fmt.Errorf("failed to approve device")
		}
		return nil
	})
	if err != nil {
		return err
	}

	fmt.Printf("Device approved: %s (ID: %s)\n", foundPubKey[:16]+"...", foundDeviceID)
	return nil
}

func CLIListPending(storagePath string) error {
	store, err := NewDeviceStore(storagePath)
	if err != nil {
		return fmt.Errorf("failed to open device store: %w", err)
	}
	defer store.Close()

	pending := store.GetPending()

	if len(pending) == 0 {
		fmt.Println("No pending devices")
		return nil
	}

	fmt.Println("Pending devices:")
	fmt.Println("================")
	for i, device := range pending {
		fmt.Printf("\n%d. Device ID: %s\n", i+1, device.DeviceID)
		fmt.Printf("   Public Key: %s\n", device.PublicKey)
		fmt.Printf("   Remote Addr: %s\n", device.RemoteAddr)
		fmt.Printf("   Pending Since: %s\n", device.PendingAt.Format("2006-01-02 15:04:05"))
		if device.ClientInfo != nil {
			if device.ClientInfo.DisplayName != "" {
				fmt.Printf("   Display name: %s\n", device.ClientInfo.DisplayName)
			}
			fmt.Println("   Client Info:")
			fmt.Printf("     User-Agent: %s\n", device.ClientInfo.UserAgent)
			fmt.Printf("     Browser: %s %s\n", device.ClientInfo.Browser, device.ClientInfo.BrowserVersion)
			fmt.Printf("     OS: %s %s\n", device.ClientInfo.OS, device.ClientInfo.OSVersion)
			fmt.Printf("     Screen: %s\n", device.ClientInfo.Screen)
			fmt.Printf("     Timezone: %s\n", device.ClientInfo.Timezone)
			fmt.Printf("     Languages: %s\n", device.ClientInfo.Languages)
			fmt.Printf("     CPU Cores: %s\n", device.ClientInfo.HardwareConcurrency)
			fmt.Printf("     X-Forwarded-For: %s\n", device.ClientInfo.XForwardedFor)
			fmt.Printf("     X-Real-IP: %s\n", device.ClientInfo.XRealIP)
			fmt.Printf("     Forwarded: %s\n", device.ClientInfo.Forwarded)
			fmt.Printf("     Peer Remote Addr: %s\n", device.ClientInfo.PeerRemoteAddr)
		}
	}

	return nil
}

func CLIListAuthorized(storagePath string) error {
	store, err := NewDeviceStore(storagePath)
	if err != nil {
		return fmt.Errorf("failed to open device store: %w", err)
	}
	defer store.Close()

	authorized, err := store.GetAuthorized()
	if err != nil {
		return fmt.Errorf("failed to read authorized devices: %w", err)
	}

	if len(authorized) == 0 {
		fmt.Println("No authorized devices")
		return nil
	}

	fmt.Println("Authorized devices:")
	fmt.Println("===================")
	for i, device := range authorized {
		fmt.Printf("\n%d. Device ID: %s\n", i+1, device.DeviceID)
		fmt.Printf("   Public Key: %s\n", device.PublicKey)
		fmt.Printf("   Remote Addr: %s\n", device.RemoteAddr)
		fmt.Printf("   Approved At: %s\n", formatAbsAndRelative(device.ApprovedAt))
		if !device.LastSeen.IsZero() {
			fmt.Printf("   Last Seen: %s\n", formatAbsAndRelative(device.LastSeen))
		} else {
			fmt.Printf("   Last Seen: (never — no traffic since tracking enabled)\n")
		}
		fmt.Printf("   Session Secret: %s\n", device.SessionSecret)
	}

	return nil
}

func CLIListDenied(storagePath string) error {
	store, err := NewDeviceStore(storagePath)
	if err != nil {
		return fmt.Errorf("failed to open device store: %w", err)
	}
	defer store.Close()

	rows, err := store.ListPairingDenials()
	if err != nil {
		return fmt.Errorf("failed to read pairing denials: %w", err)
	}

	if len(rows) == 0 {
		fmt.Println("No denied devices (no pairing_denials rows)")
		return nil
	}

	fmt.Println("Denied pairing keys:")
	fmt.Println("====================")
	for i, r := range rows {
		fmt.Printf("\n%d. Public Key: %s\n", i+1, r.PublicKey)
		fmt.Printf("   Last denied at: %s\n", formatAbsAndRelative(r.DeniedAt))
		fmt.Printf("   Strike count: %d", r.StrikeCount)
		if r.StrikeCount >= MaxPairingDenyStrikes {
			fmt.Print(" (pairing closed for this key)")
		}
		fmt.Println()
		if r.Active {
			fmt.Println("   Active denial: yes (user sees denied screen if they poll)")
		} else {
			fmt.Println("   Active denial: no (may be pending again or cleared)")
		}
		if r.SnarkIndex != nil {
			fmt.Printf("   Snark line index: %d\n", *r.SnarkIndex)
		}
		if strings.TrimSpace(r.CustomMessage) != "" {
			fmt.Printf("   Custom message: %s\n", r.CustomMessage)
		}
	}

	return nil
}

type activityRow struct {
	EventTime time.Time
	Status    string
	DeviceID  string
	PublicKey string
	Remote    string
	Note      string
}

func shortPub(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 28 {
		return s
	}
	return s[:28] + "…"
}

func CLIListAllActivity(storagePath string) error {
	store, err := NewDeviceStore(storagePath)
	if err != nil {
		return fmt.Errorf("failed to open device store: %w", err)
	}
	defer store.Close()

	pending := store.GetPending()
	authorized, err := store.GetAuthorized()
	if err != nil {
		return fmt.Errorf("failed to read authorized devices: %w", err)
	}
	denied, err := store.ListPairingDenials()
	if err != nil {
		return fmt.Errorf("failed to read pairing denials: %w", err)
	}

	var rows []activityRow
	for _, p := range pending {
		rows = append(rows, activityRow{
			EventTime: p.PendingAt,
			Status:    "pending",
			DeviceID:  p.DeviceID,
			PublicKey: shortPub(p.PublicKey),
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
			note = "last activity " + humanizeSince(a.LastSeen)
		}
		rows = append(rows, activityRow{
			EventTime: t,
			Status:    "authorized",
			DeviceID:  a.DeviceID,
			PublicKey: shortPub(a.PublicKey),
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
		rows = append(rows, activityRow{
			EventTime: d.DeniedAt,
			Status:    "denied",
			DeviceID:  "—",
			PublicKey: shortPub(d.PublicKey),
			Remote:    "—",
			Note:      note,
		})
	}

	if len(rows) == 0 {
		fmt.Println("No pending, authorized, or denied pairing records.")
		fmt.Println(threatListHint)
		return nil
	}

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].EventTime.After(rows[j].EventTime)
	})

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "LAST_EVENT (UTC)\tSTATUS\tDEVICE_ID\tPUBLIC_KEY\tREMOTE\tNOTE")
	for _, r := range rows {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.EventTime.UTC().Format("2006-01-02 15:04:05"),
			r.Status,
			r.DeviceID,
			r.PublicKey,
			r.Remote,
			r.Note,
		)
	}
	_ = w.Flush()
	fmt.Fprintln(os.Stdout, threatListHint)
	return nil
}

const threatListHint = "Note: Browser \"Temporarily banned\" is IP threat state (blacklist/tarpit/…), not the table above — run: vpnless list threats   (clear: vpnless clear-threat <ip>)"

func CLIListThreats(storagePath string) error {
	store, err := NewDeviceStore(storagePath)
	if err != nil {
		return fmt.Errorf("failed to open device store: %w", err)
	}
	defer store.Close()

	list, err := store.ThreatList(time.Now())
	if err != nil {
		return fmt.Errorf("failed to list threats: %w", err)
	}
	if len(list) == 0 {
		fmt.Println("No threat telemetry rows (no failed-auth hits and no admin threat actions).")
		return nil
	}

	fmt.Println("Threat targets (SQLite — shared across Caddy workers).")
	fmt.Println("Auto-blacklist: after 20 failed vpnless-auth strikes (unpaired/no cookie) for one IP, mode becomes blacklist for ~30 minutes.")
	fmt.Println("For blacklisted IPs, LAST_SEEN is updated on each blocked hit at the vpnless gate (failed session/cookie/signature before 403).")
	fmt.Println("Remove blacklisting: admin Threat Monitor → Clear, or: vpnless clear-threat <ip>")
	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "IP\tMODE\tHITS\tSTRIKES\tMODE_SET (UTC)\tLAST_SEEN (UTC)\tEXPIRES (UTC)\tLAST_PATH")
	for _, t := range list {
		exp := "—"
		if !t.ExpiresAt.IsZero() {
			exp = t.ExpiresAt.UTC().Format("2006-01-02 15:04:05")
		}
		setAt := "—"
		if !t.SetAt.IsZero() {
			setAt = t.SetAt.UTC().Format("2006-01-02 15:04:05")
		}
		seen := "—"
		if !t.LastSeen.IsZero() {
			seen = t.LastSeen.UTC().Format("2006-01-02 15:04:05")
		}
		lp := t.LastPath
		if lp == "" {
			lp = "—"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\n",
			t.IP, t.Mode, t.Hits, t.StrikeCount, setAt, seen, exp, lp)
	}
	_ = w.Flush()
	return nil
}

func CLIClearThreat(storagePath, ipOrHost string) error {
	ip := NormalizeThreatIP(ipOrHost)
	if ip == "" {
		return fmt.Errorf("ip is required")
	}
	store, err := NewDeviceStore(storagePath)
	if err != nil {
		return fmt.Errorf("failed to open device store: %w", err)
	}
	defer store.Close()
	if err := store.ThreatAdminSet(ip, "clear", 0, time.Now()); err != nil {
		return err
	}
	fmt.Printf("Threat state cleared for %s\n", ip)
	return nil
}

func CLIDeny(storagePath, publicKeyOrDeviceID string) error {
	store, err := NewDeviceStore(storagePath)
	if err != nil {
		return err
	}
	defer store.Close()

	err = store.DenyPendingDevice(publicKeyOrDeviceID, "", nil)
	if err != nil {
		if errors.Is(err, ErrPendingDeviceNotFound) {
			return fmt.Errorf("device not found in pending list: %s", publicKeyOrDeviceID)
		}
		return err
	}

	fmt.Printf("Device denied: %s\n", publicKeyOrDeviceID)
	return nil
}

func CLIRemove(storagePath, publicKeyOrDeviceID string) error {
	store, err := NewDeviceStore(storagePath)
	if err != nil {
		return err
	}
	defer store.Close()

	removed := ""
	err = store.ApplyTransactional(func(work *DeviceStore) error {
		if work.RemoveAuthorizedDevice(publicKeyOrDeviceID) {
			removed = "authorized"
			return nil
		}
		if work.RemovePairingDenial(publicKeyOrDeviceID) {
			removed = "denied"
			return nil
		}
		return fmt.Errorf("not found in authorized or pairing-denied list: %s", publicKeyOrDeviceID)
	})
	if err != nil {
		return err
	}
	if removed == "authorized" {
		fmt.Printf("Removed from authorized list (access revoked): %s\n", publicKeyOrDeviceID)
	} else {
		fmt.Printf("Pairing denial cleared (key may request access again): %s\n", publicKeyOrDeviceID)
	}
	return nil
}

func CLIExport(storagePath, outputPath string) error {
	store, err := NewDeviceStore(storagePath)
	if err != nil {
		return fmt.Errorf("failed to open device store: %w", err)
	}
	defer store.Close()

	data, err := store.SnapshotJSON()
	if err != nil {
		return fmt.Errorf("failed to export device store: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write export file: %w", err)
	}

	fmt.Printf("Exported device store to: %s\n", outputPath)
	return nil
}

func formatAbsAndRelative(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("2006-01-02 15:04:05") + " (" + humanizeSince(t) + ")"
}

func humanizeSince(t time.Time) string {
	sec := int(time.Since(t).Seconds())
	if sec < 0 {
		return "just now"
	}
	if sec < 45 {
		return "just now"
	}
	if sec < 90 {
		return "1 minute ago"
	}
	if sec < 3600 {
		return fmt.Sprintf("%d minutes ago", sec/60)
	}
	if sec < 7200 {
		return "1 hour ago"
	}
	if sec < 86400 {
		return fmt.Sprintf("%d hours ago", sec/3600)
	}
	days := sec / 86400
	if days == 1 {
		return "1 day ago"
	}
	if days < 14 {
		return fmt.Sprintf("%d days ago", days)
	}
	weeks := days / 7
	if weeks < 8 {
		if weeks <= 1 {
			return "1 week ago"
		}
		return fmt.Sprintf("%d weeks ago", weeks)
	}
	return t.Format("Jan 2, 2006")
}
