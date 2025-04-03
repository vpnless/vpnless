package vpnless

import (
	"regexp"
	"strings"
)

type ClientInfo struct {
	RemoteAddr string `json:"remote_addr"`
	UserAgent  string `json:"user_agent"`
	Browser    string `json:"browser"`
	BrowserVer string `json:"browser_version"`
	OS         string `json:"os"`
	OSVersion  string `json:"os_version"`
}

func parseUserAgent(ua string) (browser, browserVer, os, osVer string) {
	if ua == "" {
		return "Unknown", "", "Unknown", ""
	}

	// Order matters: check Edge (contains Chrome), then Chrome, then Firefox, Safari, Opera
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
		browserVer = extractVersion(ua, "Edg/")
	case strings.Contains(ua, "OPR/") || strings.Contains(ua, "Opera/"):
		browser = "Opera"
		browserVer = extractVersion(ua, "OPR/")
		if browserVer == "" {
			browserVer = extractVersion(ua, "Opera/")
		}
	case strings.Contains(ua, "Chrome/") && !strings.Contains(ua, "Chromium"):
		browser = "Chrome"
		browserVer = extractVersion(ua, "Chrome/")
	case strings.Contains(ua, "Chromium/"):
		browser = "Chromium"
		browserVer = extractVersion(ua, "Chromium/")
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
		browserVer = extractVersion(ua, "Firefox/")
	case strings.Contains(ua, "Safari/") && !strings.Contains(ua, "Chrome"):
		browser = "Safari"
		browserVer = extractVersion(ua, "Version/")
		if browserVer == "" {
			browserVer = extractVersion(ua, "Safari/")
		}
	default:
		browser = "Unknown"
	}

	// OS detection
	switch {
	case strings.Contains(ua, "Windows NT 10"):
		os = "Windows"
		osVer = "10/11"
	case strings.Contains(ua, "Windows NT 6.3"):
		os = "Windows"
		osVer = "8.1"
	case strings.Contains(ua, "Windows"):
		os = "Windows"
	case strings.Contains(ua, "Mac OS X"):
		os = "macOS"
		osVer = extractVersion(ua, "Mac OS X ")
		osVer = strings.ReplaceAll(osVer, "_", ".")
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		os = "iOS"
		osVer = extractVersion(ua, "OS ")
	case strings.Contains(ua, "Android"):
		os = "Android"
		osVer = extractVersion(ua, "Android ")
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	case strings.Contains(ua, "CrOS"):
		os = "Chrome OS"
		osVer = extractVersion(ua, "CrOS ")
	default:
		os = "Unknown"
	}

	return browser, browserVer, os, osVer
}

var versionRe = regexp.MustCompile(`(\d+(?:\.\d+)?(?:\.\d+)?)`)

func extractVersion(ua, prefix string) string {
	i := strings.Index(ua, prefix)
	if i < 0 {
		return ""
	}
	s := ua[i+len(prefix):]
	if j := strings.IndexAny(s, " \t;)"); j >= 0 {
		s = s[:j]
	}
	if m := versionRe.FindStringSubmatch(s); len(m) > 0 {
		return m[1]
	}
	return ""
}

func getClientInfoFromRequest(remoteAddr, userAgent string) ClientInfo {
	browser, browserVer, os, osVer := parseUserAgent(userAgent)
	return ClientInfo{
		RemoteAddr: remoteAddr,
		UserAgent:  userAgent,
		Browser:    browser,
		BrowserVer: browserVer,
		OS:         os,
		OSVersion:  osVer,
	}
}
