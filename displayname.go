package vpnless

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxDisplayNameRunes = 96

// SanitizeDisplayName: human-ish label for UI; letters/marks, space, a few punctuation; drops garbage.
func SanitizeDisplayName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Browsers typically send NFC; we validate runes without re-normalizing to avoid extra deps.
	var b strings.Builder
	runeCount := 0
	lastSpace := false
	for _, r := range s {
		if r == 0 || unicode.IsControl(r) {
			continue
		}
		var ok bool
		switch {
		case unicode.IsLetter(r) || unicode.IsMark(r):
			ok = true
		case r == ' ' || r == '-' || r == '\'' || r == '\u2019' || r == '.':
			ok = true
		default:
			ok = false
		}
		if !ok {
			continue
		}
		if r == ' ' {
			if runeCount == 0 || lastSpace {
				continue
			}
			lastSpace = true
		} else {
			lastSpace = false
		}
		if runeCount >= maxDisplayNameRunes {
			break
		}
		b.WriteRune(r)
		runeCount++
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return ""
	}
	if utf8.RuneCountInString(out) > maxDisplayNameRunes {
		out = truncateRunes(out, maxDisplayNameRunes)
	}
	return out
}

const maxDenyMessageRunes = 400

// SanitizeDenyMessage: admin → user text on deny; looser charset, length cap.
func SanitizeDenyMessage(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	runeCount := 0
	lastSpace := false
	for _, r := range s {
		if r == 0 || unicode.IsControl(r) {
			continue
		}
		var ok bool
		switch {
		case unicode.IsLetter(r) || unicode.IsMark(r) || unicode.IsDigit(r):
			ok = true
		case r == ' ' || r == '-' || r == '\'' || r == '\u2019' || r == '.' || r == ',' || r == '!' || r == '?' || r == ':' || r == ';' || r == '(' || r == ')' || r == '"' || r == '#' || r == '%' || r == '&' || r == '*' || r == '@' || r == '+' || r == '/' || r == '\\' || r == '|' || r == '~' || r == '^' || r == '=' || r == '_' || r == '[' || r == ']' || r == '{' || r == '}':
			ok = true
		default:
			ok = false
		}
		if !ok {
			continue
		}
		if r == ' ' {
			if runeCount == 0 || lastSpace {
				continue
			}
			lastSpace = true
		} else {
			lastSpace = false
		}
		if runeCount >= maxDenyMessageRunes {
			break
		}
		b.WriteRune(r)
		runeCount++
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return ""
	}
	if utf8.RuneCountInString(out) > maxDenyMessageRunes {
		out = truncateRunes(out, maxDenyMessageRunes)
	}
	return out
}

func truncateRunes(s string, n int) string {
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}
