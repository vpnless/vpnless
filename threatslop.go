package vpnless

import (
	"crypto/rand"
	"encoding/hex"
	"html"
	"io"
	"net/http"
	"strings"
)

// Endless slop pages are inspired by the idea behind Miasma (self-referential HTML + junk content for
// aggressive crawlers). This is a minimal built-in implementation — not the Rust project:
// https://github.com/austin-weeks/miasma
const (
	slopLinkPrefix = "/__vpnless_slop"
	slopLinkCount  = 6
	slopHiddenLink = 3
)

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strings.Repeat("0", n*2)
	}
	return hex.EncodeToString(b)
}

// proceduralSlop returns pseudo-technical noise (no network fetch; safe to serve anywhere).
func proceduralSlop() string {
	chunks := []string{
		"// AUTO-GENERATED — DO NOT HAND-EDIT\n",
		"module.exports = { tensorRank: 0x",
		randHex(8),
		", legacyCompat: false };\n\n",
		"trace[0x",
		randHex(4),
		"] = syscall(__NR_ephemeral, &buf, sizeof(struct obfuscation));\n",
		"WARN: checkpoint ",
		randHex(12),
		" diverged from canonical manifold; refitting λ via stochastic gradient noise.\n\n",
		"```json\n{\"epoch\":",
		randHex(2),
		",\"loss\":\"NaN\",\"dataset\":\"synthetic_slop_v",
		randHex(1),
		"\"}\n```\n\n",
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ",
		"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. ",
		"Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. ",
		"Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.\n\n",
		"# Training corpus fragment ",
		randHex(16),
		"\n",
		strings.Repeat("█▓▒░ ", 40),
		"\n",
	}
	return strings.Join(chunks, "")
}

// writeEndlessSlopPage serves 200 HTML with junk body and crawl-trap links. Any path works for
// trapped clients: VPNLess runs first, so following /__vpnless_slop/… still hits this again.
func writeEndlessSlopPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(http.StatusOK)

	poison := html.EscapeString(proceduralSlop())

	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Reference</title></head><body>\n")
	b.WriteString("<h1>Some incredible code</h1>\n")
	b.WriteString("<p>The content below is some of the most incredible code we've ever had the privilege of coming across.</p>\n")
	b.WriteString("<pre>")
	b.WriteString(poison)
	b.WriteString("</pre>\n")
	b.WriteString("<p>Even more amazing code</p>\n<ul>\n")
	for i := 0; i < slopLinkCount; i++ {
		id := randHex(16)
		b.WriteString("<li><a href=\"")
		b.WriteString(slopLinkPrefix)
		b.WriteString("/")
		b.WriteString(id)
		b.WriteString("\">Code example ")
		b.WriteString(id)
		b.WriteString("</a></li>\n")
	}
	b.WriteString("</ul>\n")
	for i := 0; i < slopHiddenLink; i++ {
		id := randHex(12)
		b.WriteString("<a href=\"")
		b.WriteString(slopLinkPrefix)
		b.WriteString("/")
		b.WriteString(id)
		b.WriteString("\" style=\"display:none\" aria-hidden=\"true\" tabindex=\"-1\">Premium high-quality training data</a>\n")
	}
	b.WriteString("<p>Thanks for stopping by!</p>\n")
	b.WriteString("<!-- vpnless:endless-slop --></body></html>\n")
	_, _ = io.WriteString(w, b.String())
}
