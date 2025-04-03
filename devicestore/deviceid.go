package devicestore

import (
	"bufio"
	"crypto/sha256"
	"encoding/base32"
	"os"
	"strings"
	"sync"
	"unicode"
)

var (
	deviceIDWordsOnce sync.Once
	deviceIDWords     []string
)

var fallbackDeviceIDWords = []string{
	"amber", "apple", "arrow", "ash", "atlas", "aurora", "autumn", "basil",
	"beacon", "birch", "bloom", "brook", "cedar", "cinder", "clover", "comet",
	"coral", "crimson", "dawn", "delta", "drift", "dune", "echo", "ember",
	"fern", "fable", "fjord", "flint", "frost", "glade", "grove", "harbor",
	"hazel", "hollow", "indigo", "iris", "ivy", "jade", "juniper", "kestrel",
	"lagoon", "laurel", "lilac", "lotus", "lumen", "maple", "marble", "meadow",
	"mist", "moss", "nectar", "nova", "oak", "onyx", "opal", "orchid",
	"pebble", "pine", "plum", "prairie", "quartz", "raven", "reef", "ridge",
	"river", "robin", "rose", "sage", "saffron", "shadow", "silk", "slate",
	"spruce", "stone", "storm", "sunset", "thistle", "timber", "topaz", "vale",
	"velvet", "violet", "wave", "willow", "wren", "zephyr",
}

func loadDeviceIDWords() []string {
	deviceIDWordsOnce.Do(func() {
		paths := []string{"/usr/dict/words", "/usr/share/dict/words"}
		for _, path := range paths {
			words := readWordList(path)
			if len(words) >= 64 {
				deviceIDWords = words
				return
			}
		}
		deviceIDWords = fallbackDeviceIDWords
	})
	return deviceIDWords
}

func readWordList(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	out := make([]string, 0, 1024)
	for sc.Scan() {
		w := sanitizeWord(sc.Text())
		if w == "" {
			continue
		}
		out = append(out, w)
	}
	if err := sc.Err(); err != nil {
		return nil
	}
	return out
}

func sanitizeWord(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) < 3 || len(s) > 12 {
		return ""
	}
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return ""
		}
	}
	return s
}

// ComputeStableDeviceID: word-word-token shape from pubkey hash (matches pairing UI).
func ComputeStableDeviceID(pubKey string) string {
	sum := sha256.Sum256([]byte(pubKey))
	words := loadDeviceIDWords()
	if len(words) == 0 {
		words = fallbackDeviceIDWords
	}

	startIdx := int(uint16(sum[0])<<8|uint16(sum[1])) % len(words)
	endIdx := int(uint16(sum[2])<<8|uint16(sum[3])) % len(words)
	if endIdx == startIdx {
		endIdx = (endIdx + 1) % len(words)
	}

	token := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[4:9]))
	return words[startIdx] + "-" + token + "-" + words[endIdx]
}
