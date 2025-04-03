package vpnless

import (
	"crypto/rand"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"strconv"
	"strings"
	"time"
)

// verifyTOTP validates a 6-digit TOTP code using RFC 6238 defaults:
// HMAC-SHA1, 30s step, with +/- one step skew tolerance.
func verifyTOTP(secret, code string, now time.Time) bool {
	cleanCode := strings.TrimSpace(code)
	if len(cleanCode) != 6 {
		return false
	}
	for _, r := range cleanCode {
		if r < '0' || r > '9' {
			return false
		}
	}

	cleanSecret := strings.ToUpper(strings.TrimSpace(secret))
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := encoding.DecodeString(cleanSecret)
	if err != nil || len(key) == 0 {
		return false
	}

	counter := now.Unix() / 30
	for _, offset := range []int64{-1, 0, 1} {
		if totpAtCounter(key, counter+offset) == cleanCode {
			return true
		}
	}
	return false
}

func totpAtCounter(key []byte, counter int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))

	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binCode := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)

	otp := binCode % 1000000
	s := strconv.Itoa(otp)
	for len(s) < 6 {
		s = "0" + s
	}
	return s
}

func generateTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}
