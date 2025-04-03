package vpnless

import "testing"

func TestSanitizeDisplayName(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"   ", ""},
		{"Alice", "Alice"},
		{"  Bob  Smith  ", "Bob Smith"},
		{"José O'Brien", "José O'Brien"},
		{"Line1\nLine2", "LineLine"},
		{"bad\x00name", "badname"},
		{"drop<script>", "dropscript"},
		{"a-b.c", "a-b.c"},
		{"!!!", ""},
	}
	for _, tc := range tests {
		got := SanitizeDisplayName(tc.in)
		if got != tc.want {
			t.Errorf("SanitizeDisplayName(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestSanitizeDisplayNameMaxRunes(t *testing.T) {
	var b []rune
	for i := 0; i < maxDisplayNameRunes+10; i++ {
		b = append(b, 'a')
	}
	got := SanitizeDisplayName(string(b))
	if len([]rune(got)) != maxDisplayNameRunes {
		t.Fatalf("got %d runes, want %d", len([]rune(got)), maxDisplayNameRunes)
	}
}

func TestSanitizeDenyMessage(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"   ", ""},
		{"Go away", "Go away"},
		{"  Not today  ", "Not today"},
		{"Weird\x00stuff!", "Weirdstuff!"},
		{"Line1\nLine2", "Line1Line2"},
		{"drop<script>tags", "dropscripttags"},
		{"!!!", "!!!"},
		{"Hi — \"you\" #1 (ok)?", "Hi \"you\" #1 (ok)?"},
	}
	for _, tc := range tests {
		got := SanitizeDenyMessage(tc.in)
		if got != tc.want {
			t.Errorf("SanitizeDenyMessage(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestSanitizeDenyMessageMaxRunes(t *testing.T) {
	var b []rune
	for i := 0; i < maxDenyMessageRunes+10; i++ {
		b = append(b, 'x')
	}
	got := SanitizeDenyMessage(string(b))
	if len([]rune(got)) != maxDenyMessageRunes {
		t.Fatalf("got %d runes, want %d", len([]rune(got)), maxDenyMessageRunes)
	}
}
