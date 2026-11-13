package data

import "testing"

func TestEscapeYARALiteral(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "plain text", "plain text"},
		{"quote", `say "hi"`, `say \"hi\"`},
		{"backslash", `a\b`, `a\\b`},
		{"trailing backslash", `abc\`, `abc\\`},
		{"newline", "line1\nline2", `line1\nline2`},
		{"carriage return", "a\rb", `a\x0db`},
		{"tab", "a\tb", `a\tb`},
		{"nul", "a\x00b", `a\x00b`},
		{"del", "a\x7fb", `a\x7fb`},
		{"preserve escaped quote", `say \"hi\"`, `say \"hi\"`},
		{"preserve escaped backslash", `a\\b`, `a\\b`},
		{"preserve t n escapes", `a\tb\nc`, `a\tb\nc`},
		{"preserve hex escape", "a" + `\x41` + "b", "a" + `\x41` + "b"},
		{"truncated hex escape", `a\x4z`, `a\\x4z`},
		{"truncated hex escape at end", `a\x4`, `a\\x4`},
		{"illegal escape", `a\rb`, `a\\rb`},
		{"boundary mix", "\"\\\n\r\t\x01", `\"\\\n\x0d\t\x01`},
		{"unicode passthrough", "héllo→世界", "héllo→世界"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EscapeYARALiteral(tc.in)
			if got != tc.want {
				t.Fatalf("EscapeYARALiteral(%q) = %q; want %q", tc.in, got, tc.want)
			}
			// The mapping must be a fixed point.
			if again := EscapeYARALiteral(got); again != got {
				t.Fatalf("not idempotent: %q -> %q -> %q", tc.in, got, again)
			}
		})
	}
}

func TestEscapeYARARegex(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "abc.*", "abc.*"},
		{"raw slash", "a/b", `a\/b`},
		{"escaped slash preserved", `a\/b`, `a\/b`},
		{"regex escapes preserved", `\d+\.\w`, `\d+\.\w`},
		{"trailing backslash", `abc\`, `abc\\`},
		{"newline", "a\nb", `a\nb`},
		{"carriage return", "a\rb", `a\x0db`},
		{"nul", "a\x00b", `a\x00b`},
		{"boundary mix", "/\\\n\x00", `\/\\\n\x00`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EscapeYARARegex(tc.in)
			if got != tc.want {
				t.Fatalf("EscapeYARARegex(%q) = %q; want %q", tc.in, got, tc.want)
			}
			if again := EscapeYARARegex(got); again != got {
				t.Fatalf("not idempotent: %q -> %q -> %q", tc.in, got, again)
			}
		})
	}
}

func TestUnescapeYARALiteral(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"plain", "plain", "plain", false},
		{"escapes", `a\tb\nc\"d\\e`, "a\tb\nc\"d\\e", false},
		{"hex upper", `a\x41b`, "aAb", false},
		{"hex lower", `a\x0ab`, "a\nb", false},
		{"truncated hex", `a\x4`, "", true},
		{"bad hex", `a\xzzb`, "", true},
		{"illegal escape", `a\rb`, "", true},
		{"trailing backslash", `abc\`, "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UnescapeYARALiteral(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("UnescapeYARALiteral(%q) = %q; want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if got != tc.want {
				t.Fatalf("UnescapeYARALiteral(%q) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestEscapeUnescapeRoundTrip(t *testing.T) {
	// Values without backslashes are fully reversible at the logical level.
	// Backslash-containing source form is validated separately because the
	// YARA grammar stores string bodies in escaped source form.
	values := []string{
		"",
		"plain",
		`quote " inside`,
		"newline\nand\rcarriage\tand\x00nul",
		"mixed \"quotes\" and line breaks \n end",
		"unicode héllo 世界 \x7f",
	}

	for _, v := range values {
		encoded := EscapeYARALiteral(v)
		decoded, err := UnescapeYARALiteral(encoded)
		if err != nil {
			t.Fatalf("UnescapeYARALiteral(%q) error: %s", encoded, err)
		}
		if decoded != v {
			t.Fatalf("round trip failed for %q: encoded %q decoded %q", v, encoded, decoded)
		}
	}

	// Source-form values containing valid YARA escapes are a fixed point and
	// decode to their logical values.
	sourceForms := map[string]string{
		`back\\slash`:              `back\slash`,
		`already escaped \\\" val`: `already escaped \" val`,
		`a\tb\nc`:                  "a\tb\nc",
	}
	for encoded, want := range sourceForms {
		if again := EscapeYARALiteral(encoded); again != encoded {
			t.Fatalf("source form %q not a fixed point: %q", encoded, again)
		}
		got, err := UnescapeYARALiteral(encoded)
		if err != nil {
			t.Fatalf("UnescapeYARALiteral(%q) error: %s", encoded, err)
		}
		if got != want {
			t.Fatalf("source form %q decoded to %q; want %q", encoded, got, want)
		}
	}
}
