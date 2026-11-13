package data

import (
	"fmt"
	"strings"
)

// Deterministic escaping for YARA text emitted by Serialize.
//
// The grammar stores the bodies of double-quoted strings and regular
// expressions in source form, i.e. exactly as they appear between the
// delimiters, including any backslash escape sequences. The helpers in this
// file turn arbitrary text (including text assembled programmatically from
// JSON) into source form that the YARA lexer can always load.
//
// The mapping is canonical and a fixed point: feeding the output back through
// the same helper leaves it unchanged. Text already written with valid YARA
// escapes is preserved verbatim, so rules produced by the parser round-trip
// without being rewritten.

// EscapeYARALiteral returns the body of a deterministic, parse-safe YARA
// double-quoted string, without the enclosing quotes. It applies to meta
// string values, plain text strings, include/import paths and base64
// alphabets.
//
// Valid YARA escapes (\t, \n, \", \\ and \xHH) are passed through unchanged.
// Raw quotes, backslashes, line breaks and other control bytes are encoded
// using the same escape vocabulary, which is the only one accepted by the
// grammar lexer.
func EscapeYARALiteral(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			switch next := s[i+1]; {
			case next == 't' || next == 'n' || next == '"' || next == '\\':
				b.WriteByte('\\')
				b.WriteByte(next)
				i += 2
			case next == 'x' && i+3 < len(s) && isHexDigit(s[i+2]) && isHexDigit(s[i+3]):
				b.WriteString(s[i : i+4])
				i += 4
			default:
				// Unknown or truncated escape: quote the raw backslash so no
				// illegal escape sequence reaches the lexer.
				b.WriteString(`\\`)
				i++
			}
			continue
		}

		switch c := s[i]; c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			// Lone trailing backslash.
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\x0d`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 || c == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, c)
			} else {
				b.WriteByte(c)
			}
		}
		i++
	}

	return b.String()
}

// EscapeYARARegex returns the body of a deterministic, parse-safe YARA regex,
// without the enclosing slashes. Regex escapes such as \. or \d are retained
// verbatim; only raw slashes, a lone trailing backslash and control bytes
// that would break the lexical grammar are encoded.
func EscapeYARARegex(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); {
		if s[i] == '\\' {
			// A backslash only forms a legal regex escape when followed by a
			// printable character. Before a control byte (e.g. a newline) it
			// is encoded as a lone backslash and the control byte is handled
			// on the next iteration.
			if i+1 < len(s) && s[i+1] >= 0x20 && s[i+1] != 0x7f {
				b.WriteByte('\\')
				b.WriteByte(s[i+1])
				i += 2
				continue
			}
			// Lone trailing backslash.
			b.WriteString(`\\`)
			i++
			continue
		}

		switch c := s[i]; c {
		case '/':
			b.WriteString(`\/`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\x0d`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 || c == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, c)
			} else {
				b.WriteByte(c)
			}
		}
		i++
	}

	return b.String()
}

// UnescapeYARALiteral decodes the body of a YARA double-quoted string using
// the same escape rules as the grammar lexer: \t, \n, \", \\ and \xHH. It
// exists so callers can recover the logical value of a serialized literal
// and verify round trips.
func UnescapeYARALiteral(s string) (string, error) {
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			i++
			continue
		}
		if i+1 >= len(s) {
			return "", fmt.Errorf("illegal escape sequence")
		}

		switch s[i+1] {
		case 't':
			b.WriteByte('\t')
			i += 2
		case 'n':
			b.WriteByte('\n')
			i += 2
		case '"':
			b.WriteByte('"')
			i += 2
		case '\\':
			b.WriteByte('\\')
			i += 2
		case 'x':
			if i+3 >= len(s) || !isHexDigit(s[i+2]) || !isHexDigit(s[i+3]) {
				return "", fmt.Errorf("illegal hex escape sequence")
			}
			var value byte
			if _, err := fmt.Sscanf(s[i+2:i+4], "%x", &value); err != nil {
				return "", fmt.Errorf("illegal hex escape sequence")
			}
			b.WriteByte(value)
			i += 4
		default:
			return "", fmt.Errorf("illegal escape sequence")
		}
	}

	return b.String(), nil
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F')
}
