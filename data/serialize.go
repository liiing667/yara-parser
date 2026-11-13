// Functions and methods for reserializing the JSON into YARA rules.
// TODO: Handle indents better... Maybe have a global var denoting
// how many spaces to indent.
// TODO: Handle indents and formatting in general for conditions.
// Once conditions are treated as first-class vs. text, we can do that.

package data

import (
	"fmt"
	"strings"
)

// Serialize for RuleSet builds a complete YARA ruleset
func (rs *RuleSet) Serialize() (out string, err error) {
	var b strings.Builder

	if len(rs.Includes) > 0 {
		for _, include := range rs.Includes {
			b.WriteString("include \"")
			b.WriteString(EscapeYARALiteral(include))
			b.WriteString("\"\n")
		}
		b.WriteRune('\n')
	}
	if len(rs.Imports) > 0 {
		for _, imp := range rs.Imports {
			b.WriteString("import \"")
			b.WriteString(EscapeYARALiteral(imp))
			b.WriteString("\"\n")
		}
		b.WriteRune('\n')
	}

	for _, rule := range rs.Rules {
		str, err := rule.Serialize()
		if err != nil {
			return "", err
		}
		b.WriteString(str)
	}

	out = b.String()

	return
}

// Serialize for Rule builds a YARA rule as a string
func (r *Rule) Serialize() (out string, err error) {
	var b strings.Builder

	// Rule modifiers
	if r.Modifiers.Global {
		b.WriteString("global ")
	}
	if r.Modifiers.Private {
		b.WriteString("private ")
	}

	// Rule name
	b.WriteString(fmt.Sprintf("rule %s ", r.Identifier))

	// Any applicable tags
	if len(r.Tags) > 0 {
		b.WriteString(": ")
		for _, t := range r.Tags {
			b.WriteString(t)
			b.WriteRune(' ')
		}
	}

	// Start metas, strings, etc.
	b.WriteString("{\n")

	metas, err := r.Meta.Serialize()
	if err != nil {
		return
	}
	b.WriteString(metas)

	strs, err := r.Strings.Serialize()
	if err != nil {
		return
	}
	b.WriteString(strs)

	b.WriteString("condition:\n")
	b.WriteString("  ") // TODO: Don't assume indent...
	b.WriteString(r.Condition)
	b.WriteString("\n}\n\n")

	out = b.String()

	return
}

// Serialize for Metas returns the "meta:" section in the YARA rule
func (ms *Metas) Serialize() (out string, err error) {
	if ms == nil || len(*ms) == 0 {
		return
	}

	var b strings.Builder
	b.WriteString("meta:\n")

	for _, m := range *ms {
		meta, e := m.Serialize()
		if e != nil {
			err = e
			return
		}
		b.WriteString("  ") // TODO: make indent customizable
		b.WriteString(meta)
		b.WriteRune('\n')
	}

	out = b.String()
	return
}

// Serialize for Meta returns the string representation of the key/value pair
func (m *Meta) Serialize() (out string, err error) {
	switch val := m.Val.(type) {
	case string:
		out = fmt.Sprintf(`%s = "%s"`, m.Key, EscapeYARALiteral(val))

	case int64:
		out = fmt.Sprintf(`%s = %d`, m.Key, val)

	case Dec, Oct, Hex:
		out = fmt.Sprintf(`%s = %s`, m.Key, val)

	case bool:
		out = fmt.Sprintf(`%s = %v`, m.Key, val)

	case float64:
		// encoding/json decodes every number into float64. YARA meta only
		// accepts integers, so a whole-number float round-trips as an int.
		// Fractional values have no legal YARA representation.
		if val != float64(int64(val)) {
			err = fmt.Errorf("meta %q: YARA does not support fractional number %v", m.Key, val)
			return
		}
		out = fmt.Sprintf(`%s = %d`, m.Key, int64(val))

	default:
		err = fmt.Errorf(`Unsupported meta value type "%s"`, val)
	}

	return
}

// Serialize for Strings returns the "strings:" section in the YARA rule
func (ss *Strings) Serialize() (out string, err error) {
	if ss == nil || len(*ss) == 0 {
		return
	}

	var b strings.Builder
	b.WriteString("strings:\n")

	for _, s := range *ss {
		str, e := s.Serialize()
		if e != nil {
			err = e
			return
		}
		b.WriteString("  ") // TODO: Make indent customizable
		b.WriteString(str)
		b.WriteRune('\n')
	}

	out = b.String()
	return
}

// Serialize for String returns a String as a string
func (s *String) Serialize() (out string, err error) {
	// Format string for:
	// `<identifier> = <encapsOpen> <text> <encapsClose> <modifiers>`
	format := "%s = %s%s%s %s"

	var (
		encapsOpen  string
		encapsClose string
		text        = s.Text
	)
	switch t := s.Type; t {
	case TypeString:
		encapsOpen = `"`
		encapsClose = `"`
		text = EscapeYARALiteral(text)

	case TypeHexString:
		if s.Modifiers.Xor != nil {
			err = NewYARAError(ErrInvalidStringModifierCombo, "hex string with xor")
			return
		}
		encapsOpen, encapsClose = "{", "}"

	case TypeRegex:
		if s.Modifiers.Xor != nil {
			err = NewYARAError(ErrInvalidStringModifierCombo, "regex with xor")
			return
		}
		text = EscapeYARARegex(text)
		encapsOpen = "/"
		var closeBuilder strings.Builder
		closeBuilder.WriteRune('/')
		if s.Modifiers.I {
			closeBuilder.WriteRune('i')
		}
		if s.Modifiers.S {
			closeBuilder.WriteRune('s')
		}
		encapsClose = closeBuilder.String()

	default:
		err = fmt.Errorf("No such string type %s (%d)", t, t)
		return
	}

	mods, err := s.Modifiers.Serialize()
	if err != nil {
		return
	}

	out = fmt.Sprintf(format, s.ID, encapsOpen, text, encapsClose, mods)

	return
}

// Serialize for StringModifiers creates a space-sparated list of
// string modifiers, excluding the i and s which are appended to /regex/
// The returned error must be nil.
func (m *StringModifiers) Serialize() (out string, err error) {
	if err = m.Validate(); err != nil {
		return
	}

	const modsAvailable = 8
	modifiers := make([]string, 0, modsAvailable)
	if m.ASCII {
		modifiers = append(modifiers, "ascii")
	}
	if m.Wide {
		modifiers = append(modifiers, "wide")
	}
	if m.Nocase {
		modifiers = append(modifiers, "nocase")
	}
	if m.Fullword {
		modifiers = append(modifiers, "fullword")
	}
	if m.Private {
		modifiers = append(modifiers, "private")
	}
	if m.Xor != nil {
		var xor string
		xor, err = m.Xor.Serialize()
		if xor != "" && err == nil {
			modifiers = append(modifiers, xor)
		}
	}
	if m.Base64 != nil {
		var b64 string
		b64, err = m.Base64.serialize("base64")
		if err != nil {
			return
		}
		modifiers = append(modifiers, b64)
	}
	if m.Base64Wide != nil {
		var b64wide string
		b64wide, err = m.Base64Wide.serialize("base64wide")
		if err != nil {
			return
		}
		modifiers = append(modifiers, b64wide)
	}

	out = strings.Join(modifiers, " ")
	return
}

// serialize renders a base64-family modifier using the given keyword
// ("base64" or "base64wide"). A nil value yields an empty string and no
// error; a zero-length value yields the bare keyword; a 64-byte value is
// emitted as keyword("<alphabet>").
func (b64 Base64) serialize(keyword string) (out string, err error) {
	if b64 == nil {
		return
	}

	switch len(b64) {
	case 0:
		out = keyword
	case 64:
		out = fmt.Sprintf(`%s("%s")`, keyword, EscapeYARALiteral(string(b64)))
	default:
		err = fmt.Errorf(`%s modifier requires no alphabet or a 64-char alphabet`, keyword)
	}

	return
}

// Serialize for the base64 string modifier returns a representation depending
// on the provided alphabet. If the Base64 is nil, then the modifier is assumed
// to be not present, and an empty string is output. If the Base64 is
// zero-length, then the form of the modifier is assumed to be base64 without
// an alphabet. If the Base64 is not zero-length, it must be 64 bytes
// representing a 64-character alphabet
func (b64 Base64) Serialize() (out string, err error) {
	return b64.serialize("base64")
}

// Validate returns an error that can be unwrapped to
// ErrInvalidStringModifierCombo if an illegal combination of string modifiers
// is present
func (m *StringModifiers) Validate() error {
	if m.Nocase && m.Xor != nil {
		return NewYARAError(ErrInvalidStringModifierCombo, "xor, nocase")
	}

	return nil
}

// Serialize for Xor outputs the correct form of the xor modifier and verifies
// that any specified values are in range
func (xor Xor) Serialize() (out string, err error) {
	if xor == nil {
		// no action: blank string, no error
		return
	}

	switch len(xor) {
	case 0:
		out = "xor"
	case 1:
		out = fmt.Sprintf("xor(%s)", xor[0])
	case 2:
		out = fmt.Sprintf("xor(%s-%s)", xor[0], xor[1])
		if xor[0].Value() > xor[1].Value() {
			msg := fmt.Sprintf(`bad xor range (%s-%s)`, xor[0], xor[1])
			err = NewYARAError(ErrInvalidStringModifierCombo, msg)
		}
	default:
		msg := fmt.Sprintf(`"xor" modifier expects 0, 1, or 2 values; got %d`, xor)
		err = NewYARAError(err, msg)
	}

	if err == nil {
		for _, val := range xor {
			if val.Value() < 0 || val.Value() > 255 {
				msg := fmt.Sprintf(`"xor" modifier value must be in [0,255]; got %s`, val)
				err = NewYARAError(ErrInvalidStringModifierCombo, msg)
			}
		}
	}

	return
}
