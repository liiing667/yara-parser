package data

import (
	"strings"
	"testing"
)

func TestMetaSerializeFloat(t *testing.T) {
	t.Run("whole number from JSON", func(t *testing.T) {
		m := Meta{Key: "n", Val: float64(7)}
		got, err := m.Serialize()
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if want := `n = 7`; got != want {
			t.Fatalf("got %q; want %q", got, want)
		}
	})

	t.Run("fractional value unsupported", func(t *testing.T) {
		m := Meta{Key: "n", Val: 7.5}
		if _, err := m.Serialize(); err == nil {
			t.Fatal("fractional float should be rejected")
		}
	})
}

func TestMetaSerializeEscaping(t *testing.T) {
	m := Meta{Key: "k", Val: "quote \" back\\ new\n nul\x00"}
	got, err := m.Serialize()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if want := `k = "quote \" back\\ new\n nul\x00"`; got != want {
		t.Fatalf("got %q; want %q", got, want)
	}
}

func TestBase64WideSerialize(t *testing.T) {
	m := StringModifiers{
		Base64:     Base64{},
		Base64Wide: Base64(DefaultAlphabet),
	}
	got, err := m.Serialize()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !strings.Contains(got, "base64 ") {
		t.Fatalf("missing base64 modifier in %q", got)
	}
	if !strings.Contains(got, `base64wide("`+DefaultAlphabet+`")`) {
		t.Fatalf("missing base64wide modifier in %q", got)
	}
}

func TestRuleSetSerializeEscaping(t *testing.T) {
	rs := RuleSet{
		Includes: []string{`a"b\c` + "\n"},
		Imports:  []string{"pe"},
		Rules: []Rule{
			{Identifier: "R", Condition: "true"},
		},
	}
	got, err := rs.Serialize()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !strings.Contains(got, `include "a\"b\\c\n"`) {
		t.Fatalf("include path not escaped in:\n%s", got)
	}
	if !strings.Contains(got, `import "pe"`) {
		t.Fatalf("import missing in:\n%s", got)
	}
}
