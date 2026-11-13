package tests

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Northern-Lights/yara-parser/data"
)

// boundaryValues are logical (unencoded) values containing every character
// class that can break a YARA double-quoted literal: quotes, backslashes,
// line breaks, tabs and other control bytes, plus valid and invalid escape
// sequences when treated as source text.
var boundaryValues = []string{
	``,
	`plain ascii`,
	`quote " inside`,
	`back\slash`,
	`trailing backslash\`,
	"newline\nand\rcarriage",
	"tab\tand\x00nul\x01and\x7fdel",
	`all together: "q" \ bs ` + "\n\t\r\x02 end",
}

// buildBoundaryRuleset assembles a ruleset whose components carry boundary
// characters in every place Serialize emits double-quoted text.
func buildBoundaryRuleset() data.RuleSet {
	metas := make(data.Metas, 0, len(boundaryValues))
	for _, v := range boundaryValues {
		metas = append(metas, data.Meta{
			Key: "k",
			Val: v,
		})
	}

	plain := make(data.Strings, 0, len(boundaryValues))
	for i, v := range boundaryValues {
		plain = append(plain, data.String{
			ID:   "$p",
			Type: data.TypeString,
			Text: v,
			Modifiers: data.StringModifiers{
				ASCII:    true,
				Wide:     i%2 == 0,
				Nocase:   i%3 == 0,
				Fullword: i%4 == 0,
			},
		})
	}

	// The anonymous "$" identifier may legally repeat.
	for i := range plain {
		plain[i].ID = "$"
	}

	regexes := data.Strings{
		{
			ID:   "$r1",
			Type: data.TypeRegex,
			Text: "a/b\\.c.*\n\td",
			Modifiers: data.StringModifiers{
				I:    true,
				Wide: true,
			},
		},
		{
			ID:   "$r2",
			Type: data.TypeRegex,
			Text: "trailing backslash\\",
			Modifiers: data.StringModifiers{
				S:       true,
				Private: true,
			},
		},
	}

	hexes := data.Strings{
		{
			ID:   "$h1",
			Type: data.TypeHexString,
			Text: " aa bb ?? cc [1-3] ( d0 | d1 ) ",
			Modifiers: data.StringModifiers{
				Private: true,
			},
		},
	}

	b64 := data.Strings{
		{
			ID:   "$b1",
			Type: data.TypeString,
			Text: "abcdefg",
			Modifiers: data.StringModifiers{
				Base64:     data.Base64{},
				Base64Wide: data.Base64(data.DefaultAlphabet),
			},
		},
		{
			ID:   "$b2",
			Type: data.TypeString,
			Text: "abcdefg",
			Modifiers: data.StringModifiers{
				Xor: data.Xor{data.Dec(1), data.Hex(0x0f)},
			},
		},
	}

	allStrings := make(data.Strings, 0, len(plain)+len(regexes)+len(hexes)+len(b64))
	allStrings = append(allStrings, plain...)
	allStrings = append(allStrings, regexes...)
	allStrings = append(allStrings, hexes...)
	allStrings = append(allStrings, b64...)

	return data.RuleSet{
		File:     "boundary.yar",
		Includes: []string{`./inc "quote".yar`, `back\slash.yar`},
		Imports:  []string{`pe`, `path with "quote"`},
		Rules: []data.Rule{
			{
				Modifiers:  data.RuleModifiers{Global: true, Private: true},
				Identifier: "BOUNDARY",
				Tags:       []string{"tag1", "tag2"},
				Meta:       metas,
				Strings:    allStrings,
				Condition:  `$r1 and pe.name == "demo"`,
			},
		},
	}
}

// TestSerializeBoundaryRoundTrip verifies that a ruleset carrying quotes,
// backslashes, line breaks and control bytes serializes into YARA that the
// grammar can load again, with logical values preserved.
func TestSerializeBoundaryRoundTrip(t *testing.T) {
	original := buildBoundaryRuleset()

	yara1, err := original.Serialize()
	if err != nil {
		t.Fatalf("first Serialize failed: %s", err)
	}

	parsed, err := parseRuleStr(yara1)
	if err != nil {
		t.Fatalf("serialized YARA does not parse:\n%s\nerror: %s", yara1, err)
	}

	// Includes and imports round-trip at source-form level.
	wantIncludes := make([]string, len(original.Includes))
	for i, inc := range original.Includes {
		wantIncludes[i] = data.EscapeYARALiteral(inc)
	}
	if got := parsed.Includes; !reflect.DeepEqual(got, wantIncludes) {
		t.Fatalf("includes mismatch:\n got %q\nwant %q", got, wantIncludes)
	}
	wantImports := make([]string, len(original.Imports))
	for i, imp := range original.Imports {
		wantImports[i] = data.EscapeYARALiteral(imp)
	}
	if got := parsed.Imports; !reflect.DeepEqual(got, wantImports) {
		t.Fatalf("imports mismatch:\n got %q\nwant %q", got, wantImports)
	}

	rule := parsed.Rules[0]
	if rule.Identifier != "BOUNDARY" || !rule.Modifiers.Global || !rule.Modifiers.Private {
		t.Fatalf("rule header not preserved: %+v", rule)
	}
	if !reflect.DeepEqual(rule.Tags, []string{"tag1", "tag2"}) {
		t.Fatalf("tags not preserved: %v", rule.Tags)
	}
	if rule.Condition != original.Rules[0].Condition {
		t.Fatalf("condition text not preserved:\n got %q\nwant %q",
			rule.Condition, original.Rules[0].Condition)
	}

	// Meta values must decode back to the original logical values.
	if len(rule.Meta) != len(boundaryValues) {
		t.Fatalf("meta count = %d; want %d", len(rule.Meta), len(boundaryValues))
	}
	for i, m := range rule.Meta {
		got, ok := m.Val.(string)
		if !ok {
			t.Fatalf("meta %d is not a string: %T", i, m.Val)
		}
		decoded, err := data.UnescapeYARALiteral(got)
		if err != nil {
			t.Fatalf("meta %d unescape %q failed: %s", i, got, err)
		}
		if decoded != boundaryValues[i] {
			t.Fatalf("meta %d mismatch:\n got %q\nwant %q", i, decoded, boundaryValues[i])
		}
	}

	// Plain strings must decode back to the original logical values.
	var plainGot data.Strings
	for _, s := range rule.Strings {
		if s.Type == data.TypeString && s.Modifiers.Base64 == nil && s.Modifiers.Xor == nil {
			plainGot = append(plainGot, s)
		}
	}
	if len(plainGot) != len(boundaryValues) {
		t.Fatalf("plain string count = %d; want %d", len(plainGot), len(boundaryValues))
	}
	for i, s := range plainGot {
		decoded, err := data.UnescapeYARALiteral(s.Text)
		if err != nil {
			t.Fatalf("string %d unescape %q failed: %s", i, s.Text, err)
		}
		if decoded != boundaryValues[i] {
			t.Fatalf("string %d mismatch:\n got %q\nwant %q", i, decoded, boundaryValues[i])
		}
	}

	// Regex source text is preserved verbatim because the input already
	// contains valid regex escapes.
	regexByID := map[string]data.String{}
	for _, s := range rule.Strings {
		if s.Type == data.TypeRegex {
			regexByID[s.ID] = s
		}
	}
	if got := regexByID["$r1"].Text; got != `a\/b\.c.*\n\td` {
		t.Fatalf("regex r1 text = %q; want %q", got, `a\/b\.c.*\n\td`)
	}
	if !regexByID["$r1"].Modifiers.I || !regexByID["$r1"].Modifiers.Wide {
		t.Fatalf("regex r1 modifiers not preserved: %+v", regexByID["$r1"].Modifiers)
	}
	if got := regexByID["$r2"].Text; got != `trailing backslash\\` {
		t.Fatalf("regex r2 text = %q; want %q", got, `trailing backslash\\`)
	}

	// Hex strings and their source text are passed through untouched.
	var hexGot *data.String
	for i := range rule.Strings {
		if rule.Strings[i].Type == data.TypeHexString {
			hexGot = &rule.Strings[i]
			break
		}
	}
	if hexGot == nil {
		t.Fatal("hex string missing after round trip")
	}
	if hexGot.Text != original.Rules[0].Strings[len(plainGot)+2].Text {
		t.Fatalf("hex text mismatch:\n got %q\nwant %q",
			hexGot.Text, original.Rules[0].Strings[len(plainGot)+2].Text)
	}
}

// TestSerializeDeterministicAndFixedPoint ensures repeated serialization is
// byte-identical and that serializing a re-parsed ruleset yields the same
// YARA text.
func TestSerializeDeterministicAndFixedPoint(t *testing.T) {
	original := buildBoundaryRuleset()

	yara1, err := original.Serialize()
	if err != nil {
		t.Fatalf("first Serialize failed: %s", err)
	}
	yara1Again, err := original.Serialize()
	if err != nil {
		t.Fatalf("second Serialize failed: %s", err)
	}
	if yara1 != yara1Again {
		t.Fatal("serialization is not deterministic")
	}

	parsed, err := parseRuleStr(yara1)
	if err != nil {
		t.Fatalf("serialized YARA does not parse: %s", err)
	}
	yara2, err := parsed.Serialize()
	if err != nil {
		t.Fatalf("re-serialization failed: %s", err)
	}
	if yara1 != yara2 {
		t.Fatalf("not a fixed point:\n--- first ---\n%s\n--- second ---\n%s", yara1, yara2)
	}
}

// TestSerializeEscapedSourcePreserved verifies that valid escapes present in
// hand-written YARA source are preserved instead of being double-escaped.
func TestSerializeEscapedSourcePreserved(t *testing.T) {
	const source = `
include "a\\\"b.yar"

rule ESCAPES {
meta:
    m = "tab\there quote\"here back\\here hex\x41here newline\nhere"
strings:
    $s1 = "say \"hi\" \\ end"
    $r1 = /a\/b\\c\./is
    $h1 = { aa bb ?? cc }
condition:
    $s1 and $r1 and $h1
}
`

	rs, err := parseRuleStr(source)
	if err != nil {
		t.Fatalf("source fixture does not parse: %s", err)
	}

	out, err := rs.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %s", err)
	}

	for _, fragment := range []string{
		`include "a\\\"b.yar"`,
		`m = "tab\there quote\"here back\\here hex\x41here newline\nhere"`,
		`$s1 = "say \"hi\" \\ end"`,
		`$r1 = /a\/b\\c\./is`,
		`$h1 = { aa bb ?? cc }`,
	} {
		if !strings.Contains(out, fragment) {
			t.Fatalf("serialized output missing fragment %q:\n%s", fragment, out)
		}
	}

	// The re-serialized output must itself be loadable and fixed point.
	reparsed, err := parseRuleStr(out)
	if err != nil {
		t.Fatalf("serialized output does not parse: %s", err)
	}
	out2, err := reparsed.Serialize()
	if err != nil {
		t.Fatalf("second Serialize failed: %s", err)
	}
	if out != out2 {
		t.Fatalf("escaped source is not a fixed point:\n--- first ---\n%s\n--- second ---\n%s", out, out2)
	}
}

// TestSerializeIncludeImportEscaping ensures raw boundary characters in
// include/import paths are encoded instead of breaking the file syntax.
func TestSerializeIncludeImportEscaping(t *testing.T) {
	rs := data.RuleSet{
		Includes: []string{"path with \"quote\"", "back\\slash"},
		Imports:  []string{"line\nbreak"},
		Rules: []data.Rule{
			{
				Identifier: "R",
				Condition:  "true",
			},
		},
	}

	out, err := rs.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %s", err)
	}

	for _, fragment := range []string{
		`include "path with \"quote\""`,
		`include "back\\slash"`,
		`import "line\nbreak"`,
	} {
		if !strings.Contains(out, fragment) {
			t.Fatalf("output missing %q:\n%s", fragment, out)
		}
	}

	if _, err := parseRuleStr(out); err != nil {
		t.Fatalf("serialized output does not parse: %s", err)
	}
}
