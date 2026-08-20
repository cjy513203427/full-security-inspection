package i18n

import (
	"regexp"
	"testing"
)

// Every catalog key must carry a translation for every supported language.
// A key with, say, only ZH+EN would silently fall back to English for
// German at runtime — this catches that at build time instead.
func TestCatalogHasAllLanguagesForEveryKey(t *testing.T) {
	want := []Lang{ZH, EN, DE}
	for key, variants := range catalog {
		for _, l := range want {
			if _, ok := variants[l]; !ok {
				t.Errorf("catalog key %q is missing a %s translation", key, l)
			}
		}
		if len(variants) != len(want) {
			t.Errorf("catalog key %q has %d language(s), want exactly %d (an unexpected Lang constant?)", key, len(variants), len(want))
		}
	}
}

// argIndexPattern matches Go fmt's explicit-argument-index verbs, e.g.
// "%[2]d" or "%[1].0f" — the whole point of using them in this catalog (see
// catalog.go's doc comment) is letting a translation reorder words relative
// to the source Chinese, but that only stays correct if every language's
// template references the *same set* of argument indices. A translation
// that drops one (or introduces one the others don't have) either silently
// loses information or panics at Sprintf time — this test catches it before
// either happens at runtime.
var argIndexPattern = regexp.MustCompile(`%\[(\d+)\]`)

func TestCatalogArgIndicesMatchAcrossLanguages(t *testing.T) {
	for key, variants := range catalog {
		var zhIdx map[string]bool
		for _, l := range []Lang{ZH, EN, DE} {
			tmpl, ok := variants[l]
			if !ok {
				continue // already reported by TestCatalogHasAllLanguagesForEveryKey
			}
			idx := indexSet(tmpl)
			if l == ZH {
				zhIdx = idx
				continue
			}
			if !sameSet(idx, zhIdx) {
				t.Errorf("catalog key %q: %s argument indices %v don't match zh's %v", key, l, sortedKeys(idx), sortedKeys(zhIdx))
			}
		}
	}
}

func indexSet(tmpl string) map[string]bool {
	out := map[string]bool{}
	for _, m := range argIndexPattern.FindAllStringSubmatch(tmpl, -1) {
		out[m[1]] = true
	}
	return out
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestParseLang(t *testing.T) {
	cases := []struct {
		in   string
		want Lang
		ok   bool
	}{
		{"zh", ZH, true},
		{"EN", EN, true},
		{" de ", DE, true},
		{"fr", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := ParseLang(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("ParseLang(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestT_FormatsAndFallsBack(t *testing.T) {
	prev := Current()
	defer SetSession(prev)

	SetSession(EN)
	if got := T("category.password"); got != "password" {
		t.Errorf("T(category.password) in EN = %q, want %q", got, "password")
	}

	SetSession(DE)
	if got := T("category.password"); got != "Passwort" {
		t.Errorf("T(category.password) in DE = %q, want %q", got, "Passwort")
	}

	// A key that genuinely doesn't exist degrades to the bare key rather
	// than panicking or returning an empty string.
	if got := T("no.such.key"); got != "no.such.key" {
		t.Errorf("T(no.such.key) = %q, want the bare key back", got)
	}

	// Formatting actually substitutes args.
	SetSession(EN)
	if got := T("target.browser_cookies", "Chrome"); got != "Chrome Cookies Database" {
		t.Errorf("T(target.browser_cookies, Chrome) = %q, want %q", got, "Chrome Cookies Database")
	}
}

// SetSession/Set must reject nonsense rather than silently leaving the
// language unchanged with no signal to the caller.
func TestSetSession_InvalidFallsBackToEnglish(t *testing.T) {
	prev := Current()
	defer SetSession(prev)

	SetSession(ZH)
	SetSession(Lang("xx"))
	if Current() != EN {
		t.Errorf("SetSession with an invalid Lang = %v, want fallback to EN", Current())
	}
}
