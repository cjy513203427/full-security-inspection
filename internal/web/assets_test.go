package web

import "testing"

// A broken go:embed path or a deleted static file would silently produce
// an empty/incomplete FS that only fails at runtime inside the WebView2
// window — catch it at build/test time instead.
func TestAssetsContainDashboard(t *testing.T) {
	fsys, err := Assets()
	if err != nil {
		t.Fatalf("Assets: %v", err)
	}
	for _, name := range []string{"index.html", "app.js", "style.css"} {
		f, err := fsys.Open(name)
		if err != nil {
			t.Fatalf("expected %s to be embedded, got error: %v", name, err)
		}
		f.Close()
	}
}
