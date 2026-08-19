package web

import "io/fs"

// Assets returns the dashboard's static files (index.html, app.js,
// style.css) rooted at their web path, for Wails' AssetServer to host
// inside the native window.
func Assets() (fs.FS, error) {
	return fs.Sub(staticFiles, "static")
}
