package web

import "embed"

// staticFiles holds the dashboard's HTML/CSS/JS, compiled directly into the
// exe so the whole tool ships as a single file with no external assets.
//
//go:embed static/*
var staticFiles embed.FS
