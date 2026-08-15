package web

import (
	"embed"
	"io/fs"
)

//go:embed dist/*
var distFS embed.FS

// FS returns the sub-filesystem pointing to dist.
func FS() (fs.FS, error) {
	return fs.Sub(distFS, "dist")
}
