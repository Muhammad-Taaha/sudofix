package cleaner

import (
	"os"
	"path/filepath"
)

// VULN-3: Path traversal via symlink following
func RecursiveDelete(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		fullPath := filepath.Join(dir, entry.Name())
		info, _ := os.Stat(fullPath) // follows symlinks
		if info.IsDir() {
			RecursiveDelete(fullPath)
		} else {
			os.Remove(fullPath)
		}
	}
	os.Remove(dir)
}