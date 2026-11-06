// Package jobs shares directory restore planning between the CLI and web UI.
package jobs

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"filippo.io/age"
	"github.com/ramst/tbcrypt/internal/tbx"
)

// DecryptFile describes one input and its mirrored destination directory.
type DecryptFile struct{ Path, OutputDir string }

// PlanDecrypt snapshots all inputs before writing outputs, so restoring inside
// a source directory never recursively processes newly restored files.
func PlanDecrypt(ctx context.Context, sources []string, output string) ([]DecryptFile, error) {
	var plan []DecryptFile
	seen := make(map[string]bool)
	add := func(path, out string) {
		k, _ := filepath.Abs(path)
		if runtime.GOOS == "windows" {
			k = strings.ToLower(k)
		}
		if !seen[k] {
			seen[k] = true
			plan = append(plan, DecryptFile{path, out})
		}
	}
	for _, src := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		info, err := os.Lstat(src)
		if err != nil {
			return nil, err
		}
		if info.Mode().IsRegular() {
			add(src, output)
			continue
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("choose regular files or folders: %s", src)
		}
		err = filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if d.Type().IsRegular() && strings.EqualFold(filepath.Ext(path), ".tbx") {
				rel, err := filepath.Rel(src, filepath.Dir(path))
				if err != nil {
					return err
				}
				add(path, filepath.Join(output, rel))
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return plan, nil
}

// DecryptOne authenticates and publishes one planned restore.
func DecryptOne(ctx context.Context, file DecryptFile, id age.Identity) (string, error) {
	return tbx.DecryptFileContext(ctx, file.Path, file.OutputDir, id)
}
