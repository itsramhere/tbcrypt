// Package strip creates private temporary copies and removes metadata if possible.
package strip

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/itsramhere/tbcrypt/internal/fsutil"
)

// Warning reports unavailable metadata removal; CleanPath remains usable.
type Warning struct{ Err error }

// Error describes the non-fatal metadata-removal failure.
func (w *Warning) Error() string { return "metadata was not stripped: " + w.Err.Error() }

// Unwrap exposes the underlying exiftool error.
func (w *Warning) Unwrap() error { return w.Err }

// Strip copies srcPath to tmpDir, then runs exiftool on the copy only.
// Callers own and must remove cleanPath even when a Warning is returned.
func Strip(ctx context.Context, exiftoolPath, srcPath, tmpDir string) (cleanPath string, stripped bool, err error) {
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		return "", false, err
	}
	in, err := os.Open(srcPath)
	if err != nil {
		return "", false, err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return "", false, err
	}
	if !info.Mode().IsRegular() {
		return "", false, fmt.Errorf("source is not a regular file")
	}
	out, err := os.CreateTemp(tmpDir, "tbcrypt-*"+filepath.Ext(srcPath))
	if err != nil {
		return "", false, err
	}
	cleanPath = out.Name()
	defer func() {
		out.Close()
		if err != nil {
			if _, ok := err.(*Warning); !ok {
				os.Remove(cleanPath)
				cleanPath = ""
			}
		}
	}()
	if _, err = io.Copy(out, fsutil.Reader{Context: ctx, Source: in}); err != nil {
		return cleanPath, false, err
	}
	if err = out.Close(); err != nil {
		return cleanPath, false, err
	}
	if exiftoolPath == "" {
		return cleanPath, false, &Warning{fmt.Errorf("exiftool not found")}
	}
	cmd := exec.CommandContext(ctx, exiftoolPath, "-all=", "-tagsFromFile", "@", "-Orientation", "-ColorSpaceTags", "-overwrite_original", "-q", "-q", "-api", "LargeFileSupport=1", cleanPath)
	hideWindow(cmd)
	if runErr := cmd.Run(); runErr != nil {
		if ctx.Err() != nil {
			return cleanPath, false, ctx.Err()
		}
		// A failed exiftool may have partially modified its input. Restore the copy.
		if _, err = in.Seek(0, io.SeekStart); err != nil {
			return cleanPath, false, err
		}
		restore, openErr := os.OpenFile(cleanPath, os.O_WRONLY|os.O_TRUNC, 0600)
		if openErr != nil {
			return cleanPath, false, openErr
		}
		_, err = io.Copy(restore, fsutil.Reader{Context: ctx, Source: in})
		closeErr := restore.Close()
		if err != nil {
			return cleanPath, false, err
		}
		if closeErr != nil {
			return cleanPath, false, closeErr
		}
		return cleanPath, false, &Warning{runErr}
	}
	return cleanPath, true, nil
}
