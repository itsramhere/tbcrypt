package strip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ramst/tbcrypt/internal/config"
)

// Reuse this test executable as a fake exiftool, without a shell or compiler.
func TestMain(m *testing.M) {
	if mode := os.Getenv("TBCRYPT_TEST_EXIFTOOL"); mode != "" {
		if len(os.Args) != 12 || !reflect.DeepEqual(os.Args[1:11], []string{"-all=", "-tagsFromFile", "@", "-Orientation", "-ColorSpaceTags", "-overwrite_original", "-q", "-q", "-api", "LargeFileSupport=1"}) {
			os.Exit(2)
		}
		if err := os.WriteFile(os.Args[11], []byte("changed by exiftool"), 0600); err != nil {
			os.Exit(3)
		}
		if mode == "fail" {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestExiftoolSubprocess(t *testing.T) {
	tool, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "fail"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("TBCRYPT_TEST_EXIFTOOL", mode)
			dir := t.TempDir()
			src := filepath.Join(dir, "original.jpg")
			original := []byte("unmodified original")
			if err := os.WriteFile(src, original, 0600); err != nil {
				t.Fatal(err)
			}
			clean, stripped, err := Strip(context.Background(), tool, src, filepath.Join(dir, "tmp"))
			if clean != "" {
				defer os.Remove(clean)
			}
			var warning *Warning
			want := []byte("changed by exiftool")
			if mode == "fail" {
				if stripped || !errors.As(err, &warning) {
					t.Fatalf("failure: %v %v", stripped, err)
				}
				want = original
			} else if err != nil || !stripped {
				t.Fatalf("success: %v %v", stripped, err)
			}
			got, err := os.ReadFile(clean)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("copy: %q %v", got, err)
			}
			got, err = os.ReadFile(src)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatal("original was changed")
			}
		})
	}
}

func TestUnmodifiedCopyWithoutExiftool(t *testing.T) {
	for _, tool := range []string{"", filepath.Join(t.TempDir(), "missing-exiftool.exe")} {
		t.Run(tool, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "original.jpg")
			data := []byte("original data")
			if err := os.WriteFile(src, data, 0600); err != nil {
				t.Fatal(err)
			}
			clean, stripped, err := Strip(context.Background(), tool, src, filepath.Join(dir, "tmp"))
			var warning *Warning
			if stripped || !errors.As(err, &warning) {
				t.Fatalf("got %v %v", stripped, err)
			}
			defer os.Remove(clean)
			if clean == src || filepath.Ext(clean) != ".jpg" {
				t.Fatalf("not a separate matching-extension file: %s", clean)
			}
			copyData, err := os.ReadFile(clean)
			if err != nil || !bytes.Equal(copyData, data) {
				t.Fatalf("copy: %v", err)
			}
			original, err := os.ReadFile(src)
			if err != nil || !bytes.Equal(original, data) {
				t.Fatalf("original changed: %v", err)
			}
		})
	}
}

func TestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	clean, _, err := Strip(ctx, "", "missing", t.TempDir())
	if !errors.Is(err, context.Canceled) || clean != "" {
		t.Fatalf("%s %v", clean, err)
	}
}

func TestExiftool(t *testing.T) {
	tool := config.FindExiftool(config.Config{})
	if tool == "" {
		t.Skip("exiftool not installed")
	}
	// A PATH entry can exist while its external interpreter is unavailable or
	// blocked by the test sandbox. Distinguish that from a stripping regression.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	version := exec.CommandContext(ctx, tool, "-ver")
	hideWindow(version)
	if output, err := version.CombinedOutput(); err != nil {
		t.Skipf("exiftool cannot run in this environment: %v: %s", err, output)
	}
	// A one-pixel PNG with a removable tEXt chunk, generated without external tools.
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	var chunk bytes.Buffer
	metadata := []byte("Comment\x00tbcrypt-private-metadata")
	binary.Write(&chunk, binary.BigEndian, uint32(len(metadata)))
	chunk.WriteString("tEXt")
	chunk.Write(metadata)
	binary.Write(&chunk, binary.BigEndian, crc32.ChecksumIEEE(chunk.Bytes()[4:]))
	// Insert the ancillary chunk before the final 12-byte IEND chunk.
	imageBytes := encoded.Bytes()
	data := append(bytes.Clone(imageBytes[:len(imageBytes)-12]), chunk.Bytes()...)
	data = append(data, imageBytes[len(imageBytes)-12:]...)
	src := filepath.Join(t.TempDir(), "image.png")
	if err := os.WriteFile(src, data, 0600); err != nil {
		t.Fatal(err)
	}
	clean, stripped, err := Strip(context.Background(), tool, src, t.TempDir())
	if clean != "" {
		defer os.Remove(clean)
	}
	if err != nil || !stripped {
		t.Fatalf("strip: %v %v", stripped, err)
	}
	cleanBytes, err := os.ReadFile(clean)
	if err != nil || bytes.Contains(cleanBytes, metadata) {
		t.Fatalf("metadata not removed: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(cleanBytes)); err != nil {
		t.Fatalf("stripped image is invalid: %v", err)
	}
	original, _ := os.ReadFile(src)
	if !bytes.Equal(original, data) {
		t.Fatal("original changed")
	}
}
