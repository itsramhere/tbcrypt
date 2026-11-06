// Package tbx streams authenticated TBX1 containers using age encryption.
package tbx

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	"filippo.io/age"
	"github.com/itsramhere/tbcrypt/internal/fsutil"
)

const magic = "TBX1\n"
const maxHeader = 64 * 1024

// Container errors can be tested with errors.Is.
var (
	ErrNotTBX   = errors.New("not a TBX1 container")
	ErrWrongKey = errors.New("no matching identity")
	ErrCorrupt  = errors.New("corrupt TBX1 container")
)

// Header describes the original name and the exact decrypted byte count.
type Header struct {
	V    int    `json:"v"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// Encrypt writes a TBX1 container without buffering file contents.
func Encrypt(dst io.Writer, src io.Reader, name string, size int64, r age.Recipient) error {
	if size < 0 || r == nil {
		return errors.New("invalid encryption parameters")
	}
	h, err := json.Marshal(Header{1, name, size})
	if err != nil {
		return err
	}
	if len(h) > maxHeader {
		return errors.New("header too large")
	}
	if _, err := io.WriteString(dst, magic); err != nil {
		return err
	}
	w, err := age.Encrypt(dst, r)
	if err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(h))); err != nil {
		return err
	}
	if _, err := w.Write(h); err != nil {
		return err
	}
	n, err := io.Copy(w, src)
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("source size changed: expected %d, got %d", size, n)
	}
	return w.Close()
}

func start(src io.Reader, id age.Identity) (io.Reader, Header, error) {
	var h Header
	var prefix [5]byte
	if _, err := io.ReadFull(src, prefix[:]); err != nil || string(prefix[:]) != magic {
		return nil, h, ErrNotTBX
	}
	if id == nil {
		return nil, h, errors.New("identity required")
	}
	plain, err := age.Decrypt(src, id)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, h, fmt.Errorf("%w: %w", ErrWrongKey, err)
		}
		return nil, h, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	var length uint32
	if err := binary.Read(plain, binary.BigEndian, &length); err != nil {
		return nil, h, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	if length == 0 || length > maxHeader {
		return nil, h, fmt.Errorf("%w: invalid header length", ErrCorrupt)
	}
	b := make([]byte, int(length))
	if _, err := io.ReadFull(plain, b); err != nil {
		return nil, h, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, h, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	if h.V != 1 || h.Size < 0 {
		return nil, h, fmt.Errorf("%w: invalid header", ErrCorrupt)
	}
	return plain, h, nil
}

// Decrypt authenticates the full stream, including its end, and checks its size.
// On error dst may contain partial plaintext; file callers must use a temp file.
func Decrypt(dst io.Writer, src io.Reader, id age.Identity) (Header, error) {
	plain, h, err := start(src, id)
	if err != nil {
		return h, err
	}
	n, err := io.Copy(dst, plain)
	if err != nil {
		return h, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	if n != h.Size {
		return h, fmt.Errorf("%w: size is %d, expected %d", ErrCorrupt, n, h.Size)
	}
	return h, nil
}

// ReadHeader decrypts only the beginning; it does not verify the entire file.
func ReadHeader(src io.Reader, id age.Identity) (Header, error) {
	_, h, err := start(src, id)
	return h, err
}

func cleanName(name string) string {
	// path.Base treats normalized separators consistently without interpreting a
	// colon as a Windows drive prefix ("x:y" must sanitize to "xy").
	name = path.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || strings.ContainsRune("<>:\"/\\|?*", r) {
			return -1
		}
		return r
	}, name)
	name = strings.TrimRight(name, ". ")
	if name == "" || name == "." || name == ".." {
		return ""
	}
	stem := strings.ToUpper(strings.TrimRight(strings.SplitN(name, ".", 2)[0], " "))
	if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || (len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '1' && stem[3] <= '9') {
		return ""
	}
	return name
}

// SanitizeName removes traversal, control characters and Windows special names.
// The fallback is sanitized too; "file" is used if both names are invalid.
func SanitizeName(name, fallback string) string {
	if n := cleanName(name); n != "" {
		return n
	}
	if n := cleanName(fallback); n != "" {
		return n
	}
	return "file"
}

// EncryptFile exclusively creates dstPath via dstPath.part and a final rename.
func EncryptFile(srcPath, dstPath, name string, r age.Recipient) (err error) {
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("source is not a regular file")
	}
	if _, err = fsutil.Reserve(dstPath, false); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(dstPath)
		}
	}()
	return encryptReserved(in, info.Size(), dstPath, name, r)
}

func encryptReserved(src io.Reader, size int64, dstPath, name string, r age.Recipient) (err error) {
	f, err := os.OpenFile(dstPath+".part", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { f.Close(); os.Remove(f.Name()) }()
	if err = Encrypt(f, src, name, size, r); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), dstPath)
}

// EncryptUnique streams to a uniquely named destination and returns its path.
// The caller supplies the exact source size and may wrap src for cancellation.
func EncryptUnique(dstPath, name string, size int64, src io.Reader, r age.Recipient) (path string, err error) {
	path, err = fsutil.Reserve(dstPath, true)
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			os.Remove(path)
		}
	}()
	err = encryptReserved(src, size, path, name, r)
	return path, err
}

// DecryptFile publishes verified plaintext at a sanitized, unique output path.
func DecryptFile(srcPath, outDir string, id age.Identity) (outPath string, err error) {
	return DecryptFileContext(context.Background(), srcPath, outDir, id)
}

// DecryptFileContext cancels between reads and removes owned partial output.
func DecryptFileContext(ctx context.Context, srcPath, outDir string, id age.Identity) (outPath string, err error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	in, err := os.Open(srcPath)
	if err != nil {
		return "", err
	}
	defer in.Close()
	reader := fsutil.Reader{Context: ctx, Source: in}
	h, err := ReadHeader(reader, id)
	if err != nil {
		return "", err
	}
	if _, err = in.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	if err = os.MkdirAll(outDir, 0700); err != nil {
		return "", err
	}
	fallback := strings.TrimSuffix(filepath.Base(srcPath), filepath.Ext(srcPath))
	outPath, err = fsutil.Reserve(filepath.Join(outDir, SanitizeName(h.Name, fallback)), true)
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			os.Remove(outPath)
		}
	}()
	f, err := os.OpenFile(outPath+".part", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return outPath, err
	}
	defer func() { f.Close(); os.Remove(f.Name()) }()
	if _, err = Decrypt(f, reader, id); err != nil {
		return outPath, err
	}
	if err = f.Sync(); err != nil {
		return outPath, err
	}
	if err = f.Close(); err != nil {
		return outPath, err
	}
	if err = ctx.Err(); err != nil {
		return outPath, err
	}
	err = os.Rename(f.Name(), outPath)
	return outPath, err
}
