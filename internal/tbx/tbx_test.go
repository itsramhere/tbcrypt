package tbx

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func identity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func encrypted(t *testing.T, data []byte, id *age.X25519Identity) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := Encrypt(&b, bytes.NewReader(data), "photo.jpg", int64(len(data)), id.Recipient()); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestRoundTrip(t *testing.T) {
	id := identity(t)
	for _, size := range []int{0, 1, 65535, 65536, 65537, 5*1024*1024 + 17} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			data := make([]byte, size)
			if _, err := rand.Read(data); err != nil {
				t.Fatal(err)
			}
			enc := encrypted(t, data, id)
			var out bytes.Buffer
			h, err := Decrypt(&out, bytes.NewReader(enc), id)
			if err != nil {
				t.Fatal(err)
			}
			if h != (Header{1, "photo.jpg", int64(size)}) || !bytes.Equal(out.Bytes(), data) {
				t.Fatal("round trip mismatch")
			}
			first, err := ReadHeader(bytes.NewReader(enc), id)
			if err != nil || first != h {
				t.Fatalf("header: %+v %v", first, err)
			}
		})
	}
}

func TestWrongKeyAndDamage(t *testing.T) {
	id := identity(t)
	data := make([]byte, 200000)
	rand.Read(data)
	good := encrypted(t, data, id)
	_, err := Decrypt(io.Discard, bytes.NewReader(good), identity(t))
	var match *age.NoIdentityMatchError
	if !errors.Is(err, ErrWrongKey) || !errors.As(err, &match) {
		t.Fatalf("wrong key error: %v", err)
	}
	cases := map[string][]byte{}
	for name, pos := range map[string]int{"magic": 1, "age-header": 10, "middle": len(good) / 2, "last": len(good) - 1} {
		b := bytes.Clone(good)
		b[pos] ^= 0x40
		cases[name] = b
	}
	cases["truncate-one"] = good[:len(good)-1]
	cases["truncate-half"] = good[:len(good)/2]
	cases["append"] = append(bytes.Clone(good), []byte("garbage")...)
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Decrypt(io.Discard, bytes.NewReader(b), id)
			if err == nil {
				t.Fatal("accepted damaged ciphertext")
			}
			if name == "magic" {
				if !errors.Is(err, ErrNotTBX) {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrWrongKey) {
				t.Fatal(err)
			}
		})
	}
}

func TestMalformedPlaintext(t *testing.T) {
	id := identity(t)
	for _, tc := range []struct {
		name   string
		length uint32
		header string
		data   string
	}{
		{"oversize", maxHeader + 1, "", ""}, {"empty", 0, "", ""}, {"invalid-json", 1, "{", ""},
		{"version", len32(`{"v":2,"size":0}`), `{"v":2,"size":0}`, ""},
		{"negative", len32(`{"v":1,"size":-1}`), `{"v":1,"size":-1}`, ""},
		{"short", len32(`{"v":1,"size":2}`), `{"v":1,"size":2}`, "x"},
		{"extra", len32(`{"v":1,"size":0}`), `{"v":1,"size":0}`, "x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			b.WriteString(magic)
			w, err := age.Encrypt(&b, id.Recipient())
			if err != nil {
				t.Fatal(err)
			}
			binary.Write(w, binary.BigEndian, tc.length)
			io.WriteString(w, tc.header+tc.data)
			if err = w.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = Decrypt(io.Discard, &b, id); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("expected corruption, got %v", err)
			}
		})
	}
}
func len32(s string) uint32 { return uint32(len(s)) }

func TestSanitizeName(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`..\evil.txt`, "evil.txt"}, {"a/b/c.jpg", "c.jpg"}, {"CON", "fallback"}, {"con.txt", "fallback"},
		{"x:y", "xy"}, {"trailing. ", "trailing"}, {"", "fallback"}, {"..", "fallback"}, {".", "fallback"},
		{"NUL.jpg", "fallback"}, {"com9.bin", "fallback"}, {"LPT1", "fallback"}, {"COM10.txt", "COM10.txt"},
		{"a\x00\x01b?.txt", "ab.txt"}, {"prn", "fallback"}, {"aux.a", "fallback"}, {"normal.txt", "normal.txt"},
	} {
		t.Run(fmt.Sprintf("%q", tc.in), func(t *testing.T) {
			if got := SanitizeName(tc.in, "fallback"); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
	if got := SanitizeName("CON", `..\NUL`); got != "file" {
		t.Fatalf("unsafe fallback: %q", got)
	}
}

func TestFilesAndCleanup(t *testing.T) {
	id := identity(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "source.jpg")
	dest := filepath.Join(dir, "photo.tbx")
	data := bytes.Repeat([]byte("test"), 50000)
	if err := os.WriteFile(src, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(src, dest, `..\photo.jpg`, id.Recipient()); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(src, dest, "x", id.Recipient()); !os.IsExist(err) {
		t.Fatalf("overwrite: %v", err)
	}
	outDir := filepath.Join(dir, "out")
	for _, want := range []string{"photo.jpg", "photo (2).jpg"} {
		out, err := DecryptFile(dest, outDir, id)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Base(out) != want {
			t.Fatalf("got %s", out)
		}
		b, err := os.ReadFile(out)
		if err != nil || !bytes.Equal(b, data) {
			t.Fatalf("bad output: %v", err)
		}
	}
	bad := encrypted(t, data, id)
	bad[len(bad)-1] ^= 1
	if err := os.WriteFile(dest, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptFile(dest, outDir, id); err == nil {
		t.Fatal("accepted tampering")
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("failure left files: %v", entries)
	}
	if err := EncryptFile(src, filepath.Join(dir, "failed.tbx"), "x", failingRecipient{}); err == nil {
		t.Fatal("expected failure")
	}
	if _, err := os.Stat(filepath.Join(dir, "failed.tbx.part")); !os.IsNotExist(err) {
		t.Fatal("part left")
	}
	if _, err := os.Stat(filepath.Join(dir, "failed.tbx")); !os.IsNotExist(err) {
		t.Fatal("output left")
	}
}

type failingRecipient struct{}

func (failingRecipient) Wrap([]byte) ([]*age.Stanza, error) {
	return nil, errors.New("injected failure")
}

func TestEncryptSizeMismatch(t *testing.T) {
	id := identity(t)
	if err := Encrypt(io.Discard, bytes.NewReader([]byte("x")), "x", 2, id.Recipient()); err == nil {
		t.Fatal("accepted wrong size")
	}
}
