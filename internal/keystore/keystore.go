// Package keystore protects an age identity with a password-derived key.
package keystore

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/itsramhere/tbcrypt/internal/fsutil"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
)

// Errors distinguish an existing store, a weak password and a failed unlock.
var (
	ErrExists        = errors.New("keyfile already exists")
	ErrWeakPassword  = errors.New("password must be at least 12 bytes")
	ErrWrongPassword = errors.New("wrong password or damaged keyfile")
)

// Params are the Argon2id work factors persisted in the keyfile.
// Zero Params select production defaults; smaller explicit values support tests.
type Params struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

func (p Params) resolved() Params {
	if p == (Params{}) {
		return Params{3, 65536, 4}
	}
	return p
}
func (p Params) valid() bool {
	return p.Time >= 1 && p.Time <= 10 && p.Threads >= 1 && p.Threads <= 64 && p.MemoryKiB >= 8*uint32(p.Threads) && p.MemoryKiB <= 256*1024
}

type keyfile struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Salt       []byte `json:"salt"`
	Time       uint32 `json:"time"`
	MemoryKiB  uint32 `json:"memory_kib"`
	Threads    uint8  `json:"threads"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
	Recipient  string `json:"recipient"`
}

// Key holds an unlocked X25519 identity.
type Key struct{ identity *age.X25519Identity }

// Identity returns the private age identity.
func (k *Key) Identity() *age.X25519Identity { return k.identity }

// Recipient returns the public encryption recipient.
func (k *Key) Recipient() *age.X25519Recipient { return k.identity.Recipient() }

// Init creates a new store with production Argon2id parameters.
func Init(dir, password string) error { return InitWithParams(dir, password, Params{}) }

// InitWithParams creates a new store with explicit work factors.
func InitWithParams(dir, password string, params Params) (err error) {
	path := filepath.Join(dir, "keyfile.json")
	if _, err := os.Stat(path); err == nil {
		return ErrExists
	} else if !os.IsNotExist(err) {
		return err
	}
	if len(password) < 12 {
		return ErrWeakPassword
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	b, err := wrap(id, password, params.resolved())
	if err != nil {
		return err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	// An exclusive reservation prevents concurrent initialization overwriting keys.
	if _, err = fsutil.Reserve(path, false); err != nil {
		if os.IsExist(err) {
			return ErrExists
		}
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(path)
		}
	}()
	return fsutil.Atomic(path, b)
}

func wrap(id *age.X25519Identity, password string, p Params) ([]byte, error) {
	if !p.valid() {
		return nil, errors.New("invalid Argon2id parameters")
	}
	f := keyfile{Version: 1, KDF: "argon2id", Salt: make([]byte, 16), Nonce: make([]byte, 24), Time: p.Time, MemoryKiB: p.MemoryKiB, Threads: p.Threads, Recipient: id.Recipient().String()}
	if _, err := rand.Read(f.Salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(f.Nonce); err != nil {
		return nil, err
	}
	kek := argon2.IDKey([]byte(password), f.Salt, p.Time, p.MemoryKiB, p.Threads, 32)
	defer clear(kek)
	var key [32]byte
	copy(key[:], kek)
	defer clear(key[:])
	var nonce [24]byte
	copy(nonce[:], f.Nonce)
	plain := []byte(id.String())
	defer clear(plain)
	f.Ciphertext = secretbox.Seal(nil, plain, &nonce, &key)
	return json.MarshalIndent(f, "", "  ")
}

func load(dir string) (keyfile, error) {
	var f keyfile
	in, err := os.Open(filepath.Join(dir, "keyfile.json"))
	if err != nil {
		return f, err
	}
	defer in.Close()
	b, err := io.ReadAll(io.LimitReader(in, 65537))
	if err != nil {
		return f, err
	}
	if len(b) > 65536 {
		return f, errors.New("keyfile too large")
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, err
	}
	if f.Version != 1 || f.KDF != "argon2id" || len(f.Salt) != 16 || len(f.Nonce) != 24 || len(f.Ciphertext) < secretbox.Overhead || !(Params{f.Time, f.MemoryKiB, f.Threads}).valid() {
		return f, errors.New("invalid keyfile")
	}
	return f, nil
}

// Unlock authenticates the keyfile and decrypts its private identity.
func Unlock(dir, password string) (*Key, error) {
	f, err := load(dir)
	if err != nil {
		return nil, err
	}
	kek := argon2.IDKey([]byte(password), f.Salt, f.Time, f.MemoryKiB, f.Threads, 32)
	defer clear(kek)
	var key [32]byte
	copy(key[:], kek)
	defer clear(key[:])
	var nonce [24]byte
	copy(nonce[:], f.Nonce)
	plain, ok := secretbox.Open(nil, f.Ciphertext, &nonce, &key)
	if !ok {
		return nil, ErrWrongPassword
	}
	defer clear(plain)
	id, err := age.ParseX25519Identity(string(plain))
	if err != nil {
		return nil, fmt.Errorf("invalid private identity: %w", err)
	}
	if id.Recipient().String() != f.Recipient {
		return nil, errors.New("keyfile recipient mismatch")
	}
	return &Key{id}, nil
}

// LoadRecipient reads the public recipient without requesting a password.
func LoadRecipient(dir string) (*age.X25519Recipient, error) {
	f, err := load(dir)
	if err != nil {
		return nil, err
	}
	return age.ParseX25519Recipient(f.Recipient)
}

// ChangePassword rewraps the same identity using a new salt and nonce.
func ChangePassword(dir, old, new string) error {
	if len(new) < 12 {
		return ErrWeakPassword
	}
	k, err := Unlock(dir, old)
	if err != nil {
		return err
	}
	f, err := load(dir)
	if err != nil {
		return err
	}
	b, err := wrap(k.Identity(), new, Params{f.Time, f.MemoryKiB, f.Threads})
	if err != nil {
		return err
	}
	return fsutil.Atomic(filepath.Join(dir, "keyfile.json"), b)
}

// Export copies the keyfile to a new destination, refusing overwrite.
func Export(dir, destPath string) (err error) {
	src, err := os.Open(filepath.Join(dir, "keyfile.json"))
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		dst.Close()
		if err != nil {
			os.Remove(destPath)
		}
	}()
	if _, err = io.Copy(dst, src); err != nil {
		return err
	}
	if err = dst.Sync(); err != nil {
		return err
	}
	return dst.Close()
}
