// Package web serves tbcrypt's authenticated, loopback-only browser interface.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ramst/tbcrypt/internal/config"
	"github.com/ramst/tbcrypt/internal/keystore"
	"github.com/ramst/tbcrypt/internal/pipeline"
)

//go:embed static/index.html static/app.js static/style.css
var assets embed.FS

// Picker opens native selectors. Implementations return ErrCanceled on cancel.
type Picker interface {
	Pick(context.Context, string, string) ([]string, error)
	SaveKey(context.Context) (string, error)
}

// ErrCanceled represents a dismissed native dialog.
var ErrCanceled = errors.New("selection canceled")

// Options configures serving and injectable dependencies. Zero values select
// production defaults. Process and work-factor overrides support isolated tests.
type Options struct {
	Addr, ConfigDir string
	OpenBrowser     bool
	Logger          *slog.Logger
	Output          io.Writer
	Picker          Picker
	OpenPath        func(string) error
	Clock           func() time.Time
	IdleTimeout     time.Duration
	KeyParams       keystore.Params
	UnlockDelay     time.Duration
	ProcessFunc     func(context.Context, pipeline.Options, string, bool) (pipeline.Result, error)
}

type server struct {
	opts        Options
	host, token string
	ctx         context.Context
	cancel      context.CancelFunc
	mu, auth    sync.Mutex
	key         *keystore.Key
	config      config.Config
	activity    time.Time
	jobs        map[string]*job
	order       []string
	active      string
	directories map[string]bool
	workers     sync.WaitGroup
	static      http.Handler
}

func newServer(ctx context.Context, opts Options) (*server, error) {
	if opts.ConfigDir == "" {
		var err error
		opts.ConfigDir, err = config.DefaultDir()
		if err != nil {
			return nil, err
		}
	}
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:8737"
	}
	absDir, err := filepath.Abs(opts.ConfigDir)
	if err != nil {
		return nil, err
	}
	opts.ConfigDir = absDir
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.Output == nil {
		opts.Output = os.Stdout
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 15 * time.Minute
	}
	if opts.UnlockDelay <= 0 {
		opts.UnlockDelay = time.Second
	}
	if opts.Picker == nil {
		opts.Picker = nativePicker{}
	}
	if opts.OpenPath == nil {
		opts.OpenPath = openDirectory
	}
	if opts.ProcessFunc == nil {
		opts.ProcessFunc = func(ctx context.Context, o pipeline.Options, p string, move bool) (pipeline.Result, error) {
			if move {
				return pipeline.ProcessOne(ctx, o, p)
			}
			return pipeline.EncryptOne(ctx, o, p)
		}
	}
	c, err := config.Load(opts.ConfigDir)
	if err != nil {
		return nil, err
	}
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		return nil, err
	}
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	root, cancel := context.WithCancel(ctx)
	return &server{opts: opts, host: opts.Addr, token: hex.EncodeToString(secret[:]), ctx: root, cancel: cancel, config: c, activity: opts.Clock(), jobs: make(map[string]*job), directories: make(map[string]bool), static: http.FileServer(http.FS(sub))}, nil
}

func (s *server) close() {
	s.mu.Lock()
	s.cancel()
	s.mu.Unlock()
	s.workers.Wait()
	s.mu.Lock()
	s.key = nil
	s.mu.Unlock()
}
func (s *server) idleLocked() {
	if s.key != nil && s.active == "" && s.opts.Clock().Sub(s.activity) >= s.opts.IdleTimeout {
		s.key = nil
	}
}
func (s *server) checkIdle() { s.mu.Lock(); defer s.mu.Unlock(); s.idleLocked() }

func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]string{"error": message})
}
func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			fail(w, 413, "That request is too large. Choose fewer paths at once.")
			return false
		}
		fail(w, 400, "Please send a valid JSON request.")
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		fail(w, 400, "Please send one JSON object.")
		return false
	}
	return true
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	_, port, _ := net.SplitHostPort(s.host)
	if r.Host != "127.0.0.1:"+port && r.Host != "localhost:"+port {
		fail(w, 403, "This address is not allowed. Open the URL printed in the terminal.")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		h.Set("Cache-Control", "no-store")
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-TBCrypt-Token")), []byte(s.token)) != 1 {
			fail(w, 401, "Open the complete URL printed in the terminal to connect.")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+r.Host {
			fail(w, 403, "Requests from another website are not allowed.")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			fail(w, 405, "Use GET to read or JSON POST to make changes.")
			return
		}
		if r.Method == http.MethodPost {
			kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || kind != "application/json" {
				fail(w, 415, "Please send JSON with Content-Type: application/json.")
				return
			}
		}
		s.mu.Lock()
		s.idleLocked()
		s.activity = s.opts.Clock()
		s.mu.Unlock()
		s.api(w, r)
		return
	}
	h.Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		fail(w, 405, "Use GET to open this page.")
		return
	}
	switch r.URL.Path {
	case "/", "/app.js", "/style.css":
		s.static.ServeHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

func listen(addr string) (net.Listener, error) {
	if addr == "" {
		addr = "127.0.0.1:8737"
	}
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errors.New("use a loopback address such as 127.0.0.1:8737")
	}
	if host != "127.0.0.1" {
		return nil, errors.New("tbcrypt can only listen on 127.0.0.1")
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 0 || port > 65535 {
		return nil, errors.New("choose a port between 1 and 65535")
	}
	var last error
	for n := 0; n <= 10 && port+n <= 65535; n++ {
		listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port+n)))
		if err == nil {
			return listener, nil
		}
		last = err
		if port == 0 {
			break
		}
	}
	return nil, fmt.Errorf("could not start a local server: %w", last)
}

// Serve binds loopback, prints the secret URL, optionally opens it, and serves
// until cancellation. Shutdown cancels jobs and waits for owned file cleanup.
func Serve(ctx context.Context, opts Options) error {
	listener, err := listen(opts.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	opts.Addr = listener.Addr().String()
	s, err := newServer(ctx, opts)
	if err != nil {
		return err
	}
	defer s.close()
	url := "http://" + opts.Addr + "/#" + s.token
	fmt.Fprintf(s.opts.Output, "tbcrypt running at %s — press Ctrl+C to stop\n", url)
	if opts.OpenBrowser {
		if err := openBrowser(url); err != nil {
			s.opts.Logger.Warn("could not open the browser; use the printed URL", "error", err)
		}
	}
	httpServer := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: time.Minute, BaseContext: func(net.Listener) context.Context { return s.ctx }}
	finished := make(chan error, 1)
	go func() { finished <- httpServer.Serve(listener) }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var serveErr error
	running := true
	for running {
		select {
		case <-ctx.Done():
			running = false
		case serveErr = <-finished:
			running = false
		case <-ticker.C:
			s.checkIdle()
		}
	}
	s.cancel()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdown); err != nil {
		_ = httpServer.Close()
		return err
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}
