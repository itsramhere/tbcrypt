package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"filippo.io/age"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ramst/tbcrypt/internal/config"
	"github.com/ramst/tbcrypt/internal/keystore"
	"github.com/ramst/tbcrypt/internal/pipeline"
)

const password = "a strong web test password"

type fakePicker struct {
	paths []string
	save  string
	err   error
}

func (p *fakePicker) Pick(context.Context, string, string) ([]string, error) { return p.paths, p.err }
func (p *fakePicker) SaveKey(context.Context) (string, error)                { return p.save, p.err }

type fixture struct {
	s      *server
	t      *testing.T
	picker *fakePicker
	log    *bytes.Buffer
}

func newFixture(t *testing.T, modify func(*Options)) *fixture {
	t.Helper()
	p := &fakePicker{}
	logs := &bytes.Buffer{}
	opts := Options{Addr: "127.0.0.1:8737", ConfigDir: t.TempDir(), Picker: p, Logger: slog.New(slog.NewTextHandler(logs, nil)), UnlockDelay: time.Millisecond, KeyParams: keystore.Params{Time: 1, MemoryKiB: 64, Threads: 1}, OpenPath: func(string) error { return nil }}
	if modify != nil {
		modify(&opts)
	}
	s, err := newServer(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.close)
	return &fixture{s, t, p, logs}
}
func (f *fixture) request(method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	f.t.Helper()
	var in io.Reader
	if method == "POST" {
		if body == nil {
			body = map[string]any{}
		}
		b, err := json.Marshal(body)
		if err != nil {
			f.t.Fatal(err)
		}
		in = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, "http://"+f.s.host+path, in)
	r.Header.Set("X-TBCrypt-Token", f.s.token)
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		if name == "Host" {
			r.Host = value
		} else {
			r.Header.Set(name, value)
		}
	}
	w := httptest.NewRecorder()
	f.s.ServeHTTP(w, r)
	return w
}
func (f *fixture) post(path string, body any, status int) map[string]any {
	f.t.Helper()
	w := f.request("POST", path, body, nil)
	if w.Code != status {
		f.t.Fatalf("%s: %d want %d: %s", path, w.Code, status, w.Body)
	}
	var data map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		f.t.Fatal(err)
	}
	return data
}
func (f *fixture) setup() {
	f.t.Helper()
	f.post("/api/setup", map[string]string{"password": password}, 200)
}
func (f *fixture) waitJob(id string) progress {
	f.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		w := f.request("GET", "/api/jobs/"+id, nil, nil)
		if w.Code != 200 {
			f.t.Fatal(w.Code, w.Body)
		}
		var p progress
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			f.t.Fatal(err)
		}
		if p.State != "running" {
			return p
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.t.Fatal("job did not finish")
	return progress{}
}
func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityBoundary(t *testing.T) {
	f := newFixture(t, nil)
	for _, tc := range []struct {
		name, method, path string
		headers            map[string]string
		want               int
	}{
		{"missing token", "GET", "/api/state", map[string]string{"X-TBCrypt-Token": ""}, 401},
		{"wrong token", "GET", "/api/state", map[string]string{"X-TBCrypt-Token": strings.Repeat("0", 64)}, 401},
		{"bad host", "GET", "/api/state", map[string]string{"Host": "evil.example:8737"}, 403},
		{"bad static host", "GET", "/", map[string]string{"Host": "evil.example:8737"}, 403},
		{"bad origin", "POST", "/api/lock", map[string]string{"Origin": "https://evil.example"}, 403},
		{"null origin", "GET", "/api/state", map[string]string{"Origin": "null"}, 403},
		{"wrong port", "GET", "/api/state", map[string]string{"Host": "127.0.0.1:9999"}, 403},
		{"same origin", "GET", "/api/state", map[string]string{"Origin": "http://127.0.0.1:8737"}, 200},
		{"localhost", "GET", "/api/state", map[string]string{"Host": "localhost:8737", "Origin": "http://localhost:8737"}, 200},
		{"mutation get", "GET", "/api/setup", nil, 405},
		{"post state", "POST", "/api/state", nil, 405},
		{"no json", "POST", "/api/lock", map[string]string{"Content-Type": "text/plain"}, 415},
		{"options", "OPTIONS", "/api/state", nil, 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := f.request(tc.method, tc.path, map[string]string{}, tc.headers)
			if w.Code != tc.want {
				t.Fatalf("%d: %s", w.Code, w.Body)
			}
			if w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("CORS enabled")
			}
			if w.Header().Get("Content-Security-Policy") != "default-src 'self'" || w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatal("security headers missing")
			}
		})
	}
	w := f.request("GET", "/", nil, map[string]string{"X-TBCrypt-Token": ""})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Encrypt a folder") {
		t.Fatal("static UI not served")
	}
	for _, path := range []string{"/app.js", "/style.css"} {
		if w := f.request("GET", path, nil, nil); w.Code != 200 {
			t.Fatal(path, w.Code)
		}
	}
	if w := f.request("GET", "/api/state", nil, nil); w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("API cached")
	}
}

func TestKeyLifecycleAndPickers(t *testing.T) {
	f := newFixture(t, nil)
	f.post("/api/setup", map[string]string{"password": "short"}, 400)
	result := f.post("/api/setup", map[string]string{"password": password}, 200)
	if result["keyfile"] != filepath.Join(f.s.opts.ConfigDir, "keyfile.json") {
		t.Fatal(result)
	}
	f.post("/api/setup", map[string]string{"password": password}, 409)
	f.post("/api/lock", nil, 200)
	f.post("/api/unlock", map[string]string{"password": "incorrect"}, 401)
	f.post("/api/encrypt", map[string]any{"source": t.TempDir(), "output": t.TempDir()}, 423)
	f.post("/api/unlock", map[string]string{"password": password}, 200)
	f.picker.paths = []string{t.TempDir()}
	pick := f.post("/api/pick", map[string]string{"kind": "folder", "title": "Pick folder"}, 200)
	if len(pick["paths"].([]any)) != 1 {
		t.Fatal(pick)
	}
	f.post("/api/pick", map[string]string{"kind": "unsupported"}, 400)
	f.picker.err = ErrCanceled
	if data := f.post("/api/pick", map[string]string{"kind": "files"}, 200); data["canceled"] != true {
		t.Fatal(data)
	}
	if data := f.post("/api/export-key", nil, 200); data["canceled"] != true {
		t.Fatal(data)
	}
	f.picker.err = nil
	f.picker.save = filepath.Join(t.TempDir(), "backup.json")
	f.post("/api/export-key", nil, 200)
	f.post("/api/export-key", nil, 409)
	f.post("/api/change-password", map[string]string{"old": "wrong", "new": password}, 401)
	f.post("/api/change-password", map[string]string{"old": password, "new": "short"}, 400)
	next := "another strong password"
	f.post("/api/change-password", map[string]string{"old": password, "new": next}, 200)
	f.post("/api/lock", nil, 200)
	f.post("/api/unlock", map[string]string{"password": password}, 401)
	f.post("/api/unlock", map[string]string{"password": next}, 200)
	if strings.Contains(f.log.String(), password) || strings.Contains(f.log.String(), next) {
		t.Fatal("password in logs")
	}
}

func TestEncryptDecryptJobs(t *testing.T) {
	for _, move := range []bool{false, true} {
		name := "keep"
		if move {
			name = "move"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil)
			f.setup()
			source := t.TempDir()
			output := filepath.Join(source, "encrypted")
			dest := t.TempDir()
			data := map[string][]byte{"hello.txt": []byte("private contents\n"), filepath.Join("nested", "photo.bin"): bytes.Repeat([]byte("binary"), 20000)}
			for rel, b := range data {
				write(t, filepath.Join(source, rel), b)
			}
			id := f.post("/api/encrypt", map[string]any{"source": source, "output": output, "moveOriginals": move}, 202)["jobId"].(string)
			p := f.waitJob(id)
			if p.State != "done" || p.Total != 2 || p.Done != 2 || p.Failed != 0 || len(p.Items) != 2 {
				t.Fatalf("%+v", p)
			}
			for rel, b := range data {
				path := filepath.Join(source, rel)
				if move {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatal("original not moved")
					}
					path = filepath.Join(source, "done", rel)
				}
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, b) {
					t.Fatal("original mismatch", err)
				}
			}
			entries, err := os.ReadDir(filepath.Join(source, ".tbcrypt-tmp"))
			if err != nil || len(entries) != 0 {
				t.Fatal("temp leftovers", err)
			}
			id = f.post("/api/decrypt", map[string]any{"sources": []string{output}, "output": dest}, 202)["jobId"].(string)
			p = f.waitJob(id)
			if p.State != "done" || p.Total != 2 || p.Done != 2 {
				t.Fatalf("%+v", p)
			}
			for rel, b := range data {
				got, err := os.ReadFile(filepath.Join(dest, rel))
				if err != nil || !bytes.Equal(got, b) {
					t.Fatalf("restore %s: %v", rel, err)
				}
			}
			c, err := config.Load(f.s.opts.ConfigDir)
			if err != nil || c.LastEncryptSrc != source || c.LastEncryptOut != output || c.LastDecryptSrc != output || c.LastDecryptOut != dest {
				t.Fatal("last folders not saved", err, c)
			}
			f.post("/api/open", map[string]string{"path": dest}, 200)
		})
	}
}

func TestConflictCancelAndLock(t *testing.T) {
	entered := make(chan struct{}, 1)
	f := newFixture(t, func(o *Options) {
		o.ProcessFunc = func(ctx context.Context, _ pipeline.Options, _ string, _ bool) (pipeline.Result, error) {
			entered <- struct{}{}
			<-ctx.Done()
			return pipeline.Result{}, ctx.Err()
		}
	})
	f.setup()
	source := t.TempDir()
	output := t.TempDir()
	write(t, filepath.Join(source, "a.txt"), []byte("untouched"))
	body := map[string]any{"source": source, "output": output}
	id := f.post("/api/encrypt", body, 202)["jobId"].(string)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("job never entered")
	}
	f.post("/api/encrypt", body, 409)
	f.post("/api/jobs/"+id+"/cancel", nil, 200)
	if p := f.waitJob(id); p.State != "canceled" {
		t.Fatal(p)
	}
	if b, _ := os.ReadFile(filepath.Join(source, "a.txt")); string(b) != "untouched" {
		t.Fatal("cancel touched original")
	}
	id = f.post("/api/encrypt", body, 202)["jobId"].(string)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("second job never entered")
	}
	f.post("/api/lock", nil, 200)
	if p := f.waitJob(id); p.State != "canceled" {
		t.Fatal(p)
	}
	f.post("/api/encrypt", body, 423)
}

func TestAutoLockAndRunningJob(t *testing.T) {
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	entered := make(chan struct{})
	release := make(chan struct{})
	f := newFixture(t, func(o *Options) {
		o.Clock = func() time.Time { return time.Unix(0, now.Load()) }
		o.IdleTimeout = time.Minute
		o.ProcessFunc = func(ctx context.Context, _ pipeline.Options, _ string, _ bool) (pipeline.Result, error) {
			close(entered)
			select {
			case <-release:
				return pipeline.Result{}, nil
			case <-ctx.Done():
				return pipeline.Result{}, ctx.Err()
			}
		}
	})
	f.setup()
	now.Add(int64(2 * time.Minute))
	f.s.checkIdle()
	w := f.request("GET", "/api/state", nil, nil)
	if !strings.Contains(w.Body.String(), `"unlocked":false`) {
		t.Fatal(w.Body)
	}
	f.post("/api/unlock", map[string]string{"password": password}, 200)
	src := t.TempDir()
	write(t, filepath.Join(src, "file"), []byte("data"))
	id := f.post("/api/encrypt", map[string]string{"source": src, "output": t.TempDir()}, 202)["jobId"].(string)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("job not running")
	}
	now.Add(int64(2 * time.Minute))
	f.s.checkIdle()
	f.s.mu.Lock()
	unlocked := f.s.key != nil
	f.s.mu.Unlock()
	if !unlocked {
		t.Fatal("locked a running job")
	}
	close(release)
	f.waitJob(id)
	now.Add(int64(2 * time.Minute))
	// Even without the maintenance ticker, the next API call applies expiry before touching activity.
	w = f.request("GET", "/api/state", nil, nil)
	if !strings.Contains(w.Body.String(), `"unlocked":false`) {
		t.Fatal(w.Body)
	}
}

func TestValidationHistoryAndOpen(t *testing.T) {
	f := newFixture(t, nil)
	f.setup()
	src := t.TempDir()
	out := t.TempDir()
	f.post("/api/open", map[string]string{"path": out}, 403)
	f.post("/api/encrypt", map[string]string{"source": src, "output": src}, 400)
	f.post("/api/encrypt", map[string]string{"source": filepath.Join(src, "missing"), "output": out}, 400)
	f.post("/api/decrypt", map[string]any{"sources": []string{}, "output": out}, 400)
	f.post("/api/decrypt", map[string]any{"sources": []string{filepath.Join(src, "missing")}, "output": out}, 400)
	var first string
	for n := 0; n < 21; n++ {
		id := f.post("/api/encrypt", map[string]string{"source": src, "output": out}, 202)["jobId"].(string)
		if n == 0 {
			first = id
		}
		if p := f.waitJob(id); p.State != "done" {
			t.Fatal(p)
		}
	}
	if w := f.request("GET", "/api/jobs/"+first, nil, nil); w.Code != 404 {
		t.Fatal("old job retained")
	}
	f.s.mu.Lock()
	count := len(f.s.jobs)
	f.s.mu.Unlock()
	if count != 20 {
		t.Fatal(count)
	}
	f.post("/api/open", map[string]string{"path": out}, 200)
	f.post("/api/open", map[string]string{"path": filepath.Dir(src)}, 403)
}

func TestFailedJob(t *testing.T) {
	f := newFixture(t, func(o *Options) {
		o.ProcessFunc = func(context.Context, pipeline.Options, string, bool) (pipeline.Result, error) {
			return pipeline.Result{}, errors.New("injected failure")
		}
	})
	f.setup()
	src := t.TempDir()
	write(t, filepath.Join(src, "a"), []byte("safe"))
	id := f.post("/api/encrypt", map[string]string{"source": src, "output": t.TempDir()}, 202)["jobId"].(string)
	if p := f.waitJob(id); p.State != "failed" || p.Failed != 1 || p.Items[0].Error != "injected failure" {
		t.Fatal(p)
	}
}

func TestLoopbackAndPortFallback(t *testing.T) {
	if l, err := listen("0.0.0.0:8737"); err == nil {
		l.Close()
		t.Fatal("non-loopback bind")
	}
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	next, err := listen(occupied.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if next.Addr().String() == occupied.Addr().String() {
		t.Fatal("did not fall back")
	}
}

type blockingRecipient struct {
	ctx     context.Context
	entered chan struct{}
}

func (r blockingRecipient) Wrap(key []byte) ([]*age.Stanza, error) {
	close(r.entered)
	<-r.ctx.Done()
	return nil, r.ctx.Err()
}

func TestCancelDuringEncryptionCleansOutput(t *testing.T) {
	entered := make(chan struct{})
	f := newFixture(t, func(o *Options) {
		o.ProcessFunc = func(ctx context.Context, opts pipeline.Options, path string, move bool) (pipeline.Result, error) {
			opts.Recipient = blockingRecipient{ctx, entered}
			return pipeline.EncryptOne(ctx, opts, path)
		}
	})
	f.setup()
	src := t.TempDir()
	out := t.TempDir()
	original := filepath.Join(src, "private.txt")
	write(t, original, []byte("private file bytes"))
	id := f.post("/api/encrypt", map[string]string{"source": src, "output": out}, 202)["jobId"].(string)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("encryption did not start")
	}
	f.post("/api/jobs/"+id+"/cancel", nil, 200)
	if p := f.waitJob(id); p.State != "canceled" {
		t.Fatal(p)
	}
	for _, dir := range []string{out, filepath.Join(src, ".tbcrypt-tmp")} {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("leftovers in %s: %v %v", dir, entries, err)
		}
	}
	if b, err := os.ReadFile(original); err != nil || string(b) != "private file bytes" {
		t.Fatal("original changed")
	}
}

type announcement chan string

func (c announcement) Write(p []byte) (int, error) { c <- string(p); return len(p), nil }
func TestServeAndGracefulShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	printed := make(announcement, 1)
	finished := make(chan error, 1)
	home := t.TempDir()
	go func() { finished <- Serve(ctx, Options{Addr: "127.0.0.1:0", ConfigDir: home, Output: printed}) }()
	var line string
	select {
	case line = <-printed:
	case err := <-finished:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("no startup URL")
	}
	url := strings.Fields(line)[3]
	root := strings.Split(url, "#")[0]
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(root)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	response, err = client.Get(root + "api/state")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal(response.StatusCode)
	}
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}
