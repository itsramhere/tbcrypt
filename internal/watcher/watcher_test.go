package watcher

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/itsramhere/tbcrypt/internal/keystore"
	"github.com/itsramhere/tbcrypt/internal/pipeline"
	"github.com/itsramhere/tbcrypt/internal/tbx"
)

func waitFor(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", description)
}
func fixture(t *testing.T) (*Watcher, pipeline.Options) {
	t.Helper()
	dir := t.TempDir()
	home := t.TempDir()
	if err := keystore.InitWithParams(home, "watcher test password", keystore.Params{Time: 1, MemoryKiB: 64, Threads: 1}); err != nil {
		t.Fatal(err)
	}
	k, err := keystore.Unlock(home, "watcher test password")
	if err != nil {
		t.Fatal(err)
	}
	opts := pipeline.Options{WatchDir: dir, OutputDir: filepath.Join(dir, "encrypted"), DoneDir: filepath.Join(dir, "done"), Recipient: k.Recipient(), Identity: k.Identity()}
	w := New(opts, nil)
	w.StableFor = 80 * time.Millisecond
	w.RetryDelays = []time.Duration{30 * time.Millisecond, 60 * time.Millisecond}
	return w, opts
}
func start(t *testing.T, w *Watcher) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("watcher did not stop")
		}
	})
	return cancel
}
func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestArrivalsAndCatchup(t *testing.T) {
	w, opts := fixture(t)
	write(t, filepath.Join(opts.WatchDir, "existing.txt"), []byte("catch up"))
	start(t, w)
	waitFor(t, "initial scan", func() bool { return w.Status().Done == 1 })
	src := filepath.Join(opts.WatchDir, "new", "nested", "photo.jpg")
	data := []byte("nested data")
	write(t, src, data)
	waitFor(t, "nested arrival", func() bool { return w.Status().Done == 2 })
	f, err := os.Open(filepath.Join(opts.OutputDir, "new", "nested", "photo.jpg.tbx"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out bytes.Buffer
	if _, err := tbx.Decrypt(&out, f, opts.Identity); err != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("decrypt: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("original not moved")
	}
	waitFor(t, "batch event", func() bool {
		for {
			select {
			case event := <-w.Events():
				if event.Kind == BatchDone && event.Count > 0 {
					return true
				}
			default:
				return false
			}
		}
	})
}

func TestChunkedWriteAndIgnoredFiles(t *testing.T) {
	w, opts := fixture(t)
	w.StableFor = 150 * time.Millisecond
	start(t, w)
	for _, name := range []string{"a.tmp", "a.part", "a.crdownload", "desktop.ini", "Thumbs.db", "~$doc", "existing.tbx"} {
		write(t, filepath.Join(opts.WatchDir, name), []byte("ignore"))
	}
	src := filepath.Join(opts.WatchDir, "large.dat")
	f, err := os.OpenFile(src, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i := 0; i < 6; i++ {
		if _, err = f.Write(bytes.Repeat([]byte{byte(i)}, 1024)); err != nil {
			t.Fatal(err)
		}
		f.Sync()
		time.Sleep(45 * time.Millisecond)
		if w.Status().Done != 0 {
			t.Fatal("processed during writing")
		}
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "completed copy", func() bool { return w.Status().Done == 1 })
	time.Sleep(200 * time.Millisecond)
	if w.Status().Done != 1 {
		t.Fatal("duplicate processing")
	}
	files, err := os.ReadDir(opts.WatchDir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, f := range files {
		if !f.IsDir() {
			count++
		}
	}
	if count != 7 {
		t.Fatalf("ignored files changed: %d", count)
	}
}

func TestPauseResume(t *testing.T) {
	w, opts := fixture(t)
	w.Pause()
	start(t, w)
	write(t, filepath.Join(opts.WatchDir, "paused.txt"), []byte("wait"))
	waitFor(t, "queued while paused", func() bool { return w.Status().Queued == 1 })
	time.Sleep(200 * time.Millisecond)
	if s := w.Status(); s.Done != 0 || s.State != "Paused" {
		t.Fatal(s)
	}
	w.Resume()
	waitFor(t, "resumed", func() bool { return w.Status().Done == 1 })
}

func TestRetryAndTerminalFailure(t *testing.T) {
	for _, succeed := range []bool{true, false} {
		name := "exhausted"
		if succeed {
			name = "eventual-success"
		}
		t.Run(name, func(t *testing.T) {
			w, opts := fixture(t)
			var calls atomic.Int32
			w.ProcessFunc = func(ctx context.Context, opts pipeline.Options, path string) (pipeline.Result, error) {
				n := calls.Add(1)
				if succeed && n == 2 {
					return pipeline.ProcessOne(ctx, opts, path)
				}
				return pipeline.Result{}, errors.New("injected processor failure")
			}
			start(t, w)
			src := filepath.Join(opts.WatchDir, "retry.txt")
			write(t, src, []byte("retry"))
			waitFor(t, "retry outcome", func() bool { s := w.Status(); return s.Done+s.Failed == 1 })
			if succeed {
				if calls.Load() != 2 || w.Status().Done != 1 {
					t.Fatal(w.Status(), calls.Load())
				}
			} else {
				if calls.Load() != 3 || w.Status().Failed != 1 {
					t.Fatal(w.Status(), calls.Load())
				}
				time.Sleep(200 * time.Millisecond)
				if calls.Load() != 3 {
					t.Fatal("failure hot-loop")
				}
				if _, err := os.Stat(src); err != nil {
					t.Fatal("lost original")
				}
			}
		})
	}
}

func TestCancelInFlight(t *testing.T) {
	w, opts := fixture(t)
	entered := make(chan struct{})
	finished := make(chan struct{})
	w.ProcessFunc = func(ctx context.Context, _ pipeline.Options, _ string) (pipeline.Result, error) {
		close(entered)
		<-ctx.Done()
		close(finished)
		return pipeline.Result{}, ctx.Err()
	}
	cancel := start(t, w)
	src := filepath.Join(opts.WatchDir, "cancel.txt")
	write(t, src, []byte("safe"))
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("never started")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("processor not cancelled")
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatal("lost source")
	}
}

func TestSingleWorkerDedupAndPauseInFlight(t *testing.T) {
	w, opts := fixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls, active atomic.Int32
	w.ProcessFunc = func(ctx context.Context, opts pipeline.Options, path string) (pipeline.Result, error) {
		if active.Add(1) != 1 {
			t.Error("concurrent processor calls")
		}
		defer active.Add(-1)
		if calls.Add(1) == 1 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return pipeline.Result{}, ctx.Err()
			}
		}
		return pipeline.ProcessOne(ctx, opts, path)
	}
	start(t, w)
	first := filepath.Join(opts.WatchDir, "first.txt")
	write(t, first, []byte("first"))
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("never entered processor")
	}
	w.Pause()
	// Repeated events for the current file must not enqueue another copy of it.
	for i := 0; i < 3; i++ {
		write(t, first, []byte("first"))
	}
	write(t, filepath.Join(opts.WatchDir, "second.txt"), []byte("second"))
	waitFor(t, "second queued", func() bool { return w.Status().Queued == 1 })
	close(release)
	waitFor(t, "in-flight finishes while paused", func() bool { s := w.Status(); return s.Done == 1 && s.State == "Paused" })
	time.Sleep(2 * w.StableFor)
	if calls.Load() != 1 {
		t.Fatal("dequeued while paused")
	}
	w.Resume()
	waitFor(t, "second completes", func() bool { return w.Status().Done == 2 })
	if calls.Load() != 2 {
		t.Fatal("duplicate processing")
	}
}

func TestDisappearedFileDropped(t *testing.T) {
	w, opts := fixture(t)
	w.Pause()
	start(t, w)
	src := filepath.Join(opts.WatchDir, "disappear.txt")
	write(t, src, []byte("temporary"))
	waitFor(t, "queued", func() bool { return w.Status().Queued == 1 })
	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "dropped", func() bool { return w.Status().Queued == 0 })
	w.Resume()
	time.Sleep(2 * w.StableFor)
	if s := w.Status(); s.Done != 0 || s.Failed != 0 {
		t.Fatal(s)
	}
}
