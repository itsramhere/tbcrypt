// Package watcher queues stable files for the encryption pipeline.
package watcher

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/itsramhere/tbcrypt/internal/pipeline"
)

// Event kinds describe completed work, terminal failures and non-fatal warnings.
const (
	Encrypted = "Encrypted"
	Failed    = "Failed"
	Warning   = "Warning"
	BatchDone = "BatchDone"
)

// Event reports asynchronous progress. Count is the encrypted count for BatchDone.
type Event struct {
	Kind, Path string
	Err        error
	Count      int
}

// Status is a race-safe snapshot of the watcher session.
type Status struct {
	State                string
	Queued, Done, Failed int
	Current              string
}

// ProcessFunc is a cancellable, single-file processor.
type ProcessFunc func(context.Context, pipeline.Options, string) (pipeline.Result, error)

// Watcher has one queue coordinator and one processing worker. Configure public
// fields before Run; Run is called once. Pause, Resume and Status are concurrent-safe.
type Watcher struct {
	StableFor       time.Duration
	RetryDelays     []time.Duration
	ProcessFunc     ProcessFunc
	opts            pipeline.Options
	logger          *slog.Logger
	mu              sync.Mutex
	status          Status
	paused, started bool
	events          chan Event
	wake            chan struct{}
}

// New creates an idle watcher with production stability and retry intervals.
func New(opts pipeline.Options, logger *slog.Logger) *Watcher {
	if opts.Logger == nil {
		opts.Logger = logger
	}
	return &Watcher{StableFor: 3 * time.Second, RetryDelays: []time.Duration{10 * time.Second, time.Minute, 5 * time.Minute}, ProcessFunc: pipeline.ProcessOne, opts: opts, logger: logger, status: Status{State: "Idle"}, events: make(chan Event, 64), wake: make(chan struct{}, 1)}
}

// Events returns a best-effort stream, closed when Run exits.
func (w *Watcher) Events() <-chan Event { return w.events }

// Status returns the current activity and cumulative session counters.
func (w *Watcher) Status() Status { w.mu.Lock(); defer w.mu.Unlock(); return w.status }

// Pause stops dequeuing; current work finishes and queued files are retained.
func (w *Watcher) Pause() {
	w.mu.Lock()
	w.paused = true
	if w.status.Current == "" {
		w.status.State = "Paused"
	}
	w.mu.Unlock()
	w.signal()
}

// Resume allows queued work to continue.
func (w *Watcher) Resume() {
	w.mu.Lock()
	w.paused = false
	if w.status.Current == "" {
		w.status.State = "Idle"
	}
	w.mu.Unlock()
	w.signal()
}
func (w *Watcher) signal() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}
func (w *Watcher) emit(event Event) {
	select {
	case w.events <- event:
	default:
	}
}

type stamp struct {
	size     int64
	modified time.Time
}
type entry struct {
	path, key   string
	observed    stamp
	since, next time.Time
	failures    int
}
type completion struct {
	item   *entry
	result pipeline.Result
	err    error
}

func key(path string) string {
	p, _ := filepath.Abs(path)
	p = filepath.Clean(p)
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	return p
}
func snapshot(path string) (stamp, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return stamp{}, err
	}
	if !info.Mode().IsRegular() {
		// A file replaced by a directory or symlink is no longer an input.
		return stamp{}, os.ErrNotExist
	}
	return stamp{info.Size(), info.ModTime()}, nil
}

// Run cleans stale plaintext, catches up existing inputs, and monitors recursive
// changes until cancellation. It waits for its worker before returning.
func (w *Watcher) Run(ctx context.Context) error {
	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		return errors.New("watcher already started")
	}
	w.started = true
	w.mu.Unlock()
	defer close(w.events)
	if err := pipeline.CleanTemp(w.opts); err != nil {
		return err
	}
	watch, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watch.Close()
	stable := w.StableFor
	if stable <= 0 {
		stable = 3 * time.Second
	}
	processor := w.ProcessFunc
	if processor == nil {
		processor = pipeline.ProcessOne
	}
	workerCtx, cancel := context.WithCancel(ctx)
	jobs := make(chan *entry)
	completed := make(chan completion, 1)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		for {
			select {
			case <-workerCtx.Done():
				return
			case item := <-jobs:
				result, err := processor(workerCtx, w.opts, item.path)
				select {
				case completed <- completion{item, result, err}:
				case <-workerCtx.Done():
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-workerDone }()
	queue := []*entry{}
	pending := make(map[string]*entry)
	terminal := make(map[string]stamp)
	watched := make(map[string]string)
	schedule := func(path string) {
		if pipeline.Ignored(w.opts, path) {
			return
		}
		observed, err := snapshot(path)
		if err != nil {
			return
		}
		k := key(path)
		if _, ok := pending[k]; ok {
			return
		}
		if failed, ok := terminal[k]; ok && failed == observed {
			return
		}
		delete(terminal, k)
		item := &entry{path: path, key: k, observed: observed, since: time.Now()}
		pending[k] = item
		queue = append(queue, item)
	}
	addTree := func(root string) error {
		return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			if key(path) != key(w.opts.WatchDir) && pipeline.Ignored(w.opts, path) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				k := key(path)
				if _, ok := watched[k]; !ok {
					if err := watch.Add(path); err != nil {
						return err
					}
					watched[k] = path
				}
			} else if d.Type().IsRegular() {
				schedule(path)
			}
			return nil
		})
	}
	// Install watches before catch-up scanning so arrivals during scanning are kept.
	if err := addTree(w.opts.WatchDir); err != nil {
		return err
	}
	files, err := pipeline.ScanDir(w.opts)
	if err != nil {
		return err
	}
	for _, path := range files {
		schedule(path)
	}
	interval := stable / 4
	if interval < 5*time.Millisecond {
		interval = 5 * time.Millisecond
	}
	if interval > 250*time.Millisecond {
		interval = 250 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	busy := false
	batchProcessed, batchCount := false, 0
	update := func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.status.Queued = len(queue)
		if busy {
			w.status.State = "Working"
		} else if w.paused {
			w.status.State = "Paused"
		} else {
			w.status.State = "Idle"
		}
	}
	defer func() { w.mu.Lock(); w.status.Current = ""; w.status.State = "Idle"; w.mu.Unlock() }()
	for {
		update()
		if !busy && len(queue) == 0 && batchProcessed {
			w.emit(Event{Kind: BatchDone, Count: batchCount})
			batchProcessed = false
			batchCount = 0
		}
		select {
		case <-ctx.Done():
			return nil
		case <-w.wake:
		case event, ok := <-watch.Events:
			if !ok {
				return errors.New("filesystem events closed")
			}
			if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
				k := key(event.Name)
				for dir, path := range watched {
					if dir == k || strings.HasPrefix(dir, k+string(filepath.Separator)) {
						_ = watch.Remove(path)
						delete(watched, dir)
					}
				}
			}
			if event.Has(fsnotify.Create) {
				if info, err := os.Lstat(event.Name); err == nil && info.IsDir() && !pipeline.Ignored(w.opts, event.Name) {
					if err := addTree(event.Name); err != nil {
						w.emit(Event{Kind: Warning, Path: event.Name, Err: err})
					}
				}
			}
			if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) || event.Has(fsnotify.Rename) {
				schedule(event.Name)
			}
		case err, ok := <-watch.Errors:
			if !ok {
				return errors.New("filesystem errors closed")
			}
			if w.logger != nil {
				w.logger.Error("filesystem watcher error", "error", err)
			}
			w.emit(Event{Kind: Warning, Err: err})
			if err := addTree(w.opts.WatchDir); err != nil {
				return err
			}
		case done := <-completed:
			busy = false
			batchProcessed = true
			w.mu.Lock()
			w.status.Current = ""
			w.mu.Unlock()
			item := done.item
			if done.err == nil {
				delete(pending, item.key)
				batchCount++
				w.mu.Lock()
				w.status.Done++
				w.mu.Unlock()
				if done.result.Warning != nil {
					w.emit(Event{Kind: Warning, Path: item.path, Err: done.result.Warning})
				}
				w.emit(Event{Kind: Encrypted, Path: item.path})
			} else if ctx.Err() != nil {
				return nil
			} else if os.IsNotExist(done.err) {
				delete(pending, item.key)
			} else if item.failures < len(w.RetryDelays) {
				delay := w.RetryDelays[item.failures]
				item.failures++
				item.next = time.Now().Add(delay)
				item.since = time.Now()
				queue = append(queue, item)
				if w.logger != nil {
					w.logger.Warn("processing will retry", "path", item.path, "attempt", item.failures, "delay", delay, "error", done.err)
				}
			} else {
				delete(pending, item.key)
				observed, _ := snapshot(item.path)
				terminal[item.key] = observed
				w.mu.Lock()
				w.status.Failed++
				w.mu.Unlock()
				if w.logger != nil {
					w.logger.Error("processing failed after retries", "path", item.path, "error", done.err)
				}
				w.emit(Event{Kind: Failed, Path: item.path, Err: done.err})
			}
		case now := <-ticker.C:
			// Every pending file is sampled, even while paused or while a worker is busy.
			kept := queue[:0]
			for _, item := range queue {
				observed, err := snapshot(item.path)
				if err != nil {
					if os.IsNotExist(err) {
						delete(pending, item.key)
					} else {
						item.since = now
						kept = append(kept, item)
					}
					continue
				}
				if observed != item.observed {
					item.observed = observed
					item.since = now
				}
				kept = append(kept, item)
			}
			queue = kept
			w.mu.Lock()
			paused := w.paused
			w.mu.Unlock()
			if busy || paused {
				continue
			}
			// FIFO among ready items; a long copy or a retry does not block other files.
			for i, item := range queue {
				if now.Sub(item.since) < stable || now.Before(item.next) {
					continue
				}
				if err := readable(item.path); err != nil {
					item.since = now
					continue
				}
				w.mu.Lock()
				if w.paused {
					w.mu.Unlock()
					break
				}
				queue = append(queue[:i], queue[i+1:]...)
				busy = true
				w.status.Current = item.path
				w.status.State = "Working"
				w.mu.Unlock()
				select {
				case jobs <- item:
				case <-ctx.Done():
					return nil
				}
				break
			}
		}
	}
}

// String describes a status for headless logs or UIs.
func (s Status) String() string {
	return fmt.Sprintf("%s: %d queued, %d done, %d failed", s.State, s.Queued, s.Done, s.Failed)
}
