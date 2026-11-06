package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/itsramhere/tbcrypt/internal/config"
	"github.com/itsramhere/tbcrypt/internal/jobs"
	"github.com/itsramhere/tbcrypt/internal/keystore"
	"github.com/itsramhere/tbcrypt/internal/pipeline"
)

type item struct {
	Path    string `json:"path"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
	Warning string `json:"warning,omitempty"`
}
type progress struct {
	Kind    string `json:"kind"`
	State   string `json:"state"`
	Total   int    `json:"total"`
	Done    int    `json:"done"`
	Failed  int    `json:"failed"`
	Current string `json:"current"`
	Items   []item `json:"items"`
}
type job struct {
	id       string
	output   string
	progress progress
	ctx      context.Context
	cancel   context.CancelFunc
	finished chan struct{}
}

func pathKey(path string) string {
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
	}
	return path
}
func within(dir, path string) bool {
	rel, err := filepath.Rel(pathKey(dir), pathKey(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
func existingDirectory(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("choose a folder first")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("choose a folder, not a file")
	}
	return abs, nil
}
func outputDirectory(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("choose an output folder")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return "", err
	}
	return existingDirectory(path)
}
func (s *server) available(w http.ResponseWriter) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		fail(w, 423, "Unlock your key before starting a job.")
		return false
	}
	if s.active != "" {
		fail(w, 409, "Another job is running. Wait for it or cancel it first.")
		return false
	}
	return true
}
func (s *server) begin(w http.ResponseWriter, kind string, remember func(*config.Config), dirs []string, run func(*job, *keystore.Key)) {
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		fail(w, 503, "tbcrypt is shutting down.")
		return
	}
	if s.key == nil {
		s.mu.Unlock()
		fail(w, 423, "Unlock your key before starting a job.")
		return
	}
	if s.active != "" {
		s.mu.Unlock()
		fail(w, 409, "Another job is running. Wait for it or cancel it first.")
		return
	}
	next := s.config
	remember(&next)
	if err := config.Save(s.opts.ConfigDir, next); err != nil {
		s.mu.Unlock()
		fail(w, 500, "Folder choices could not be saved. Check configuration folder permissions.")
		return
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		s.mu.Unlock()
		fail(w, 500, "A job could not be created. Please try again.")
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	j := &job{id: hex.EncodeToString(id[:]), progress: progress{Kind: kind, State: "running", Items: []item{}}, ctx: ctx, cancel: cancel, finished: make(chan struct{})}
	j.output = dirs[len(dirs)-1]
	s.config = next
	s.jobs[j.id] = j
	s.active = j.id
	s.order = append(s.order, j.id)
	if len(s.order) > 20 {
		delete(s.jobs, s.order[0])
		s.order = s.order[1:]
	}
	for _, dir := range dirs {
		s.directories[pathKey(dir)] = true
	}
	key := s.key
	s.workers.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.workers.Done()
		defer close(j.finished)
		defer cancel()
		run(j, key)
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case ctx.Err() != nil:
			j.progress.State = "canceled"
		case j.progress.Failed > 0:
			j.progress.State = "failed"
		default:
			j.progress.State = "done"
		}
		j.progress.Current = ""
		s.active = ""
		s.activity = s.opts.Clock()
	}()
	reply(w, 202, map[string]string{"jobId": j.id})
}
func (s *server) jobAPI(w http.ResponseWriter, r *http.Request) {
	suffix := strings.TrimPrefix(r.URL.Path, "/api/jobs/")
	parts := strings.Split(suffix, "/")
	if r.Method == http.MethodPost {
		var request struct{}
		if !decode(w, r, &request) {
			return
		}
	}
	s.mu.Lock()
	j := s.jobs[parts[0]]
	if j == nil {
		s.mu.Unlock()
		fail(w, 404, "That job is no longer available.")
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		snapshot := j.progress
		snapshot.Items = append([]item{}, snapshot.Items...)
		s.mu.Unlock()
		reply(w, 200, snapshot)
		return
	}
	if len(parts) == 2 && parts[1] == "cancel" && r.Method == http.MethodPost {
		j.cancel()
		s.mu.Unlock()
		reply(w, 200, map[string]bool{"canceled": true})
		return
	}
	s.mu.Unlock()
	fail(w, 405, "Use GET for job progress or POST to cancel a job.")
}
func (s *server) total(j *job, n int)         { s.mu.Lock(); j.progress.Total = n; s.mu.Unlock() }
func (s *server) current(j *job, path string) { s.mu.Lock(); j.progress.Current = path; s.mu.Unlock() }
func (s *server) record(j *job, i item) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j.progress.Items = append(j.progress.Items, i)
	if i.Error != "" {
		j.progress.Failed++
	} else {
		j.progress.Done++
	}
}
func (s *server) jobError(j *job, err error) {
	if j.ctx.Err() == nil {
		s.record(j, item{Error: err.Error()})
	}
}

func (s *server) encrypt(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Source        string `json:"source"`
		Output        string `json:"output"`
		MoveOriginals bool   `json:"moveOriginals"`
	}
	if !decode(w, r, &request) || !s.available(w) {
		return
	}
	source, err := existingDirectory(request.Source)
	if err != nil {
		fail(w, 400, "The source folder cannot be read. Choose an existing folder.")
		return
	}
	output, err := outputDirectory(request.Output)
	if err != nil {
		fail(w, 400, "The encrypted output folder cannot be created or opened.")
		return
	}
	if within(output, source) {
		fail(w, 400, "Choose a separate output folder. It cannot be the source or contain it.")
		return
	}
	done := ""
	if request.MoveOriginals {
		done = filepath.Join(source, "done")
	}
	if request.MoveOriginals && within(output, done) {
		fail(w, 400, "The originals' done folder must be outside the encrypted output folder.")
		return
	}
	s.mu.Lock()
	exif := config.FindExiftool(s.config)
	s.mu.Unlock()
	s.begin(w, "encrypt", func(c *config.Config) { c.LastEncryptSrc = source; c.LastEncryptOut = output }, []string{source, output}, func(j *job, key *keystore.Key) {
		opts := pipeline.Options{WatchDir: source, OutputDir: output, DoneDir: done, ExiftoolPath: exif, Recipient: key.Recipient(), Identity: key.Identity(), Logger: s.opts.Logger}
		if err := pipeline.CleanTemp(opts); err != nil {
			s.jobError(j, err)
			return
		}
		files, err := pipeline.ScanDir(opts)
		if err != nil {
			s.jobError(j, err)
			return
		}
		s.total(j, len(files))
		for _, path := range files {
			if j.ctx.Err() != nil {
				return
			}
			s.current(j, path)
			result, err := s.opts.ProcessFunc(j.ctx, opts, path, request.MoveOriginals)
			if j.ctx.Err() != nil && err != nil {
				return
			}
			i := item{Path: path, Output: result.Output}
			if err != nil {
				i.Error = err.Error()
				s.opts.Logger.Error("encryption failed", "path", path, "error", err)
			}
			if result.Warning != nil {
				i.Warning = result.Warning.Error()
			}
			s.record(j, i)
		}
	})
}
func (s *server) decrypt(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Sources []string `json:"sources"`
		Output  string   `json:"output"`
	}
	if !decode(w, r, &request) || !s.available(w) {
		return
	}
	if len(request.Sources) == 0 {
		fail(w, 400, "Choose encrypted files or a folder first.")
		return
	}
	sources := make([]string, 0, len(request.Sources))
	dirs := []string{}
	for _, src := range request.Sources {
		if strings.TrimSpace(src) == "" {
			fail(w, 400, "An encrypted file path is empty.")
			return
		}
		abs, err := filepath.Abs(src)
		if err == nil {
			abs, err = filepath.EvalSymlinks(abs)
		}
		if err != nil {
			fail(w, 400, "One of the selected encrypted files or folders cannot be found.")
			return
		}
		info, err := os.Stat(abs)
		if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
			fail(w, 400, "Choose regular encrypted files or folders.")
			return
		}
		sources = append(sources, abs)
		if info.IsDir() {
			dirs = append(dirs, abs)
		}
	}
	output, err := outputDirectory(request.Output)
	if err != nil {
		fail(w, 400, "The destination folder cannot be created or opened.")
		return
	}
	dirs = append(dirs, output)
	last := sources[0]
	if info, _ := os.Stat(last); info != nil && !info.IsDir() {
		last = filepath.Dir(last)
	}
	s.begin(w, "decrypt", func(c *config.Config) { c.LastDecryptSrc = last; c.LastDecryptOut = output }, dirs, func(j *job, key *keystore.Key) {
		plan, err := jobs.PlanDecrypt(j.ctx, sources, output)
		if err != nil {
			s.jobError(j, fmt.Errorf("could not read the selected inputs: %w", err))
			return
		}
		s.total(j, len(plan))
		for _, file := range plan {
			if j.ctx.Err() != nil {
				return
			}
			s.current(j, file.Path)
			target, err := jobs.DecryptOne(j.ctx, file, key.Identity())
			if j.ctx.Err() != nil && err != nil {
				return
			}
			i := item{Path: file.Path, Output: target}
			if err != nil {
				i.Output = ""
				i.Error = err.Error()
				s.opts.Logger.Error("decryption failed", "path", file.Path, "error", err)
			}
			s.record(j, i)
		}
	})
}
