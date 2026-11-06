package web

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ramst/tbcrypt/internal/config"
	"github.com/ramst/tbcrypt/internal/keystore"
)

func (s *server) api(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if strings.HasPrefix(path, "/api/jobs/") {
		s.jobAPI(w, r)
		return
	}
	if path == "/api/state" {
		if r.Method != http.MethodGet {
			fail(w, 405, "Use GET to read the app state.")
			return
		}
		s.state(w)
		return
	}
	if r.Method != http.MethodPost {
		fail(w, 405, "Use JSON POST for this action.")
		return
	}
	switch path {
	case "/api/setup":
		s.setup(w, r)
	case "/api/unlock":
		s.unlock(w, r)
	case "/api/lock":
		s.lock(w, r)
	case "/api/change-password":
		s.changePassword(w, r)
	case "/api/export-key":
		s.exportKey(w, r)
	case "/api/pick":
		s.pick(w, r)
	case "/api/open":
		s.open(w, r)
	case "/api/encrypt":
		s.encrypt(w, r)
	case "/api/decrypt":
		s.decrypt(w, r)
	default:
		fail(w, 404, "That action was not found.")
	}
}
func (s *server) state(w http.ResponseWriter) {
	_, err := os.Stat(filepath.Join(s.opts.ConfigDir, "keyfile.json"))
	if err != nil && !os.IsNotExist(err) {
		fail(w, 500, "The keyfile cannot be read. Check the configuration folder's permissions.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.config
	activeOutput := ""
	if j := s.jobs[s.active]; j != nil {
		activeOutput = j.output
	}
	reply(w, 200, map[string]any{"hasKey": err == nil, "unlocked": s.key != nil, "exiftool": config.FindExiftool(c) != "", "version": "3", "activeJob": s.active, "activeOutput": activeOutput, "last": map[string]string{"encryptSrc": c.LastEncryptSrc, "encryptOut": c.LastEncryptOut, "decryptSrc": c.LastDecryptSrc, "decryptOut": c.LastDecryptOut}})
}
func (s *server) requireKey(w http.ResponseWriter) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		fail(w, 423, "Unlock your key before continuing.")
		return false
	}
	return true
}
func (s *server) setup(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &request) {
		return
	}
	s.auth.Lock()
	defer s.auth.Unlock()
	err := keystore.InitWithParams(s.opts.ConfigDir, request.Password, s.opts.KeyParams)
	if errors.Is(err, keystore.ErrExists) {
		fail(w, 409, "A key already exists. Unlock it with its password.")
		return
	}
	if errors.Is(err, keystore.ErrWeakPassword) {
		fail(w, 400, "Choose a password of at least 12 characters.")
		return
	}
	if err != nil {
		fail(w, 500, "The keyfile could not be created. Check the configuration folder's permissions.")
		return
	}
	key, err := keystore.Unlock(s.opts.ConfigDir, request.Password)
	if err != nil {
		fail(w, 500, "Your key was created but could not be unlocked. Please restart tbcrypt.")
		return
	}
	s.mu.Lock()
	s.key = key
	s.activity = s.opts.Clock()
	s.mu.Unlock()
	reply(w, 200, map[string]string{"keyfile": filepath.Join(s.opts.ConfigDir, "keyfile.json")})
}
func (s *server) unlock(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &request) {
		return
	}
	s.auth.Lock()
	defer s.auth.Unlock()
	key, err := keystore.Unlock(s.opts.ConfigDir, request.Password)
	if errors.Is(err, keystore.ErrWrongPassword) {
		timer := time.NewTimer(s.opts.UnlockDelay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			return
		}
		fail(w, 401, "That password did not unlock the key. Please try again.")
		return
	}
	if err != nil {
		fail(w, 500, "The keyfile could not be unlocked. Check that it is present and undamaged.")
		return
	}
	s.mu.Lock()
	s.key = key
	s.activity = s.opts.Clock()
	s.mu.Unlock()
	reply(w, 200, map[string]bool{"unlocked": true})
}
func (s *server) lock(w http.ResponseWriter, r *http.Request) {
	var request struct{}
	if !decode(w, r, &request) {
		return
	}
	s.auth.Lock()
	defer s.auth.Unlock()
	s.mu.Lock()
	s.key = nil
	var finished <-chan struct{}
	if j := s.jobs[s.active]; j != nil {
		j.cancel()
		finished = j.finished
	}
	s.mu.Unlock()
	if finished != nil {
		select {
		case <-finished:
		case <-r.Context().Done():
			return
		}
	}
	reply(w, 200, map[string]bool{"unlocked": false})
}
func (s *server) changePassword(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if !decode(w, r, &request) {
		return
	}
	s.auth.Lock()
	defer s.auth.Unlock()
	if !s.requireKey(w) {
		return
	}
	err := keystore.ChangePassword(s.opts.ConfigDir, request.Old, request.New)
	switch {
	case errors.Is(err, keystore.ErrWrongPassword):
		fail(w, 401, "The current password is incorrect.")
		return
	case errors.Is(err, keystore.ErrWeakPassword):
		fail(w, 400, "Choose a new password of at least 12 characters.")
		return
	case err != nil:
		fail(w, 500, "The password could not be changed. Your keyfile was not replaced.")
		return
	}
	reply(w, 200, map[string]string{"message": "Password changed. Save a fresh keyfile backup."})
}
func (s *server) exportKey(w http.ResponseWriter, r *http.Request) {
	var request struct{}
	if !decode(w, r, &request) || !s.requireKey(w) {
		return
	}
	path, err := s.opts.Picker.SaveKey(r.Context())
	if errors.Is(err, ErrCanceled) {
		reply(w, 200, map[string]bool{"canceled": true})
		return
	}
	if err != nil {
		fail(w, 500, "The save dialog could not be opened. You can use 'tbcrypt export <path>' in the terminal.")
		return
	}
	s.auth.Lock()
	defer s.auth.Unlock()
	if !s.requireKey(w) {
		return
	}
	if err := keystore.Export(s.opts.ConfigDir, path); err != nil {
		if os.IsExist(err) {
			fail(w, 409, "A file already exists there. Choose a new backup filename.")
		} else {
			fail(w, 500, "The keyfile backup could not be saved. Choose a writable folder.")
		}
		return
	}
	reply(w, 200, map[string]string{"path": path})
}
func (s *server) pick(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Kind  string `json:"kind"`
		Title string `json:"title"`
	}
	if !decode(w, r, &request) {
		return
	}
	if request.Kind != "folder" && request.Kind != "files" {
		fail(w, 400, "Choose a folder or encrypted files.")
		return
	}
	if len(request.Title) > 200 {
		fail(w, 400, "The dialog title is too long.")
		return
	}
	if request.Title == "" {
		request.Title = "Choose for tbcrypt"
	}
	paths, err := s.opts.Picker.Pick(r.Context(), request.Kind, request.Title)
	if errors.Is(err, ErrCanceled) {
		reply(w, 200, map[string]bool{"canceled": true})
		return
	}
	if err != nil {
		fail(w, 500, "The file picker could not be opened. You can paste the path into the page instead.")
		return
	}
	if paths == nil {
		paths = []string{}
	}
	reply(w, 200, map[string]any{"paths": paths})
}
func (s *server) open(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Path string `json:"path"`
	}
	if !decode(w, r, &request) {
		return
	}
	path, err := existingDirectory(request.Path)
	if err != nil {
		fail(w, 403, "Choose a folder used by a job in this session.")
		return
	}
	s.mu.Lock()
	allowed := s.directories[pathKey(path)]
	s.mu.Unlock()
	if !allowed {
		fail(w, 403, "Only folders used by a job in this session can be opened here.")
		return
	}
	if err := s.opts.OpenPath(path); err != nil {
		fail(w, 500, "The folder could not be opened. Paste its path into your file manager.")
		return
	}
	reply(w, 200, map[string]bool{"opened": true})
}
