//go:build windows

// Package tray runs the Windows notification-area application.
package tray

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/systray"
	"github.com/ncruces/zenity"
	"github.com/ramst/tbcrypt/internal/autostart"
	"github.com/ramst/tbcrypt/internal/config"
	"github.com/ramst/tbcrypt/internal/keystore"
	"github.com/ramst/tbcrypt/internal/logging"
	"github.com/ramst/tbcrypt/internal/pipeline"
	"github.com/ramst/tbcrypt/internal/strip"
	"github.com/ramst/tbcrypt/internal/tbx"
	"github.com/ramst/tbcrypt/internal/watcher"
	"golang.org/x/sys/windows"
)

//go:embed assets/icon.ico
var icon []byte

type menus struct{ status, pause, choose, watch, encrypted, files, folder, password, export, startup, log, quit *systray.MenuItem }
type session struct {
	watcher *watcher.Watcher
	cancel  context.CancelFunc
	done    chan error
}
type app struct {
	dir     string
	logger  *slog.Logger
	config  config.Config
	key     *keystore.Key
	session *session
	warned  bool
}

// Run owns the main goroutine until Quit. Native dialogs and application work
// run outside onReady, keeping the systray message loop responsive.
func Run(configDir string) error {
	name, _ := windows.UTF16PtrFromString(`Local\tbcrypt-single-instance`)
	mutex, err := windows.CreateMutex(nil, false, name)
	if mutex != 0 {
		defer windows.CloseHandle(mutex)
	}
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return zenity.Info("tbcrypt is already running", zenity.Title("tbcrypt"))
	}
	if err != nil {
		return err
	}
	logger, closer, err := logging.Open(configDir)
	if err != nil {
		return err
	}
	defer closer.Close()
	a := &app{dir: configDir, logger: logger}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan struct{})
	result := make(chan error, 1)
	systray.Run(func() {
		systray.SetIcon(icon)
		systray.SetTooltip("tbcrypt")
		m := menus{}
		m.status = systray.AddMenuItem("Locked", "")
		m.status.Disable()
		systray.AddSeparator()
		m.pause = systray.AddMenuItem("Pause", "")
		m.choose = systray.AddMenuItem("Choose watch folder…", "")
		m.watch = systray.AddMenuItem("Open watch folder", "")
		m.encrypted = systray.AddMenuItem("Open encrypted folder", "")
		systray.AddSeparator()
		m.files = systray.AddMenuItem("Decrypt files…", "")
		m.folder = systray.AddMenuItem("Decrypt folder…", "")
		m.password = systray.AddMenuItem("Change password…", "")
		m.export = systray.AddMenuItem("Export keyfile…", "")
		systray.AddSeparator()
		m.startup = systray.AddMenuItemCheckbox("Start with Windows", "", false)
		m.log = systray.AddMenuItem("Open log", "")
		m.quit = systray.AddMenuItem("Quit", "")
		go func() {
			err := a.loop(ctx, m)
			if err != nil && !errors.Is(err, zenity.ErrCanceled) {
				logger.Error("tray stopped", "error", err)
				_ = zenity.Error(err.Error(), zenity.Title("tbcrypt"))
			}
			if errors.Is(err, zenity.ErrCanceled) {
				err = nil
			}
			result <- err
			close(finished)
			systray.Quit()
		}()
	}, func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			logger.Warn("shutdown timed out")
		}
	})
	select {
	case err := <-result:
		return err
	default:
		return nil
	}
}

func (a *app) prompt(title string) (string, error) {
	_, p, err := zenity.Password(zenity.Title(title))
	return p, err
}
func (a *app) newPassword() (string, error) {
	for {
		p, err := a.prompt("tbcrypt — new password (at least 12 characters)")
		if err != nil {
			return "", err
		}
		if len(p) < 12 {
			_ = zenity.Warning("Use a password of at least 12 bytes.", zenity.Title("tbcrypt"))
			continue
		}
		confirm, err := a.prompt("tbcrypt — confirm new password")
		if err != nil {
			return "", err
		}
		if p != confirm {
			_ = zenity.Warning("Passwords do not match. Please try again.", zenity.Title("tbcrypt"))
			continue
		}
		return p, nil
	}
}
func (a *app) startup() error {
	var err error
	a.config, err = config.Load(a.dir)
	if err != nil {
		return err
	}
	if _, err = os.Stat(filepath.Join(a.dir, "keyfile.json")); os.IsNotExist(err) {
		p, err := a.newPassword()
		if err != nil {
			return err
		}
		if err = keystore.Init(a.dir, p); err != nil {
			return err
		}
		a.key, err = keystore.Unlock(a.dir, p)
		if err != nil {
			return err
		}
		_ = zenity.Warning("Your files can ONLY be decrypted with this keyfile AND your password. If you lose either, the files are gone forever. Back up the keyfile now (USB drive / password manager) — not in TeraBox unencrypted folder alongside files.", zenity.Title("tbcrypt — permanent data loss warning"))
		if zenity.Question("Export keyfile backup…", zenity.Title("tbcrypt"), zenity.OKLabel("Export backup…"), zenity.CancelLabel("Later")) == nil {
			a.showError(a.export())
		}
	} else if err != nil {
		return err
	} else {
		for attempt := 0; attempt < 5; attempt++ {
			p, err := a.prompt("tbcrypt — unlock")
			if err != nil {
				return err
			}
			a.key, err = keystore.Unlock(a.dir, p)
			if err == nil {
				break
			}
			if !errors.Is(err, keystore.ErrWrongPassword) {
				return err
			}
			_ = zenity.Warning(fmt.Sprintf("Incorrect password. %d attempt(s) remaining.", 4-attempt), zenity.Title("tbcrypt"))
		}
		if a.key == nil {
			return errors.New("could not unlock after 5 attempts")
		}
	}
	if a.config.WatchDir == "" {
		a.config.WatchDir, err = zenity.SelectFile(zenity.Directory(), zenity.Title("tbcrypt — choose watch folder"))
		if err != nil {
			return err
		}
	}
	enabled, err := autostart.Enabled()
	if err != nil {
		return err
	}
	a.config.StartWithWindows = enabled
	return config.Save(a.dir, a.config)
}
func (a *app) start(ctx context.Context) error {
	c := a.config.Resolved()
	opts := pipeline.Options{WatchDir: c.WatchDir, OutputDir: c.OutputDir, DoneDir: c.DoneDir, ExiftoolPath: config.FindExiftool(c), Identity: a.key.Identity(), Recipient: a.key.Recipient(), Logger: a.logger}
	if err := pipeline.CleanTemp(opts); err != nil {
		return err
	}
	if opts.ExiftoolPath == "" && !a.warned {
		a.warned = true
		a.notify("Exiftool was not found. Files will be encrypted with their metadata intact.")
	}
	w := watcher.New(opts, a.logger)
	workerCtx, cancel := context.WithCancel(ctx)
	s := &session{w, cancel, make(chan error, 1)}
	a.session = s
	go func() { s.done <- w.Run(workerCtx) }()
	return nil
}
func (a *app) stop() error {
	if a.session == nil {
		return nil
	}
	s := a.session
	s.cancel()
	select {
	case err := <-s.done:
		a.session = nil
		return err
	case <-time.After(10 * time.Second):
		return errors.New("watcher did not stop within 10 seconds")
	}
}
func (a *app) loop(ctx context.Context, m menus) error {
	if err := a.startup(); err != nil {
		return err
	}
	if a.config.StartWithWindows {
		m.startup.Check()
	}
	if err := a.start(ctx); err != nil {
		return err
	}
	defer func() {
		if err := a.stop(); err != nil {
			a.logger.Warn("watcher shutdown incomplete", "error", err)
		}
	}()
	paused := false
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		var events <-chan watcher.Event
		if a.session != nil {
			events = a.session.watcher.Events()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-m.quit.ClickedCh:
			return nil
		case <-ticker.C:
			if a.session == nil {
				continue
			}
			s := a.session.watcher.Status()
			switch {
			case s.State == "Working":
				m.status.SetTitle(fmt.Sprintf("Encrypting %d of %d: %s", s.Done+1, s.Done+s.Queued+1, filepath.Base(s.Current)))
			case s.State == "Paused":
				m.status.SetTitle("Paused")
			case s.Failed > 0:
				m.status.SetTitle(fmt.Sprintf("%d failed — see log", s.Failed))
			default:
				m.status.SetTitle("Idle — watching " + a.config.WatchDir)
			}
		case event, ok := <-events:
			if !ok {
				if a.session != nil {
					err := <-a.session.done
					a.session = nil
					if err != nil {
						a.logger.Error("watcher stopped", "error", err)
						a.notify("Watcher stopped: " + err.Error())
						m.status.SetTitle("Watcher stopped — see log")
					}
				}
				continue
			}
			switch event.Kind {
			case watcher.Failed:
				a.notify("Could not encrypt " + filepath.Base(event.Path) + ": " + event.Err.Error())
			case watcher.Warning:
				var warning *strip.Warning
				if errors.As(event.Err, &warning) {
					if !a.warned {
						a.warned = true
						a.notify(event.Err.Error())
					}
				} else {
					a.notify("Watcher warning: " + event.Err.Error())
				}
			case watcher.BatchDone:
				if event.Count > 0 {
					a.notify(fmt.Sprintf("Encrypted %d files — ready to upload", event.Count))
				}
			}
		case <-m.pause.ClickedCh:
			if a.session == nil {
				continue
			}
			paused = !paused
			if paused {
				a.session.watcher.Pause()
				m.pause.SetTitle("Resume")
			} else {
				a.session.watcher.Resume()
				m.pause.SetTitle("Pause")
			}
		case <-m.choose.ClickedCh:
			folder, err := zenity.SelectFile(zenity.Directory(), zenity.Title("tbcrypt — choose watch folder"))
			if err != nil {
				a.showError(err)
				continue
			}
			if err = a.stop(); err != nil {
				a.showError(err)
				continue
			}
			previous := a.config
			a.config.WatchDir = folder
			// Empty stored paths represent defaults. Explicit overrides remain explicit.
			if err = config.Save(a.dir, a.config); err != nil {
				a.config = previous
				a.showError(err)
			}
			paused = false
			m.pause.SetTitle("Pause")
			a.showError(a.start(ctx))
		case <-m.watch.ClickedCh:
			a.showError(open(a.config.WatchDir))
		case <-m.encrypted.ClickedCh:
			path := a.config.Resolved().OutputDir
			err := os.MkdirAll(path, 0700)
			if err == nil {
				err = open(path)
			}
			a.showError(err)
		case <-m.log.ClickedCh:
			a.showError(open(filepath.Join(a.dir, "tbcrypt.log")))
		case <-m.export.ClickedCh:
			a.showError(a.export())
		case <-m.password.ClickedCh:
			old, err := a.prompt("tbcrypt — old password")
			if err != nil {
				a.showError(err)
				continue
			}
			next, err := a.newPassword()
			if err == nil {
				err = keystore.ChangePassword(a.dir, old, next)
			}
			a.showError(err)
		case <-m.startup.ClickedCh:
			enable := !a.config.StartWithWindows
			var err error
			if enable {
				var exe string
				exe, err = os.Executable()
				if err == nil {
					err = autostart.Enable(exe)
				}
			} else {
				err = autostart.Disable()
			}
			if err != nil {
				a.showError(err)
				continue
			}
			previous := a.config.StartWithWindows
			a.config.StartWithWindows = enable
			if err := config.Save(a.dir, a.config); err != nil {
				a.config.StartWithWindows = previous
				var rollback error
				if previous {
					var exe string
					exe, rollback = os.Executable()
					if rollback == nil {
						rollback = autostart.Enable(exe)
					}
				} else {
					rollback = autostart.Disable()
				}
				a.showError(errors.Join(err, rollback))
				continue
			}
			if enable {
				m.startup.Check()
			} else {
				m.startup.Uncheck()
			}
		case <-m.files.ClickedCh:
			paths, err := zenity.SelectFileMultiple(zenity.Title("tbcrypt — decrypt files"), zenity.FileFilter{Name: "TBX containers", Patterns: []string{"*.tbx"}})
			if err != nil {
				a.showError(err)
				continue
			}
			a.decrypt(ctx, paths)
		case <-m.folder.ClickedCh:
			path, err := zenity.SelectFile(zenity.Directory(), zenity.Title("tbcrypt — encrypted source folder"))
			if err != nil {
				a.showError(err)
				continue
			}
			a.decrypt(ctx, []string{path})
		}
	}
}
func (a *app) export() error {
	dest, err := zenity.SelectFileSave(zenity.Title("tbcrypt — export keyfile backup"), zenity.Filename("tbcrypt-keyfile.json"))
	if err != nil {
		return err
	}
	return keystore.Export(a.dir, dest)
}
func (a *app) showError(err error) {
	if err != nil && !errors.Is(err, zenity.ErrCanceled) {
		a.logger.Error("tray action failed", "error", err)
		_ = zenity.Error(err.Error(), zenity.Title("tbcrypt"))
	}
}
func (a *app) notify(message string) {
	go func() {
		if err := zenity.Notify(message, zenity.Title("tbcrypt")); err != nil {
			a.logger.Warn("notification failed", "error", err)
		}
	}()
}
func open(path string) error {
	verb, _ := windows.UTF16PtrFromString("open")
	target, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, target, nil, nil, windows.SW_SHOWNORMAL)
}
func (a *app) decrypt(ctx context.Context, paths []string) {
	dest, err := zenity.SelectFile(zenity.Directory(), zenity.Title("tbcrypt — restored destination folder"))
	if err != nil {
		a.showError(err)
		return
	}
	go func() {
		success, failed := 0, 0
		for _, src := range paths {
			info, err := os.Stat(src)
			if err != nil {
				failed++
				a.logger.Error("decrypt input failed", "path", src, "error", err)
				continue
			}
			one := func(path, out string) {
				if ctx.Err() != nil {
					return
				}
				if _, err := tbx.DecryptFile(path, out, a.key.Identity()); err != nil {
					failed++
					a.logger.Error("decrypt failed", "path", path, "error", err)
				} else {
					success++
				}
			}
			if !info.IsDir() {
				one(src, dest)
				continue
			}
			type target struct{ path, out string }
			var targets []target
			err = filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				if d.Type().IsRegular() && strings.EqualFold(filepath.Ext(path), ".tbx") {
					rel, err := filepath.Rel(src, filepath.Dir(path))
					if err != nil {
						return err
					}
					targets = append(targets, target{path, filepath.Join(dest, rel)})
				}
				return nil
			})
			if err != nil {
				failed++
				a.logger.Error("decrypt folder failed", "path", src, "error", err)
			}
			// Snapshot inputs before restoring: the destination may be inside src.
			for _, target := range targets {
				one(target.path, target.out)
			}
		}
		a.notify(fmt.Sprintf("Decrypted %d file(s); %d error(s).", success, failed))
	}()
}
