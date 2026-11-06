package web

import (
	"context"
	"errors"
	"github.com/ncruces/zenity"
)

type nativePicker struct{}

func (nativePicker) Pick(ctx context.Context, kind, title string) ([]string, error) {
	options := []zenity.Option{zenity.Title(title), zenity.Context(ctx)}
	var paths []string
	var err error
	if kind == "folder" {
		var path string
		path, err = zenity.SelectFile(append(options, zenity.Directory())...)
		if err == nil {
			paths = []string{path}
		}
	} else {
		paths, err = zenity.SelectFileMultiple(append(options, zenity.FileFilter{Name: "Encrypted TBX files", Patterns: []string{"*.tbx"}})...)
	}
	if errors.Is(err, zenity.ErrCanceled) {
		err = ErrCanceled
	}
	return paths, err
}
func (nativePicker) SaveKey(ctx context.Context) (string, error) {
	path, err := zenity.SelectFileSave(zenity.Title("Save tbcrypt keyfile backup"), zenity.Filename("tbcrypt-keyfile.json"), zenity.Context(ctx))
	if errors.Is(err, zenity.ErrCanceled) {
		err = ErrCanceled
	}
	return path, err
}
