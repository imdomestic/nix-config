package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var errRuntimeSecret = errors.New("runtime secret must be a private regular file or protected systemd credential")

// systemd's root-owned 0440 files use a named-user ACL, not shared group access.
// Accept them only in its root-owned, read-only /run/credentials namespace.
func protectedSystemdCredential(path, directory string, file, parent os.FileInfo) bool {
	directory = filepath.Clean(directory)
	if directory == "." || !strings.HasPrefix(directory, "/run/credentials/") || filepath.Dir(path) != directory || !parent.IsDir() || parent.Mode().Perm()&0027 != 0 || parent.Mode().Perm()&0222 != 0 || file.Mode().Perm() != 0440 {
		return false
	}
	f, fok := file.Sys().(*syscall.Stat_t)
	p, pok := parent.Sys().(*syscall.Stat_t)
	return fok && pok && f.Uid == 0 && f.Gid == 0 && p.Uid == 0 && p.Gid == 0
}

func readRuntimeSecret(path string, limit int64) ([]byte, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, errRuntimeSecret
	}
	parentPath := filepath.Dir(path)
	parent, err := os.Lstat(parentPath)
	if err != nil || !parent.IsDir() {
		return nil, errRuntimeSecret
	}
	root, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, errRuntimeSecret
	}
	defer root.Close()
	openedParent, err := root.Stat(".")
	if err != nil || !os.SameFile(parent, openedParent) {
		return nil, errRuntimeSecret
	}
	name := filepath.Base(path)
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errRuntimeSecret
	}
	if info.Mode().Perm()&0077 != 0 && !protectedSystemdCredential(path, os.Getenv("CREDENTIALS_DIRECTORY"), info, openedParent) {
		return nil, errRuntimeSecret
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errRuntimeSecret
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || info.Mode() != opened.Mode() || info.Size() != opened.Size() {
		return nil, errRuntimeSecret
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errRuntimeSecret
	}
	return data, nil
}
