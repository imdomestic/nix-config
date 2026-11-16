package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type secretInfo struct {
	mode     os.FileMode
	uid, gid uint32
}

func (i secretInfo) Name() string       { return "secret" }
func (i secretInfo) Size() int64        { return 64 }
func (i secretInfo) Mode() os.FileMode  { return i.mode }
func (i secretInfo) ModTime() time.Time { return time.Time{} }
func (i secretInfo) IsDir() bool        { return i.mode.IsDir() }
func (i secretInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid, Gid: i.gid} }

func TestProtectedSystemdCredentialACLMode(t *testing.T) {
	file := secretInfo{mode: 0440}
	parent := secretInfo{mode: os.ModeDir | 0550}
	path := "/run/credentials/agy-proxy.service/client-key"
	dir := filepath.Dir(path)
	if !protectedSystemdCredential(path, dir, file, parent) {
		t.Fatal("systemd's root-owned ACL credential was rejected")
	}
	for _, tc := range []struct {
		path, dir    string
		file, parent secretInfo
	}{
		{path, "", file, parent},
		{path, "/run/credentials/other.service", file, parent},
		{"/tmp/credentials/client-key", "/tmp/credentials", file, parent},
		{path, dir, secretInfo{mode: 0444}, parent},
		{path, dir, secretInfo{mode: 0640}, parent},
		{path, dir, secretInfo{mode: 0440, uid: 1000}, parent},
		{path, dir, file, secretInfo{mode: os.ModeDir | 0750}},
		{path, dir, file, secretInfo{mode: os.ModeDir | 0555}},
		{path, dir, file, secretInfo{mode: os.ModeDir | 0550, gid: 1000}},
	} {
		if protectedSystemdCredential(tc.path, tc.dir, tc.file, tc.parent) {
			t.Fatal("unprotected credential shape was accepted")
		}
	}
}

func TestRuntimeSecretOrdinaryFilesStayPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client-key")
	if err := os.WriteFile(path, []byte("fixture-not-a-real-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRuntimeSecret(path, 4096); err != nil {
		t.Fatal(err)
	}
	if _, err := readRuntimeSecret(path, 4); err == nil {
		t.Fatal("secret size limit ignored")
	}
	for _, mode := range []os.FileMode{0640, 0644, 0440} {
		_ = os.Chmod(path, mode)
		if _, err := readRuntimeSecret(path, 4096); err == nil {
			t.Fatal("ordinary group/world-readable secret accepted")
		}
	}
	_ = os.Chmod(path, 0600)
	link := path + ".link"
	_ = os.Symlink(path, link)
	if _, err := readRuntimeSecret(link, 4096); err == nil {
		t.Fatal("secret symlink followed")
	}
}
