package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteExclusiveOpenError(t *testing.T) {
	orig := fsOpenFile
	fsOpenFile = func(string, int, os.FileMode) (*os.File, error) { return nil, errors.New("open denied") }
	t.Cleanup(func() { fsOpenFile = orig })
	if err := writeExclusive(filepath.Join(t.TempDir(), "f"), []byte("x"), 0o600); err == nil {
		t.Fatal("want error when open fails")
	}
}

func TestWriteAtomicReplaceTempError(t *testing.T) {
	orig := fsCreateTemp
	fsCreateTemp = func(string, string) (*os.File, error) { return nil, errors.New("temp denied") }
	t.Cleanup(func() { fsCreateTemp = orig })
	if err := writeAtomicReplace(filepath.Join(t.TempDir(), "f"), []byte("x"), 0o600); err == nil {
		t.Fatal("want error when create temp fails")
	}
}

func TestWriteAtomicReplaceRenameError(t *testing.T) {
	orig := fsRename
	fsRename = func(string, string) error { return errors.New("rename denied") }
	t.Cleanup(func() { fsRename = orig })
	if err := writeAtomicReplace(filepath.Join(t.TempDir(), "f"), []byte("x"), 0o600); err == nil {
		t.Fatal("want error when rename fails")
	}
}

func TestFsyncDirOpenErrorNonWindows(t *testing.T) {
	origOpen, origGOOS := fsOpen, runtimeGOOS
	fsOpen = func(string) (*os.File, error) { return nil, errors.New("open denied") }
	runtimeGOOS = "linux"
	t.Cleanup(func() { fsOpen, runtimeGOOS = origOpen, origGOOS })
	if err := fsyncDir(t.TempDir()); err == nil {
		t.Fatal("want error on non-windows open failure")
	}
}

func TestFsyncDirOpenErrorWindowsIgnored(t *testing.T) {
	origOpen, origGOOS := fsOpen, runtimeGOOS
	fsOpen = func(string) (*os.File, error) { return nil, errors.New("open denied") }
	runtimeGOOS = "windows"
	t.Cleanup(func() { fsOpen, runtimeGOOS = origOpen, origGOOS })
	if err := fsyncDir(t.TempDir()); err != nil {
		t.Fatalf("windows open error should be ignored, got %v", err)
	}
}

// TestWriteExclusiveWriteError returns a read-only file so Write fails,
// covering the write-failure arm of writeExclusive.
func TestWriteExclusiveWriteError(t *testing.T) {
	orig := fsOpenFile
	fsOpenFile = func(name string, _ int, _ os.FileMode) (*os.File, error) {
		f, err := os.Create(name)
		if err != nil {
			return nil, err
		}
		_ = f.Close()
		return os.OpenFile(name, os.O_RDONLY, 0o600)
	}
	t.Cleanup(func() { fsOpenFile = orig })
	if err := writeExclusive(filepath.Join(t.TempDir(), "f"), []byte("data"), 0o600); err == nil {
		t.Fatal("want error writing to read-only file")
	}
}

// TestWriteAtomicReplaceWriteError returns a read-only temp file so Write fails.
func TestWriteAtomicReplaceWriteError(t *testing.T) {
	orig := fsCreateTemp
	fsCreateTemp = func(dir, pattern string) (*os.File, error) {
		f, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		name := f.Name()
		_ = f.Close()
		return os.OpenFile(name, os.O_RDONLY, 0o600)
	}
	t.Cleanup(func() { fsCreateTemp = orig })
	if err := writeAtomicReplace(filepath.Join(t.TempDir(), "f"), []byte("data"), 0o600); err == nil {
		t.Fatal("want error writing to read-only temp file")
	}
}
