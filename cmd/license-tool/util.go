package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func timeNow() time.Time { return time.Now().UTC() }

// usageError marks an error as a command-usage problem (missing/invalid flags)
// so main can map it to exit code 2, distinct from runtime failures (exit 1).
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// writeFileNoClobber durably writes data to path.
//
// In no-force mode it creates the file with O_CREATE|O_EXCL so that an existing
// file is never clobbered and there is no time-of-check/time-of-use race: the
// kernel refuses the open if the path already exists. In force mode it writes
// to a sibling temp file, fsyncs the temp file, atomically renames it over the
// destination (never truncating the destination first), then fsyncs the parent
// directory so the rename itself is durable. Both paths fsync file contents so
// a crash cannot leave a half-written key/license on disk.
func writeFileNoClobber(path string, data []byte, perm os.FileMode, force bool) error {
	if !force {
		return writeExclusive(path, data, perm)
	}
	return writeAtomicReplace(path, data, perm)
}

// writeExclusive creates path with O_CREATE|O_EXCL|O_WRONLY, writes data,
// fsyncs the file, and fsyncs the parent directory so the new entry is durable.
// It fails (without clobbering) if the path already exists.
func writeExclusive(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("output %q already exists (use -force to overwrite)", path)
		}
		return fmt.Errorf("create output file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write output file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("fsync output file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close output file: %w", err)
	}
	return fsyncDir(filepath.Dir(path))
}

// writeAtomicReplace writes data to a sibling temp file, fsyncs it, renames it
// over path (atomic replace, no prior truncation of the destination), then
// fsyncs the parent directory so the rename is durable across a crash.
func writeAtomicReplace(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return fsyncDir(dir)
}

// fsyncDir fsyncs a directory so that a create/rename entry within it survives
// a crash. A failure to open or sync the directory is not fatal on platforms
// that do not support directory fsync (e.g. Windows), so those errors are
// ignored there; on POSIX the sync error is returned.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		if runtime.GOOS == "windows" {
			return nil
		}
		return fmt.Errorf("open dir for fsync: %w", err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		if runtime.GOOS == "windows" {
			return nil
		}
		return fmt.Errorf("fsync dir: %w", err)
	}
	return d.Close()
}

// readPublicKeyFile loads a Base64URL public key file's contents (trimmed).
func readPublicKeyFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read public key: %w", err)
	}
	return string(bytes.TrimSpace(b)), nil
}

// marshalIndentEnvelope pretty-prints any value as JSON without HTML escaping.
func marshalIndentEnvelope(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
