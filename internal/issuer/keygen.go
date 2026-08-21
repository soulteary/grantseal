// Package issuer contains the PRIVATE, issuer-side license logic: key
// generation, signing, license issuance and revocation-list creation.
//
// It lives under internal/ so that client code (which imports pkg/license and
// pkg/fingerprint) CANNOT import it. Private keys and signing logic never reach
// a client binary. Private keys must never be committed, logged, or embedded.
package issuer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// KeyPair holds a freshly generated Ed25519 key pair plus its key_id.
type KeyPair struct {
	KeyID      string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateKeyPair creates a new Ed25519 key pair using crypto/rand.
func GenerateKeyPair(keyID string) (*KeyPair, error) {
	if keyID == "" {
		return nil, fmt.Errorf("issuer: key_id must not be empty")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("issuer: generate key: %w", err)
	}
	return &KeyPair{KeyID: keyID, PublicKey: pub, PrivateKey: priv}, nil
}

// PublicKeyBase64 returns the Base64URL-encoded public key for distribution.
func (kp *KeyPair) PublicKeyBase64() string {
	return base64.URLEncoding.EncodeToString(kp.PublicKey)
}

// privateKeyBase64 returns the Base64URL-encoded private seed. Unexported to
// discourage accidental exposure; only the writer uses it.
func (kp *KeyPair) privateKeyBase64() string {
	// Store the 32-byte seed rather than the 64-byte expanded key.
	return base64.URLEncoding.EncodeToString(kp.PrivateKey.Seed())
}

// WriteKeyFiles writes the private key (0600) and public key (0644) to disk.
// It refuses to overwrite an existing private-key file unless `force` is set,
// and verifies the private file lands with restrictive permissions.
//
// Durability & failure semantics: both files are fsynced and the containing
// directory is fsynced so a crash cannot leave a truncated key on disk. The two
// files are written as a group but NOT transactionally: the private key is
// written first, and if the subsequent public-key write fails the already
// written private key is removed and an error is returned, so the caller never
// observes a private key without its matching public key. In no-force mode the
// private key is created with O_EXCL (never truncating an existing file); in
// force mode it is atomically replaced via a temp file + rename.
func (kp *KeyPair) WriteKeyFiles(dir string, force bool) (privPath, pubPath string, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("issuer: mkdir: %w", err)
	}
	privPath = filepath.Join(dir, kp.KeyID+"-private.key")
	pubPath = filepath.Join(dir, kp.KeyID+"-public.key")

	if err := writeKeyFileDurable(privPath, []byte(kp.privateKeyBase64()+"\n"), 0o600, force); err != nil {
		return "", "", fmt.Errorf("issuer: write private key: %w", err)
	}
	// Enforce 0600 in case umask relaxed it.
	if err := os.Chmod(privPath, 0o600); err != nil {
		return "", "", fmt.Errorf("issuer: chmod private key: %w", err)
	}

	if err := writeKeyFileDurable(pubPath, []byte(kp.PublicKeyBase64()+"\n"), 0o644, true); err != nil {
		// Roll back the private key so we never leave it without its public
		// counterpart (see the group-write semantics above).
		_ = os.Remove(privPath)
		return "", "", fmt.Errorf("issuer: write public key: %w", err)
	}
	return privPath, pubPath, nil
}

// writeKeyFileDurable writes data to path, fsyncing both the file and its
// parent directory. In no-force mode it uses O_CREATE|O_EXCL so an existing
// file is never clobbered; in force mode it atomically replaces via a sibling
// temp file + rename (without truncating the destination first).
func writeKeyFileDurable(path string, data []byte, perm os.FileMode, force bool) error {
	if !force {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
		if err != nil {
			if os.IsExist(err) {
				return fmt.Errorf("refusing to overwrite existing file %q (use force)", path)
			}
			return err
		}
		if _, err := f.Write(data); err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return err
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		return fsyncDirIssuer(filepath.Dir(path))
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-key-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return fsyncDirIssuer(dir)
}

// fsyncDirIssuer fsyncs a directory so a create/rename entry survives a crash.
// Directory fsync is not supported on Windows, so its errors are ignored there.
func fsyncDirIssuer(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		if runtime.GOOS == "windows" {
			return nil
		}
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		if runtime.GOOS == "windows" {
			return nil
		}
		return err
	}
	return d.Close()
}

// LoadPrivateKey reads a Base64URL-encoded Ed25519 seed from a file and returns
// the private key. It rejects world/group-readable files as a safety check.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("issuer: stat private key: %w", err)
	}
	// Unix permission bits are not meaningfully enforced on Windows, where files
	// always report a mode like 0666/0444. Only apply the strict-mode check on
	// platforms whose file system honours Unix permissions.
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("issuer: private key %q has overly permissive mode %o (want 0600)", path, fi.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("issuer: read private key: %w", err)
	}
	return DecodePrivateKey(string(data))
}

// DecodePrivateKey decodes a Base64URL seed (or full key) into a private key.
// Only base64.URLEncoding is accepted, matching privateKeyBase64's output; the
// standard-alphabet fallback was removed to keep the on-disk encoding strict
// and unambiguous.
func DecodePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	trimmed := trimSpace(encoded)
	raw, err := base64.URLEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("issuer: decode private key base64: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("issuer: invalid private key length %d", len(raw))
	}
}

// trimSpace removes surrounding whitespace/newlines without importing strings
// twice (kept local to avoid pulling extra deps into intent).
func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
