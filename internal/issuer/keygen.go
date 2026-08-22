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

// Filesystem/randomness seams: defaults are the real implementations. Tests
// override these to exercise the key-generation and durable-write failure arms
// that a healthy environment never reaches.
var (
	edGenerateKey = ed25519.GenerateKey
	fsCreateTemp  = os.CreateTemp
	fsRename      = os.Rename
	fsOpen        = os.Open
	runtimeGOOS   = runtime.GOOS
)

// GenerateKeyPair creates a new Ed25519 key pair using crypto/rand.
func GenerateKeyPair(keyID string) (*KeyPair, error) {
	if keyID == "" {
		return nil, fmt.Errorf("issuer: key_id must not be empty")
	}
	pub, priv, err := edGenerateKey(rand.Reader)
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
// It refuses to overwrite either existing target file unless `force` is set,
// and verifies the private file lands with restrictive permissions.
//
// Durability & failure semantics. Both key files are first fully staged to
// sibling temp files in their own directory (data written, chmod, fsync,
// close) so that no failure while producing the bytes ever touches an existing
// target. Before committing, the staged private key is reloaded from disk, its
// public counterpart derived, and compared byte-for-byte with the staged
// public key, guaranteeing the two committed files are a matching pair.
//
// Two ordinary files on disk cannot give a true cross-file atomic transaction
// (there is no filesystem primitive to rename two files as one unit). This
// function therefore does NOT claim absolute atomicity. Instead it provides
// staging + a recoverable commit with a private-key-first bias:
//
//   - no-force: both targets are checked up front; if either already exists no
//     file is created or modified at all.
//   - force: any existing targets are first moved aside to same-directory
//     backups; the staged private key is committed first, then the staged
//     public key; if any commit step fails we make a best effort to restore the
//     previous private and public key from backup. A public-key commit failure
//     must NEVER delete an existing or already-committed private key: when only
//     one file can survive we keep the valid private key.
//
// On success the temp files and backups are removed. On failure we still make a
// best effort to clean up our own staged temp/backup files, but we never delete
// a target file we cannot confidently attribute to this call.
func (kp *KeyPair) WriteKeyFiles(dir string, force bool) (privPath, pubPath string, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("issuer: mkdir: %w", err)
	}
	privPath = filepath.Join(dir, kp.KeyID+"-private.key")
	pubPath = filepath.Join(dir, kp.KeyID+"-public.key")

	// No-force contract: never modify anything if either target exists.
	if !force {
		if _, statErr := os.Stat(privPath); statErr == nil {
			return "", "", fmt.Errorf("issuer: refusing to overwrite existing file %q (use force)", privPath)
		} else if !os.IsNotExist(statErr) {
			return "", "", fmt.Errorf("issuer: stat private key: %w", statErr)
		}
		if _, statErr := os.Stat(pubPath); statErr == nil {
			return "", "", fmt.Errorf("issuer: refusing to overwrite existing file %q (use force)", pubPath)
		} else if !os.IsNotExist(statErr) {
			return "", "", fmt.Errorf("issuer: stat public key: %w", statErr)
		}
	}

	// Stage both key files to sibling temp files. Any failure here leaves the
	// existing targets untouched.
	privTmp, err := stageKeyFile(dir, []byte(kp.privateKeyBase64()+"\n"), 0o600)
	if err != nil {
		return "", "", fmt.Errorf("issuer: stage private key: %w", err)
	}
	defer func() { _ = os.Remove(privTmp) }()

	pubTmp, err := stageKeyFile(dir, []byte(kp.PublicKeyBase64()+"\n"), 0o644)
	if err != nil {
		return "", "", fmt.Errorf("issuer: stage public key: %w", err)
	}
	defer func() { _ = os.Remove(pubTmp) }()

	// Reload the staged private key, derive its public key, and confirm it
	// matches the staged public key so we only ever commit a coherent pair.
	if err := verifyStagedPair(privTmp, pubTmp); err != nil {
		return "", "", fmt.Errorf("issuer: verify staged key pair: %w", err)
	}

	if err := commitStagedKeyFiles(dir, privTmp, pubTmp, privPath, pubPath); err != nil {
		return "", "", err
	}

	// Enforce 0600 on the committed private key in case umask relaxed it.
	if err := os.Chmod(privPath, 0o600); err != nil {
		return "", "", fmt.Errorf("issuer: chmod private key: %w", err)
	}
	return privPath, pubPath, nil
}

// stageKeyFile fully writes data to a sibling temp file in dir with the given
// permissions, fsyncing and closing it. On any error the temp file is removed
// and no partial artifact is left behind. It returns the temp file path.
func stageKeyFile(dir string, data []byte, perm os.FileMode) (string, error) {
	tmp, err := fsCreateTemp(dir, ".tmp-key-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", err
	}
	return tmpName, nil
}

// verifyStagedPair reloads the staged private key, derives its public key and
// compares it byte-for-byte with the staged public key file's decoded bytes,
// ensuring the two files we are about to commit are a matching key pair.
func verifyStagedPair(privTmp, pubTmp string) error {
	priv, err := LoadPrivateKey(privTmp)
	if err != nil {
		return err
	}
	derived, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("private key public part is not ed25519")
	}
	pubData, err := os.ReadFile(pubTmp)
	if err != nil {
		return err
	}
	staged, err := base64.URLEncoding.DecodeString(trimSpace(string(pubData)))
	if err != nil {
		return fmt.Errorf("decode staged public key: %w", err)
	}
	if !ed25519.PublicKey(staged).Equal(derived) {
		return fmt.Errorf("staged public key does not match staged private key")
	}
	return nil
}

// commitStagedKeyFiles moves the staged temp files into place using a
// recoverable, private-key-first commit order:
//
//  1. Back up any existing target files to same-directory siblings.
//  2. Rename the staged private key into place; on failure restore backups.
//  3. Rename the staged public key into place; on failure restore the public
//     backup only, leaving the freshly committed private key intact (we never
//     delete a valid private key because the public commit failed).
//
// After a successful private-key rename the caller must not remove privTmp
// (it no longer exists under that name); the outer deferred cleanup tolerates a
// missing file. On success the backups are removed.
func commitStagedKeyFiles(dir, privTmp, pubTmp, privPath, pubPath string) error {
	privBak, err := backupExisting(dir, privPath)
	if err != nil {
		return fmt.Errorf("issuer: back up existing private key: %w", err)
	}
	pubBak, err := backupExisting(dir, pubPath)
	if err != nil {
		// Restore the private backup before failing so nothing is left moved.
		restoreBackup(privBak, privPath)
		return fmt.Errorf("issuer: back up existing public key: %w", err)
	}

	// Commit the private key first: it is the irreplaceable secret.
	if err := fsRename(privTmp, privPath); err != nil {
		restoreBackup(privBak, privPath)
		restoreBackup(pubBak, pubPath)
		return fmt.Errorf("issuer: commit private key: %w", err)
	}
	if err := fsyncDirIssuer(dir); err != nil {
		// The rename may or may not be durable; restore best-effort and fail.
		_ = os.Remove(privPath)
		restoreBackup(privBak, privPath)
		restoreBackup(pubBak, pubPath)
		return fmt.Errorf("issuer: sync dir after private key: %w", err)
	}

	// Commit the public key. On failure keep the new private key (do NOT delete
	// it) and only restore the previous public key so the private key is never
	// lost because its public counterpart failed to land. The new private key
	// is already safely committed, so its stale backup can be discarded.
	if err := fsRename(pubTmp, pubPath); err != nil {
		restoreBackup(pubBak, pubPath)
		removeBackup(privBak)
		return fmt.Errorf("issuer: commit public key: %w", err)
	}
	if err := fsyncDirIssuer(dir); err != nil {
		restoreBackup(pubBak, pubPath)
		removeBackup(privBak)
		return fmt.Errorf("issuer: sync dir after public key: %w", err)
	}

	// Both files committed: discard the now-stale backups.
	removeBackup(privBak)
	removeBackup(pubBak)
	return nil
}

// backupExisting moves an existing target file to a same-directory sibling so
// it can be restored if a later commit step fails. It returns "" when the
// target does not exist (nothing to back up). Windows cannot rename onto an
// existing destination, so callers rename the backup back rather than relying
// on replace semantics during recovery.
func backupExisting(dir, path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	tmp, err := fsCreateTemp(dir, ".bak-key-*")
	if err != nil {
		return "", err
	}
	bakName := tmp.Name()
	_ = tmp.Close()
	// Remove the placeholder so the rename has a free destination on Windows,
	// whose rename refuses to overwrite an existing file.
	_ = os.Remove(bakName)
	if err := fsRename(path, bakName); err != nil {
		return "", err
	}
	return bakName, nil
}

// restoreBackup best-effort renames a backup created by backupExisting back to
// its original path. A "" backup means there was nothing to restore.
func restoreBackup(bak, path string) {
	if bak == "" {
		return
	}
	// Clear any partially committed file at the destination first (Windows
	// rename will not overwrite it).
	_ = os.Remove(path)
	_ = fsRename(bak, path)
}

// removeBackup deletes a backup once its target has been committed successfully.
func removeBackup(bak string) {
	if bak == "" {
		return
	}
	_ = os.Remove(bak)
}

// fsyncDirIssuer fsyncs a directory so a create/rename entry survives a crash.
// Directory fsync is not supported on Windows, so its errors are ignored there.
func fsyncDirIssuer(dir string) error {
	d, err := fsOpen(dir)
	if err != nil {
		if runtimeGOOS == "windows" {
			return nil
		}
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		if runtimeGOOS == "windows" {
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
