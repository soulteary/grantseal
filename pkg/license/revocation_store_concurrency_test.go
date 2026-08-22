package license_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/soulteary/grantseal/pkg/license"
)

// digestFor builds a RevocationState with a caller-chosen digest so tests can
// simulate same-seq/same-digest (idempotent) vs same-seq/different-digest
// (rollback) without signing a real list.
func stateFor(listID string, seq uint64, digest string) *license.RevocationState {
	return &license.RevocationState{
		ListID:        listID,
		Sequence:      seq,
		IssuedAt:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		PayloadDigest: digest,
	}
}

// runStoreClassification exercises the atomic CheckAndSaveRevocationState
// contract against any store implementation.
func runStoreClassification(t *testing.T, store license.RevocationStateStore) {
	t.Helper()
	// First accept seq=5.
	if err := store.CheckAndSaveRevocationState(stateFor("L", 5, "d5")); err != nil {
		t.Fatalf("accept seq=5: %v", err)
	}
	// Idempotent: same seq + same digest is accepted without error.
	if err := store.CheckAndSaveRevocationState(stateFor("L", 5, "d5")); err != nil {
		t.Fatalf("idempotent seq=5 same digest: %v", err)
	}
	// Same seq, different digest -> rollback, no change.
	if err := store.CheckAndSaveRevocationState(stateFor("L", 5, "dX")); license.CodeOf(err) != license.CodeRevocationRollback {
		t.Fatalf("same seq different digest: want CodeRevocationRollback, got %v", err)
	}
	// Lower seq -> stale, no change.
	if err := store.CheckAndSaveRevocationState(stateFor("L", 4, "d4")); license.CodeOf(err) != license.CodeRevocationStale {
		t.Fatalf("lower seq: want CodeRevocationStale, got %v", err)
	}
	// Higher seq -> advance.
	if err := store.CheckAndSaveRevocationState(stateFor("L", 6, "d6")); err != nil {
		t.Fatalf("accept seq=6: %v", err)
	}
	got, err := store.LoadRevocationState("L")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got == nil || got.Sequence != 6 || got.PayloadDigest != "d6" {
		t.Fatalf("high-water after advance: got %+v", got)
	}
}

func TestMemStoreCheckAndSaveClassification(t *testing.T) {
	runStoreClassification(t, license.NewMemRevocationStateStore())
}

func TestFileStoreCheckAndSaveClassification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rev.state")
	store, err := license.NewFileRevocationStateStore(path, []byte("hmac-key"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	runStoreClassification(t, store)
}

// TestStoreConcurrentSeqAlwaysHighWater fires many concurrent seq=5 and seq=6
// transactions and asserts the final high-water mark is always 6 (never
// regressed by a lost update).
func TestStoreConcurrentSeqAlwaysHighWater(t *testing.T) {
	stores := map[string]license.RevocationStateStore{
		"mem": license.NewMemRevocationStateStore(),
	}
	fpath := filepath.Join(t.TempDir(), "rev.state")
	fs, err := license.NewFileRevocationStateStore(fpath, []byte("k"))
	if err != nil {
		t.Fatalf("file store: %v", err)
	}
	stores["file"] = fs

	for name, store := range stores {
		t.Run(name, func(t *testing.T) {
			var wg sync.WaitGroup
			for i := 0; i < 50; i++ {
				wg.Add(2)
				go func() { defer wg.Done(); _ = store.CheckAndSaveRevocationState(stateFor("L", 5, "d5")) }()
				go func() { defer wg.Done(); _ = store.CheckAndSaveRevocationState(stateFor("L", 6, "d6")) }()
			}
			wg.Wait()
			got, lerr := store.LoadRevocationState("L")
			if lerr != nil {
				t.Fatalf("load: %v", lerr)
			}
			if got == nil || got.Sequence != 6 {
				t.Fatalf("final high-water must be 6, got %+v", got)
			}
		})
	}
}

// TestTwoFileStoresSamePathNoRegress verifies that two independent
// FileRevocationStateStore instances over the SAME path coordinate through the
// shared per-path lock: concurrent writes never regress the high-water mark.
func TestTwoFileStoresSamePathNoRegress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.state")
	a, err := license.NewFileRevocationStateStore(path, []byte("k"))
	if err != nil {
		t.Fatalf("store a: %v", err)
	}
	// A different spelling of the same path must resolve to the same lock.
	b, err := license.NewFileRevocationStateStore(filepath.Join(filepath.Dir(path), ".", filepath.Base(path)), []byte("k"))
	if err != nil {
		t.Fatalf("store b: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = a.CheckAndSaveRevocationState(stateFor("L", 6, "d6")) }()
		go func() { defer wg.Done(); _ = b.CheckAndSaveRevocationState(stateFor("L", 5, "d5")) }()
	}
	wg.Wait()

	got, err := a.LoadRevocationState("L")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got == nil || got.Sequence != 6 {
		t.Fatalf("shared-path high-water must be 6, got %+v", got)
	}
}

// TestFileStoreCorruptExistingNotOverwritten asserts that when the on-disk
// state is tampered (fails its integrity check), a CheckAndSave transaction
// returns the integrity error and does NOT silently overwrite the corrupt file.
func TestFileStoreCorruptExistingNotOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rev.state")
	store, err := license.NewFileRevocationStateStore(path, []byte("k"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.CheckAndSaveRevocationState(stateFor("L", 3, "d3")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Corrupt the MAC on disk.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m["mac"] = json.RawMessage(`"deadbeef"`)
	tampered, _ := json.Marshal(m)
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read tampered: %v", err)
	}

	if err := store.CheckAndSaveRevocationState(stateFor("L", 4, "d4")); license.CodeOf(err) != license.CodeRevocationStateIntegrityFailure {
		t.Fatalf("corrupt existing: want CodeRevocationStateIntegrityFailure, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("corrupt state file must not be overwritten by a failed transaction")
	}
}
