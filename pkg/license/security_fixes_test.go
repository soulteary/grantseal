package license_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/soulteary/grantseal/pkg/license"
)

// #8 Strict Base64: AddPublicKeyBase64 must accept ONLY URL-safe Base64. A
// standard-alphabet encoding that uses '+' or '/' must be rejected.
func TestAddPublicKeyBase64StrictURLEncoding(t *testing.T) {
	// Search for a public key whose standard Base64 encoding differs from its
	// URL-safe encoding (i.e. contains '+' or '/'). Such keys are common; a
	// few draws will find one deterministically enough for a test.
	var pub ed25519.PublicKey
	var std, url string
	found := false
	for i := 0; i < 512; i++ {
		p, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		s := base64.StdEncoding.EncodeToString(p)
		u := base64.URLEncoding.EncodeToString(p)
		if s != u {
			pub, std, url = p, s, u
			found = true
			break
		}
	}
	if !found {
		t.Skip("could not find a key whose std/url base64 differ")
	}

	// URL-safe encoding: must succeed and round-trip to the same key.
	ring := license.NewKeyRing()
	if err := ring.AddPublicKeyBase64("k-url", url); err != nil {
		t.Fatalf("URL-safe encoding should be accepted, got %v", err)
	}

	// Standard encoding (contains '+' or '/'): must be rejected as malformed.
	ring2 := license.NewKeyRing()
	err := ring2.AddPublicKeyBase64("k-std", std)
	if err == nil {
		t.Fatalf("standard (non-URL-safe) base64 %q should be rejected", std)
	}
	if license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("standard base64 rejection: want CodeMalformed, got %s", license.CodeOf(err))
	}
	_ = pub
}

// #7 Revocation: ParseRevocationEnvelope rejects input above MaxRevocationFileSize.
func TestParseRevocationEnvelopeSizeCap(t *testing.T) {
	big := make([]byte, license.MaxRevocationFileSize+1)
	for i := range big {
		big[i] = 'x'
	}
	_, err := license.ParseRevocationEnvelope(big)
	if license.CodeOf(err) != license.CodeFileTooLarge {
		t.Fatalf("oversized revocation data: want CodeFileTooLarge, got %s", license.CodeOf(err))
	}
}

// #7 Revocation: LoadRevocationList rejects a validly-signed list whose entry
// count exceeds MaxRevokedIDs, returning CodeFileTooLarge.
func TestLoadRevocationListEntryCap(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ids := make([]string, license.MaxRevokedIDs+1)
	for i := range ids {
		ids[i] = "lic_" + itoaExt(i)
	}
	revEnv, err := buildRevocation(t, s, ids...)
	if err != nil {
		t.Fatalf("build revocation: %v", err)
	}
	revData, err := json.Marshal(revEnv)
	if err != nil {
		t.Fatalf("marshal revocation: %v", err)
	}
	ring := ringWith(t, "k1", pub)
	_, err = license.LoadRevocationList(ring, revData, time.Now().UTC())
	if license.CodeOf(err) != license.CodeFileTooLarge {
		t.Fatalf("over-cap revoked ids: want CodeFileTooLarge, got %s (err=%v)", license.CodeOf(err), err)
	}
}

// itoaExt is a small base-10 formatter local to this test file.
func itoaExt(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
