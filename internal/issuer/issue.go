package issuer

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/soulteary/grantseal/pkg/license"
)

// IssueRequest describes the license to issue. It mirrors the fields an issuer
// controls; ids/serials are generated with crypto/rand if omitted.
type IssueRequest struct {
	LicenseID         string
	SerialNumber      string
	ProductID         string
	CustomerID        string
	CustomerName      string
	Edition           license.Edition
	LicenseType       license.LicenseType
	IssuedAt          *time.Time
	NotBefore         *time.Time
	ExpiresAt         *time.Time
	GracePeriodDays   int
	Features          []string
	Limits            map[string]int64
	DeviceBinding     license.DeviceBinding
	VersionConstraint license.VersionConstraint
	Metadata          map[string]string
}

// BuildPayload assembles a validated Payload, generating a cryptographically
// random license_id and serial_number when the request omits them. It runs the
// same static validation the client enforces so issuers cannot mint invalid
// licenses.
func BuildPayload(req IssueRequest) (*license.Payload, error) {
	issuedAt := time.Now().UTC()
	if req.IssuedAt != nil {
		issuedAt = req.IssuedAt.UTC()
	}
	licenseID := req.LicenseID
	if licenseID == "" {
		id, err := randomID(16)
		if err != nil {
			return nil, err
		}
		licenseID = "lic_" + id
	}
	serial := req.SerialNumber
	if serial == "" {
		s, err := randomSerial()
		if err != nil {
			return nil, err
		}
		serial = s
	}

	p := &license.Payload{
		SchemaVersion:     license.SchemaVersion,
		LicenseID:         licenseID,
		SerialNumber:      serial,
		ProductID:         req.ProductID,
		CustomerID:        req.CustomerID,
		CustomerName:      req.CustomerName,
		Edition:           req.Edition,
		LicenseType:       req.LicenseType,
		IssuedAt:          issuedAt,
		NotBefore:         utcPtr(req.NotBefore),
		ExpiresAt:         utcPtr(req.ExpiresAt),
		GracePeriodDays:   req.GracePeriodDays,
		Features:          req.Features,
		Limits:            req.Limits,
		DeviceBinding:     req.DeviceBinding,
		VersionConstraint: req.VersionConstraint,
		Metadata:          req.Metadata,
	}
	if p.DeviceBinding.Mode == "" {
		p.DeviceBinding.Mode = license.DeviceModeNone
	}
	// Note: full static validation (which requires key_id) runs in
	// Signer.SignPayload after the signer stamps the key_id.
	return p, nil
}

// Issue builds and signs a license in one step, returning the envelope. It runs
// full static validation (with the signer's key_id stamped) so issuers cannot
// mint structurally invalid licenses via this path.
func Issue(s *Signer, req IssueRequest) (*license.Envelope, error) {
	p, err := BuildPayload(req)
	if err != nil {
		return nil, err
	}
	p.KeyID = s.KeyID()
	if p.SchemaVersion == 0 {
		p.SchemaVersion = license.SchemaVersion
	}
	if err := license.ValidatePayloadStatic(p); err != nil {
		return nil, fmt.Errorf("issuer: invalid license: %w", err)
	}
	return s.SignPayload(p)
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// randomID returns a hex-encoded cryptographically random id of n bytes.
func randomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("issuer: random id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// randomSerial returns a grouped uppercase serial like ABCD-EF12-3456-7890.
func randomSerial() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("issuer: random serial: %w", err)
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no ambiguous chars
	out := make([]byte, 0, 19)
	for i, v := range b {
		if i > 0 && i%2 == 0 {
			out = append(out, '-')
		}
		out = append(out, alphabet[int(v)%len(alphabet)])
		out = append(out, alphabet[int(v>>3)%len(alphabet)])
	}
	return string(out), nil
}
