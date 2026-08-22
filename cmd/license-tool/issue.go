package main

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/soulteary/grantseal/internal/issuer"
	"github.com/soulteary/grantseal/pkg/license"
)

// issueConfig is the JSON schema accepted by `issue -config`. Times are RFC3339
// strings (empty = unset). It maps to issuer.IssueRequest.
type issueConfig struct {
	KeyID             string               `json:"key_id"`
	LicenseID         string               `json:"license_id,omitempty"`
	SerialNumber      string               `json:"serial_number,omitempty"`
	ProductID         string               `json:"product_id"`
	CustomerID        string               `json:"customer_id"`
	CustomerName      string               `json:"customer_name,omitempty"`
	Edition           string               `json:"edition"`
	LicenseType       string               `json:"license_type"`
	NotBefore         string               `json:"not_before,omitempty"`
	ExpiresAt         string               `json:"expires_at,omitempty"`
	GracePeriodDays   int                  `json:"grace_period_days,omitempty"`
	Features          []string             `json:"features,omitempty"`
	Limits            map[string]int64     `json:"limits,omitempty"`
	DeviceBinding     deviceBindingConfig  `json:"device_binding,omitempty"`
	VersionConstraint versionConstraintCfg `json:"version_constraint,omitempty"`
	Metadata          map[string]string    `json:"metadata,omitempty"`
}

type deviceBindingConfig struct {
	Mode      string   `json:"mode,omitempty"`
	DeviceIDs []string `json:"device_ids,omitempty"`
}

type versionConstraintCfg struct {
	MinVersion        string `json:"min_version,omitempty"`
	MaxVersion        string `json:"max_version,omitempty"`
	MaintenanceUntil  string `json:"maintenance_until,omitempty"`
	CoveredMaxVersion string `json:"covered_max_version,omitempty"`
}

func cmdIssue(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to issue-config.json (required)")
	keyPath := fs.String("key", "", "path to the private key file (required)")
	out := fs.String("out", "", "output license file path (default stdout)")
	force := fs.Bool("force", false, "overwrite existing output file")
	coveredMaxVersion := fs.String("covered-max-version", "", "override version_constraint.covered_max_version (highest version still covered after maintenance lapses)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *configPath == "" || *keyPath == "" {
		return usageErrorf("issue: -config and -key are required")
	}

	cfgData, err := readFileBounded(*configPath, "config", license.MaxLicenseFileSize)
	if err != nil {
		return fmt.Errorf("issue: %w", err)
	}
	var cfg issueConfig
	if err := license.DecodeStrictJSON(cfgData, &cfg, license.MaxLicenseFileSize); err != nil {
		return &usageError{msg: "issue: parse config", err: err}
	}

	// A non-empty -covered-max-version flag overrides the config value.
	if *coveredMaxVersion != "" {
		cfg.VersionConstraint.CoveredMaxVersion = *coveredMaxVersion
	}

	req, err := cfg.toRequest()
	if err != nil {
		return err
	}

	priv, err := issuer.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	keyID := cfg.KeyID
	if keyID == "" {
		return usageErrorf("issue: config.key_id is required")
	}
	signer, err := issuer.NewSigner(keyID, priv)
	if err != nil {
		return err
	}
	env, err := issuer.Issue(signer, req)
	if err != nil {
		return err
	}
	data, err := env.MarshalJSONIndent()
	if err != nil {
		return err
	}
	if *out == "" {
		fprintln(stdout, string(data))
		return nil
	}
	if err := writeFileNoClobber(*out, data, 0o644, *force); err != nil {
		return err
	}
	fprintf(stderr, "issued license -> %s\n", *out)
	return nil
}

func (c issueConfig) toRequest() (issuer.IssueRequest, error) {
	nb, err := parseOptTime(c.NotBefore)
	if err != nil {
		return issuer.IssueRequest{}, &usageError{msg: "issue: not_before", err: err}
	}
	exp, err := parseOptTime(c.ExpiresAt)
	if err != nil {
		return issuer.IssueRequest{}, &usageError{msg: "issue: expires_at", err: err}
	}
	mu, err := parseOptTime(c.VersionConstraint.MaintenanceUntil)
	if err != nil {
		return issuer.IssueRequest{}, &usageError{msg: "issue: maintenance_until", err: err}
	}
	mode := license.DeviceMode(c.DeviceBinding.Mode)
	if mode == "" {
		mode = license.DeviceModeNone
	}
	return issuer.IssueRequest{
		LicenseID:       c.LicenseID,
		SerialNumber:    c.SerialNumber,
		ProductID:       c.ProductID,
		CustomerID:      c.CustomerID,
		CustomerName:    c.CustomerName,
		Edition:         license.Edition(c.Edition),
		LicenseType:     license.LicenseType(c.LicenseType),
		NotBefore:       nb,
		ExpiresAt:       exp,
		GracePeriodDays: c.GracePeriodDays,
		Features:        c.Features,
		Limits:          c.Limits,
		DeviceBinding: license.DeviceBinding{
			Mode:      mode,
			DeviceIDs: c.DeviceBinding.DeviceIDs,
		},
		VersionConstraint: license.VersionConstraint{
			MinVersion:        c.VersionConstraint.MinVersion,
			MaxVersion:        c.VersionConstraint.MaxVersion,
			MaintenanceUntil:  mu,
			CoveredMaxVersion: c.VersionConstraint.CoveredMaxVersion,
		},
		Metadata: c.Metadata,
	}, nil
}

func parseOptTime(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, err
	}
	u := t.UTC()
	return &u, nil
}
