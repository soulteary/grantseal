// Package license implements client-side offline software-license verification.
//
// Security model (see SECURITY.md):
//   - Ed25519 signatures only. PKCS#1v1.5/MD5/SHA-1/ECB/home-grown crypto are forbidden.
//   - Signatures cover the complete canonical (deterministic sorted-key JSON) payload.
//   - subtle.ConstantTimeCompare is used for sensitive comparisons.
//   - This package NEVER contains private keys; it only verifies.
//   - The verifier is fail-closed and never panics on malformed input.
package license

import "errors"

// Code is a stable, machine-readable license error code. These strings are part
// of the public contract and must remain stable across versions.
type Code string

const (
	CodeOK                    Code = "LICENSE_OK"
	CodeFileNotFound          Code = "LICENSE_FILE_NOT_FOUND"
	CodeFileTooLarge          Code = "LICENSE_FILE_TOO_LARGE"
	CodeMalformed             Code = "LICENSE_MALFORMED"
	CodeUnsupportedAlgorithm  Code = "LICENSE_UNSUPPORTED_ALGORITHM"
	CodeUnsupportedSchema     Code = "LICENSE_UNSUPPORTED_SCHEMA"
	CodeKeyUnknown            Code = "LICENSE_KEY_UNKNOWN"
	CodeKeyDisabled           Code = "LICENSE_KEY_DISABLED"
	CodeKeyRevoked            Code = "LICENSE_KEY_REVOKED"
	CodeSignatureInvalid      Code = "LICENSE_SIGNATURE_INVALID"
	CodeKeyIDMismatch         Code = "LICENSE_KEY_ID_MISMATCH"
	CodeInvalidEnum           Code = "LICENSE_INVALID_ENUM"
	CodeInvalidLimits         Code = "LICENSE_INVALID_LIMITS"
	CodeRevoked               Code = "LICENSE_REVOKED"
	CodeNotYetValid           Code = "LICENSE_NOT_YET_VALID"
	CodeExpired               Code = "LICENSE_EXPIRED"
	CodeClockRollback         Code = "LICENSE_CLOCK_ROLLBACK"
	CodeDeviceMismatch        Code = "LICENSE_DEVICE_MISMATCH"
	CodeProductMismatch       Code = "LICENSE_PRODUCT_MISMATCH"
	CodeVersionUnsupported    Code = "LICENSE_VERSION_UNSUPPORTED"
	CodeFeatureDenied         Code = "LICENSE_FEATURE_DENIED"
	CodeLimitExceeded         Code = "LICENSE_LIMIT_EXCEEDED"
	CodeStateIntegrityFailure Code = "LICENSE_STATE_INTEGRITY_FAILURE"

	// CodeFeatureUnavailable is a backward-compatible alias of the older
	// "LICENSE_FEATURE_UNAVAILABLE" spelling. New code should emit
	// CodeFeatureDenied; this constant is retained only so existing callers
	// that compared against the old string do not silently break.
	CodeFeatureUnavailable Code = "LICENSE_FEATURE_UNAVAILABLE"
)

// Error wraps a stable Code with a human-readable message and optional cause.
// It never carries sensitive data (private keys, full raw hardware values).
type Error struct {
	Code    Code
	Message string
	cause   error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil license error>"
	}
	if e.Message == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Message
}

func (e *Error) Unwrap() error { return e.cause }

// newError builds a *Error with the given code, message and optional cause.
func newError(code Code, message string, cause error) *Error {
	return &Error{Code: code, Message: message, cause: cause}
}

// Is enables errors.Is comparisons by Code, so callers can match sentinel
// errors below regardless of the wrapped message/cause.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// Sentinel errors for errors.Is matching. Each carries only its Code.
var (
	ErrFileNotFound          = &Error{Code: CodeFileNotFound}
	ErrFileTooLarge          = &Error{Code: CodeFileTooLarge}
	ErrMalformed             = &Error{Code: CodeMalformed}
	ErrUnsupportedAlgorithm  = &Error{Code: CodeUnsupportedAlgorithm}
	ErrUnsupportedSchema     = &Error{Code: CodeUnsupportedSchema}
	ErrKeyUnknown            = &Error{Code: CodeKeyUnknown}
	ErrKeyDisabled           = &Error{Code: CodeKeyDisabled}
	ErrKeyRevoked            = &Error{Code: CodeKeyRevoked}
	ErrSignatureInvalid      = &Error{Code: CodeSignatureInvalid}
	ErrKeyIDMismatch         = &Error{Code: CodeKeyIDMismatch}
	ErrInvalidEnum           = &Error{Code: CodeInvalidEnum}
	ErrInvalidLimits         = &Error{Code: CodeInvalidLimits}
	ErrRevoked               = &Error{Code: CodeRevoked}
	ErrNotYetValid           = &Error{Code: CodeNotYetValid}
	ErrExpired               = &Error{Code: CodeExpired}
	ErrClockRollback         = &Error{Code: CodeClockRollback}
	ErrDeviceMismatch        = &Error{Code: CodeDeviceMismatch}
	ErrProductMismatch       = &Error{Code: CodeProductMismatch}
	ErrVersionUnsupported    = &Error{Code: CodeVersionUnsupported}
	ErrFeatureDenied         = &Error{Code: CodeFeatureDenied}
	ErrLimitExceeded         = &Error{Code: CodeLimitExceeded}
	ErrStateIntegrityFailure = &Error{Code: CodeStateIntegrityFailure}

	// ErrFeatureUnavailable is retained as a backward-compatible alias for the
	// older feature-denied sentinel. Prefer ErrFeatureDenied in new code.
	ErrFeatureUnavailable = &Error{Code: CodeFeatureUnavailable}
)

// CodeOf extracts the stable Code from any error, returning "" if the error is
// not a license *Error.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
