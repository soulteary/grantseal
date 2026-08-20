package license

import "time"

// TrustedTimeProvider abstracts the source of "now". The default implementation
// uses the system clock; an online/NTP-backed source can be injected later
// without touching validation logic.
type TrustedTimeProvider interface {
	// Now returns the current trusted time. Implementations should return UTC.
	Now() (time.Time, error)
}

// SystemClock is the default TrustedTimeProvider using the OS clock.
type SystemClock struct{}

// Now returns the system time in UTC.
func (SystemClock) Now() (time.Time, error) { return time.Now().UTC(), nil }

// FixedClock is a deterministic clock, useful for tests and reproducible checks.
type FixedClock struct{ T time.Time }

// Now returns the fixed instant in UTC.
func (c FixedClock) Now() (time.Time, error) { return c.T.UTC(), nil }

// DefaultClockSkew is the tolerated clock skew for time comparisons (±5min).
const DefaultClockSkew = 5 * time.Minute
