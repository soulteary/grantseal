//go:build !linux && !darwin && !windows

package fingerprint

// collectComponents returns no components on unsupported platforms. It never
// fabricates an identifier, so Compute will return ErrInsufficientInfo.
func collectComponents() []Component {
	return nil
}
