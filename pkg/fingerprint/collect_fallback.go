//go:build !linux && !darwin && !windows

package fingerprint

// collectComponents returns no components on unsupported platforms. It never
// fabricates an identifier, so Compute will return ErrInsufficientInfo.
func collectComponents() []Component {
	return nil
}

// primaryCategoryPriority has no meaningful order on unsupported platforms
// (there are never any components to rank), so it returns an empty list.
func primaryCategoryPriority() []string {
	return nil
}
