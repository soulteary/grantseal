package fingerprint

import (
	"fmt"
	"testing"
)

// These benchmarks are deliberately WHITE-BOX (package fingerprint) so they can
// construct Component values with fixed raw inputs via buildComponent and call
// canonicalForm directly. The public Compute/ComputeHMAC APIs depend on real
// hardware and return ErrInsufficientInfo on the fallback platform, so they are
// unsuitable for a portable, deterministic benchmark. All inputs are built
// before the timed loop; b.ReportAllocs is enabled and results are checked.

// benchComponents builds a fixed, representative set of injected hardware
// components (no real hardware access).
func benchComponents() []Component {
	return []Component{
		buildComponent(CategoryMachineID, "  Fixed-Machine-ID-0123456789ABCDEF  "),
		buildComponent(CategoryBoardUUID, "BOARD-UUID-AABBCCDDEEFF00112233"),
		buildComponent(CategoryPlatformUUID, "platform\tuuid   with   spaces"),
		buildComponent(CategoryProductUUID, "PRODUCT-UUID-99887766554433221100"),
	}
}

// BenchmarkFingerprintCanonicalization measures the normalize + deterministic
// serialization step (canonicalForm) on injected fixed components. This is the
// portion of a fingerprint computation that does not touch hardware.
func BenchmarkFingerprintCanonicalization(b *testing.B) {
	const ns = "acme-app"
	components := benchComponents()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		canonical, categories, ok := canonicalForm(ns, components)
		if !ok {
			b.Fatal("canonicalForm reported no usable component")
		}
		if canonical == "" || len(categories) == 0 {
			b.Fatal("empty canonical form")
		}
	}
}

// BenchmarkFingerprintCanonicalizationSizes measures canonicalization as the
// number of injected components grows, isolating the sort/serialize cost.
func BenchmarkFingerprintCanonicalizationSizes(b *testing.B) {
	const ns = "acme-app"
	sizes := []int{1, 4, 16}
	categories := []string{
		CategoryMachineID, CategoryBoardUUID, CategoryPlatformUUID,
		CategoryProductUUID, CategoryMachineGUID,
	}
	for _, n := range sizes {
		n := n
		b.Run(fmt.Sprintf("components=%d", n), func(b *testing.B) {
			components := make([]Component, 0, n)
			for i := 0; i < n; i++ {
				cat := categories[i%len(categories)]
				components = append(components, buildComponent(cat, fmt.Sprintf("raw-value-%08d", i)))
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				canonical, _, ok := canonicalForm(ns, components)
				if !ok || canonical == "" {
					b.Fatal("unexpected empty canonical form")
				}
			}
		})
	}
}
