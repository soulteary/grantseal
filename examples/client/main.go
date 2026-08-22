// Command client demonstrates how a client application loads and validates a
// grantseal license, then gates features based on the read-only result.
//
// The client embeds only PUBLIC keys and imports only pkg/license (+ optionally
// pkg/fingerprint). It can never import internal/issuer, so no signing logic or
// private key can leak into the shipped binary.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/soulteary/grantseal/pkg/fingerprint"
	"github.com/soulteary/grantseal/pkg/license"
)

func main() {
	licPath := flag.String("license", "customer.lic", "path to the license file")
	pubKeyB64 := flag.String("pubkey", "", "Base64URL public key (or set PUBKEY env)")
	keyID := flag.String("key-id", "k1", "key_id matching the public key")
	product := flag.String("product", "acme-app", "this product's id")
	version := flag.String("version", "1.4.0", "this build's version")
	namespace := flag.String("namespace", "acme-app", "device fingerprint namespace")
	bindDevice := flag.Bool("device", false, "compute and pass a device fingerprint")
	flag.Parse()

	pub := *pubKeyB64
	if pub == "" {
		pub = os.Getenv("PUBKEY")
	}
	if pub == "" {
		fmt.Fprintln(os.Stderr, "provide -pubkey or PUBKEY env (Base64URL public key)")
		os.Exit(2)
	}

	// 1. Build a key ring with the embedded public key(s).
	ring := license.NewKeyRing()
	if err := ring.AddPublicKeyBase64(*keyID, pub); err != nil {
		fmt.Fprintln(os.Stderr, "bad public key:", err)
		os.Exit(2)
	}

	// 2. Optionally compute this device's fingerprint for device-bound licenses.
	device := ""
	if *bindDevice {
		fp, err := fingerprint.ComputeDefault(*namespace)
		if err != nil {
			if errors.Is(err, fingerprint.ErrInsufficientInfo) {
				fmt.Fprintln(os.Stderr, "cannot compute device fingerprint on this platform")
			} else {
				fmt.Fprintln(os.Stderr, "fingerprint error:", err)
			}
		} else {
			device = fp.Fingerprint
		}
	}

	// 3. Create the manager and validate the license file (fail-closed).
	mgr := license.NewManager(ring)
	res, err := mgr.LoadAndValidate(*licPath, license.ValidationContext{
		ProductID:         *product,
		ProductVersion:    *version,
		DeviceFingerprint: device,
	})
	if err != nil {
		// The stable code drives UX; never trust an invalid result.
		fmt.Printf("license invalid: %s\n", license.CodeOf(err))
		os.Exit(1)
	}

	// 4. Use the READ-ONLY result to gate functionality.
	fmt.Printf("license OK: status=%s edition=%s key_id=%s\n", res.Status(), res.GetEdition(), res.KeyID())
	if days := res.GetRemainingDays(); days == license.PerpetualRemainingDays {
		fmt.Println("  perpetual license (never expires)")
	} else {
		fmt.Printf("  %d day(s) remaining\n", days)
	}
	if res.Status() == license.StatusGrace {
		if gu := res.GraceUntil(); gu != nil {
			fmt.Printf("  (in grace period until %s - please renew)\n", gu.Format("2006-01-02"))
		}
	}

	// Prefer RequireFeature for gating: it returns a stable error code.
	if err := res.RequireFeature("api"); err != nil {
		fmt.Printf("  feature 'api' NOT available (%s)\n", license.CodeOf(err))
	} else {
		fmt.Println("  feature 'api' enabled")
	}

	// CheckLimit enforces a numeric quota; a missing key means unlimited.
	const seatsInUse = 5
	if err := res.CheckLimit("max_seats", seatsInUse); err != nil {
		fmt.Printf("  seat limit exceeded (%s)\n", license.CodeOf(err))
	} else if max, ok := res.GetLimit("max_seats"); ok {
		fmt.Printf("  seats: %d/%d\n", seatsInUse, max)
	} else {
		fmt.Println("  seats: unlimited")
	}
}
