//go:build linux

package fingerprint

import "os"

// collectComponents gathers stable hardware identifiers on Linux. It is
// best-effort: missing files are skipped and never cause a failure or panic.
func collectComponents() []Component {
	var components []Component

	for _, path := range []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
	} {
		if data, err := os.ReadFile(path); err == nil {
			c := buildComponent(CategoryMachineID, string(data))
			if c.value != "" {
				components = append(components, c)
				break
			}
		}
	}

	if data, err := os.ReadFile("/sys/class/dmi/id/board_serial"); err == nil {
		c := buildComponent(CategoryBoardUUID, string(data))
		if c.value != "" {
			components = append(components, c)
		}
	}

	if data, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
		c := buildComponent(CategoryProductUUID, string(data))
		if c.value != "" {
			components = append(components, c)
		}
	}

	return components
}

// primaryCategoryPriority returns the Linux priority order for selecting the v2
// primary identifier: the systemd/D-Bus machine-id is the most stable and
// privacy-neutral, followed by the DMI product UUID and board serial.
func primaryCategoryPriority() []string {
	return []string{CategoryMachineID, CategoryProductUUID, CategoryBoardUUID}
}
