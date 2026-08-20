//go:build darwin

package fingerprint

import (
	"os/exec"
	"strings"
)

// collectComponents gathers stable hardware identifiers on macOS. It runs
// ioreg to read the IOPlatformUUID. It is best-effort: any exec or parse error
// results in the identifier simply being skipped, never a panic or failure.
func collectComponents() []Component {
	var components []Component

	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return components
	}

	if uuid := parseIOPlatformUUID(string(out)); uuid != "" {
		c := buildComponent(CategoryPlatformUUID, uuid)
		if c.value != "" {
			components = append(components, c)
		}
	}

	return components
}

// parseIOPlatformUUID extracts the IOPlatformUUID value from ioreg output. Lines
// look like: "IOPlatformUUID" = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX".
func parseIOPlatformUUID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "IOPlatformUUID") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		rest := line[idx+1:]
		start := strings.Index(rest, "\"")
		if start < 0 {
			continue
		}
		rest = rest[start+1:]
		end := strings.Index(rest, "\"")
		if end < 0 {
			continue
		}
		return rest[:end]
	}
	return ""
}
