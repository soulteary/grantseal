//go:build windows

package fingerprint

import (
	"os/exec"
	"strings"
)

// collectComponents gathers a stable hardware identifier on Windows by querying
// the MachineGuid registry value. It is best-effort: any exec or parse error
// results in the identifier being skipped, never a panic or failure.
func collectComponents() []Component {
	var components []Component

	out, err := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output()
	if err != nil {
		return components
	}

	if guid := parseMachineGUID(string(out)); guid != "" {
		c := buildComponent(CategoryMachineGUID, guid)
		if c.value != "" {
			components = append(components, c)
		}
	}

	return components
}

// parseMachineGUID extracts the MachineGuid value from `reg query` output. Lines
// look like: "    MachineGuid    REG_SZ    xxxxxxxx-xxxx-...".
func parseMachineGUID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "MachineGuid") {
			continue
		}
		idx := strings.Index(line, "REG_SZ")
		if idx < 0 {
			continue
		}
		return strings.TrimSpace(line[idx+len("REG_SZ"):])
	}
	return ""
}
