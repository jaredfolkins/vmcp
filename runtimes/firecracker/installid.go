package firecracker

import (
	"fmt"
	"regexp"
)

// installIDRE is the form of an install identity. It names host files,
// the AppArmor profile, and the parent cgroup, so it is short and plain.
var installIDRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// ValidInstallID reports whether id can be an install identity: 1 to 32
// lowercase letters, digits, and inner hyphens.
func ValidInstallID(id string) error {
	if !installIDRE.MatchString(id) {
		return fmt.Errorf("install ID %q must be 1 to 32 lowercase letters, digits, and inner hyphens", id)
	}
	return nil
}

// CgroupParentName is the name of the parent cgroup of an install, under
// the cgroup root.
func CgroupParentName(installID string) string { return "vmcp-" + installID }
