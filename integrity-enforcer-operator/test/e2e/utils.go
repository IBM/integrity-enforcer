package e2e

import (
	"fmt"
	"os/exec"

	. "github.com/onsi/ginkgo"
)

// Kubectl executes kubectl commands
func Kubectl(args ...string) {
	cmd := exec.Command("kubectl", args...)
	err := cmd.Start()
	if err != nil {
		Fail(fmt.Sprintf("Error: %v", err))
	}
}
