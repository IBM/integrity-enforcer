package e2e

import (
	"fmt"
	"os/exec"

	. "github.com/onsi/ginkgo"
)

// Kubectl executes kubectl commands
func Kubectl(args ...string) error {
	cmd := exec.Command("kubectl", args...)
	err := cmd.Start()
	if err != nil {
		Fail(fmt.Sprintf("Error: %v", err))
	}
	err_w := cmd.Wait()
	return err_w
}
