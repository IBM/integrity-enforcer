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

func KubectlOut(args ...string) (error, string) {
	cmd := exec.Command("kubectl", args...)
	out, err := cmd.Output()
	if err != nil {
		return err, ""
	}
	return nil, string(out)
}
