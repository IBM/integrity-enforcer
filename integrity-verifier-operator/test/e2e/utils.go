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

func ChangeKubeContextToDefaultUser(framework *Framework, namespace, expected string) error {
	var default_user = "test-ns-user"
	secret, err := GetSecretName(framework, namespace, expected)
	if err != nil {
		return err
	}
	cmdstr := "kubectl get secret " + secret + " -o json | jq -r .data.token | base64 -D"
	out, cmd_err := exec.Command("sh", "-c", cmdstr).Output()
	if cmd_err != nil {
		return cmd_err
	}
	cmdstr = "kubectl config set-credentials " + default_user + " --token=" + string(out)
	_, cmd_err = exec.Command("sh", "-c", cmdstr).Output()
	if cmd_err != nil {
		return cmd_err
	}
	cmdstr = "kubectl config set-context --current --user=" + default_user
	_, cmd_err = exec.Command("sh", "-c", cmdstr).Output()
	if cmd_err != nil {
		return cmd_err
	}
	return nil
}

func ChangeKubeContextToKubeAdmin() error {
	cmdstr := "kubectl config set-context --current --user=" + kubeconfig_user
	_, cmd_err := exec.Command("sh", "-c", cmdstr).Output()
	if cmd_err != nil {
		return cmd_err
	}
	return nil
}
