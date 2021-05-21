package cli

import (
	"context"
	"flag"
	"fmt"

	"github.com/peterbourgon/ff/v3/ffcli"

	yamlsignaudit "github.com/IBM/integrity-enforcer/cmd/pkg/yamlsign/audit"
)

// AuditCommand verifies a signature on a supplied container image
type AuditYamlCommand struct {
	KubectlPath string
	Output      string
}

// Audit builds and returns an ffcli command
func AuditYaml() *ffcli.Command {
	cmd := AuditYamlCommand{}
	flagset := flag.NewFlagSet("ishieldctl audit", flag.ExitOnError)

	flagset.StringVar(&cmd.KubectlPath, "kubectlpath", "kubectl", "filepath to specify a kubectl command. If this is empty, execute just `kubectl`.")
	flagset.StringVar(&cmd.Output, "output", "", "If this is \"wide\", shows the detail message for each resource")

	return &ffcli.Command{
		Name:       "audit",
		ShortUsage: "ishieldctl audit -key <key path>|<key url>|<kms uri> <signed yaml file>",
		ShortHelp:  "Audit a signature on the supplied yaml file",
		LongHelp: `Audit signature and annotations on the supplied yaml file by checking the claims
against the transparency log.

EXAMPLES
  # audit cosign claims and signing certificates on the yaml file
  ishieldctl audit -apiversion <API version, e.g. v1 > -kind <resource kind e.g. ConfigMap> -namespace <a cluster namespace> -name <name of the resource>
 `,
		FlagSet: flagset,
		Exec:    cmd.Exec,
	}

}

// Exec runs the verification command
func (c *AuditYamlCommand) Exec(ctx context.Context, args []string) error {

	mainArgs, kubectlArgs := splitArgs(args)
	result, err := yamlsignaudit.AuditYaml(ctx, c.KubectlPath, mainArgs, kubectlArgs)
	if err != nil {
		return err
	}
	fmt.Println(c.Output)
	resultTable := ""
	if result != nil {
		if c.Output == "wide" {
			resultTable = string(result.DetailTable())
		} else {
			resultTable = string(result.Table())
		}
	}

	fmt.Println(resultTable)

	return nil
}

func splitArgs(args []string) ([]string, []string) {
	mainArgs := []string{}
	kubectlArgs := []string{}
	mainArgsCondition := map[string]bool{
		"-kubectlpath": true,
		"-output":      true,
	}
	skipIndex := map[int]bool{}
	for i, s := range args {
		if skipIndex[i] {
			continue
		}
		if mainArgsCondition[s] {
			mainArgs = append(mainArgs, args[i])
			mainArgs = append(mainArgs, args[i+1])
			skipIndex[i+1] = true
		} else {
			kubectlArgs = append(kubectlArgs, args[i])
		}
	}
	return mainArgs, kubectlArgs
}
