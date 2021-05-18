package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"

	"github.com/peterbourgon/ff/v3/ffcli"

	yamlsignaudit "github.com/IBM/integrity-enforcer/cmd/pkg/yamlsign/audit"
)

// AuditCommand verifies a signature on a supplied container image
type AuditYamlCommand struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
}

// Audit builds and returns an ffcli command
func AuditYaml() *ffcli.Command {
	cmd := AuditYamlCommand{}
	flagset := flag.NewFlagSet("ishieldctl audit", flag.ExitOnError)

	flagset.StringVar(&cmd.APIVersion, "apiversion", "v1", "apiversion to specify a resource. Default v1.")
	flagset.StringVar(&cmd.Kind, "kind", "ConfigMap", "kind to specify a resource. Default ConfigMap.")
	flagset.StringVar(&cmd.Namespace, "namespace", "default", "namespace to specify a resource. Default default.")
	flagset.StringVar(&cmd.Name, "name", "no-name", "name to specify a resource. Default no-name.")

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

	dr, err := yamlsignaudit.AuditYaml(ctx, c.APIVersion, c.Kind, c.Namespace, c.Name)
	if err != nil {
		return err
	}
	result, _ := json.Marshal(dr)
	fmt.Println(string(result))

	return nil
}
