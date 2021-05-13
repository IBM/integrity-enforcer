package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"

	yamlsignaudit "github.com/IBM/integrity-enforcer/cmd/pkg/yamlsign/audit"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

// AuditCommand verifies a signature on a supplied container image
type AuditYamlCommand struct {
	CheckClaims bool
	KeyRef      string
	Sk          bool
	Output      string
	Annotations *map[string]interface{}
	PayloadPath string
	Yaml        bool
	APIVersion  string
	Kind        string
	Namespace   string
	Name        string
}

// Audit builds and returns an ffcli command
func AuditYaml() *ffcli.Command {
	cmd := AuditYamlCommand{}
	flagset := flag.NewFlagSet("ishieldctl audit", flag.ExitOnError)
	annotations := annotationsMap{}

	flagset.StringVar(&cmd.KeyRef, "key", "", "path to the public key file, URL, or KMS URI")
	flagset.BoolVar(&cmd.Sk, "sk", false, "whether to use a hardware security key")
	flagset.BoolVar(&cmd.CheckClaims, "check-claims", true, "whether to check the claims found")
	flagset.StringVar(&cmd.Output, "output", "json", "output the signing image information. Default JSON.")
	flagset.StringVar(&cmd.APIVersion, "apiversion", "v1", "apiversion to specify a resource. Default v1.")
	flagset.StringVar(&cmd.Kind, "kind", "ConfigMap", "kind to specify a resource. Default ConfigMap.")
	flagset.StringVar(&cmd.Namespace, "namespace", "default", "namespace to specify a resource. Default default.")
	flagset.StringVar(&cmd.Name, "name", "no-name", "name to specify a resource. Default no-name.")
	flagset.StringVar(&cmd.PayloadPath, "payload", "", "path to the yaml file")
	flagset.BoolVar(&cmd.Yaml, "yaml", true, "if it is yaml file")

	// parse annotations
	flagset.Var(&annotations, "a", "extra key=value pairs to sign")
	cmd.Annotations = &annotations.annotations

	return &ffcli.Command{
		Name:       "audit",
		ShortUsage: "ishieldctl audit -key <key path>|<key url>|<kms uri> <signed yaml file>",
		ShortHelp:  "Audit a signature on the supplied yaml file",
		LongHelp: `Audit signature and annotations on the supplied yaml file by checking the claims
against the transparency log.

EXAMPLES
  # audit cosign claims and signing certificates on the yaml file
  ishieldctl audit -payload <signed yaml file>

  # additionally verify specified annotations
  ishieldctl audit -a key1=val1 -a key2=val2 -payload <signed yaml file> 

  # (experimental) additionally, verify with the transparency log
  ishieldctl audit -payload <signed yaml file>

  # verify image with public key
  ishieldctl audit -key <FILE> -payload <signed yaml file>

  # verify image with public key provided by URL
  ishieldctl audit -key https://host.for/<FILE> -payload <signed yaml file>

  # verify image with public key stored in Google Cloud KMS
  ishieldctl audit -key gcpkms://projects/<PROJECT>/locations/global/keyRings/<KEYRING>/cryptoKeys/<KEY> -payload <signed yaml file>`,
		FlagSet: flagset,
		Exec:    cmd.Exec,
	}

}

// Exec runs the verification command
func (c *AuditYamlCommand) Exec(ctx context.Context, args []string) error {

	co := &cosign.CheckOpts{
		Annotations: *c.Annotations,
		Claims:      c.CheckClaims,
		Tlog:        true,
		Roots:       fulcio.Roots,
	}
	keyRef := c.KeyRef

	// Keys are optional!
	if keyRef != "" {
		pubKey, err := publicKeyFromKeyRef(ctx, keyRef)
		if err != nil {
			return errors.Wrap(err, "loading public key")
		}
		co.PubKey = pubKey
	} else if c.Sk {
		pubKey, err := pivkey.NewPublicKeyProvider()
		if err != nil {
			return errors.Wrap(err, "loading public key")
		}
		co.PubKey = pubKey
	}

	dr, err := yamlsignaudit.AuditYaml(ctx, c.APIVersion, c.Kind, c.Namespace, c.Name)
	if err != nil {
		return err
	}
	result, _ := json.Marshal(dr)
	fmt.Println(string(result))

	return nil
}

// printVerification logs details about the verification to stdout
func (c *AuditYamlCommand) printVerification(verified []cosign.SignedPayload, co *cosign.CheckOpts) {
	fmt.Fprintf(os.Stderr, "\nVerification for %s --\n", c.PayloadPath)
	fmt.Fprintln(os.Stderr, "The following checks were performed on each of these signatures:")
	if co.Claims {
		if co.Annotations != nil {
			fmt.Fprintln(os.Stderr, "  - The specified annotations were verified.")
		}
		fmt.Fprintln(os.Stderr, "  - The cosign claims were validated")
	}
	if co.VerifyBundle {
		fmt.Fprintln(os.Stderr, "  - Existence of the claims in the transparency log was verified offline")
	} else if co.Tlog {
		fmt.Fprintln(os.Stderr, "  - The claims were present in the transparency log")
		fmt.Fprintln(os.Stderr, "  - The signatures were integrated into the transparency log when the certificate was valid")
	}
	if co.PubKey != nil {
		fmt.Fprintln(os.Stderr, "  - The signatures were verified against the specified public key")
	}
	fmt.Fprintln(os.Stderr, "  - Any certificates were verified against the Fulcio roots.")

	switch c.Output {
	case "text":
		for _, vp := range verified {
			if vp.Cert != nil {
				fmt.Println("Certificate common name: ", vp.Cert.Subject.CommonName)
			}

			fmt.Println(string(vp.Payload))
		}
	default:
		var outputKeys []payload.SimpleContainerImage
		for _, vp := range verified {
			ss := payload.SimpleContainerImage{}
			err := json.Unmarshal(vp.Payload, &ss)
			if err != nil {
				fmt.Println("error decoding the payload:", err.Error())
				return
			}

			if vp.Cert != nil {
				if ss.Optional == nil {
					ss.Optional = make(map[string]interface{})
				}
				ss.Optional["CommonName"] = vp.Cert.Subject.CommonName
			}
			if vp.Bundle != nil {
				if ss.Optional == nil {
					ss.Optional = make(map[string]interface{})
				}
				ss.Optional["Bundle"] = vp.Bundle
			}

			outputKeys = append(outputKeys, ss)
		}

		b, err := json.Marshal(outputKeys)
		if err != nil {
			fmt.Println("error when generating the output:", err.Error())
			return
		}

		fmt.Printf("\n%s\n", string(b))
	}
}
