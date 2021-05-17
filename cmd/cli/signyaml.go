package cli

import (
	"context"
	_ "crypto/sha256" // for `crypto.SHA256`
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	gyaml "github.com/ghodss/yaml"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	"github.com/IBM/integrity-enforcer/cmd/pkg/yamlsign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"
	"github.com/sigstore/rekor/pkg/generated/models"

	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/sigstore/pkg/signature"
)

// VerifyCommand verifies a signature on a supplied container image
type SignYamlCommand struct {
	Upload      bool
	KeyRef      string
	Sk          bool
	Annotations *map[string]interface{}
	PayloadPath string
	Pf          cosign.PassFunc
}

type annotationsMap struct {
	annotations map[string]interface{}
}

func (a *annotationsMap) Set(s string) error {
	if a.annotations == nil {
		a.annotations = map[string]interface{}{}
	}
	kvp := strings.SplitN(s, "=", 2)
	if len(kvp) != 2 {
		return fmt.Errorf("invalid flag: %s, expected key=value", s)
	}

	a.annotations[kvp[0]] = kvp[1]
	return nil
}

func (a *annotationsMap) String() string {
	s := []string{}
	for k, v := range a.annotations {
		s = append(s, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(s, ",")
}

func SignYaml() *ffcli.Command {

	cmd := SignYamlCommand{}
	flagset := flag.NewFlagSet("ishieldctl sign", flag.ExitOnError)
	annotations := annotationsMap{}

	flagset.StringVar(&cmd.KeyRef, "key", "", "path to the public key file, URL, or KMS URI")
	flagset.BoolVar(&cmd.Sk, "sk", false, "whether to use a hardware security key")
	flagset.BoolVar(&cmd.Upload, "upload", true, "whether to upload the signature")
	flagset.StringVar(&cmd.PayloadPath, "payload", "", "path to the yaml file")

	flagset.Var(&annotations, "a", "extra key=value pairs to sign")
	return &ffcli.Command{
		Name:       "sign",
		ShortUsage: "ishieldctl sign -key <key path>|<kms uri> [-payload <path>] [-a key=value] [-upload=true|false] [-f] <image uri>",
		ShortHelp:  `Sign the supplied yaml file.`,
		LongHelp: `Sign the supplied yaml file.

EXAMPLES
  # sign a yaml file with Google sign-in 
  ishieldctl sign -payload <yaml file> 

  # sign a yaml file with a local key pair file
  ishieldctl sign -key key.pub -payload <yaml file> 

  # sign a yaml file and add annotations
  ishieldctl sign -key key.pub -a key1=value1 -a key2=value2 -payload <yaml file>

  # sign a yaml file with a key pair stored in Google Cloud KMS
  ishieldctl sign -key gcpkms://projects/<PROJECT>/locations/global/keyRings/<KEYRING>/cryptoKeys/<KEY> -payload <yaml file>`,
		FlagSet: flagset,
		Exec:    cmd.Exec,
	}

}

func (c *SignYamlCommand) Exec(ctx context.Context, args []string) error {

	payloadPath := c.PayloadPath

	mPayload, _ := yamlsign.FetchYamlContent(payloadPath)

	cleanPayloadYaml, err := yaml.Marshal(mPayload)

	// The payload can be specified via a flag to skip generation.
	var payloadJson []byte
	payloadJson, _ = gyaml.YAMLToJSON(cleanPayloadYaml)

	fmt.Println("payloadJson")
	fmt.Println(string(payloadJson))

	if err != nil {
		return errors.Wrap(err, "payloadJson")
	}

	var signer signature.Signer

	var cert string
	var pemBytes []byte
	switch {
	case c.Sk:
		sk, err := pivkey.NewSignerVerifier()
		if err != nil {
			return err
		}
		signer = sk
		pemBytes, err = cosign.PublicKeyPem(ctx, sk)
		if err != nil {
			return err
		}
	case c.KeyRef != "":
		k, err := signerVerifierFromKeyRef(ctx, c.KeyRef, c.Pf)
		if err != nil {
			return errors.Wrap(err, "reading key")
		}
		signer = k
	default: // Keyless!
		fmt.Fprintln(os.Stderr, "Generating ephemeral keys...")
		k, err := fulcio.NewSigner(ctx)
		if err != nil {
			return errors.Wrap(err, "getting key from Fulcio")
		}
		signer = k
		cert, _ = k.Cert, k.Chain
		pemBytes = []byte(cert)
	}

	sig, _, err := signer.Sign(ctx, payloadJson)
	if err != nil {
		return errors.Wrap(err, "signing")
	}

	if !c.Upload {
		fmt.Println(base64.StdEncoding.EncodeToString(sig))
		return nil
	}

	fmt.Println("----------------------")
	fmt.Println("Yaml Signing Completed !!!")
	fmt.Println("----------------------")

	// Upload the cert or the public key, depending on what we have
	var rekorBytes []byte
	if cert != "" {
		rekorBytes = []byte(cert)
	} else {
		pemBytes, err := cosign.PublicKeyPem(ctx, signer)
		if err != nil {
			return nil
		}
		rekorBytes = pemBytes
	}

	entry, err := cosign.UploadTLog(sig, payloadJson, rekorBytes)
	if err != nil {
		return err
	}
	fmt.Println("tlog entry created with index: ", *entry.LogIndex)

	bund, err := bundle(entry)
	if err != nil {
		return errors.Wrap(err, "bundle")
	}

	bundleJson, err := json.Marshal(bund)

	fmt.Println("bundleJson", string(bundleJson))

	yamlsign.WriteYamlContent(sig, pemBytes, bundleJson, mPayload, payloadPath)

	return nil
}

func bundle(entry *models.LogEntryAnon) (*cosign.Bundle, error) {
	if entry.Verification == nil {
		return nil, nil
	}
	return &cosign.Bundle{
		SignedEntryTimestamp: entry.Verification.SignedEntryTimestamp,
		Body:                 entry.Body,
		IntegratedTime:       entry.IntegratedTime,
		LogIndex:             entry.LogIndex,
	}, nil
}
