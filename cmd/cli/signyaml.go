package cli

import (
	"context"
	_ "crypto/sha256" // for `crypto.SHA256`
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	gyaml "github.com/ghodss/yaml"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"

	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/sigstore/pkg/signature"
)

const IntegrityShieldAnnotationMessage = "integrityshield.io/message"
const IntegrityShieldAnnotationSignature = "integrityshield.io/signature"
const IntegrityShieldAnnotationCertificate = "integrityshield.io/certificate"

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
	flagset := flag.NewFlagSet("yamlsign sign", flag.ExitOnError)
	annotations := annotationsMap{}

	flagset.StringVar(&cmd.KeyRef, "key", "", "path to the public key file, URL, or KMS URI")
	flagset.BoolVar(&cmd.Sk, "sk", false, "whether to use a hardware security key")
	flagset.BoolVar(&cmd.Upload, "upload", true, "whether to upload the signature")
	flagset.StringVar(&cmd.PayloadPath, "payload", "", "path to the yaml file")

	flagset.Var(&annotations, "a", "extra key=value pairs to sign")
	return &ffcli.Command{
		Name:       "sign",
		ShortUsage: "yamlsign sign -key <key path>|<kms uri> [-payload <path>] [-a key=value] [-upload=true|false] [-f] <image uri>",
		ShortHelp:  `Sign the supplied yaml file.`,
		LongHelp: `Sign the supplied yaml file.

EXAMPLES
  # sign a yaml file with Google sign-in 
  yamlsign sign -payload <yaml file> 

  # sign a yaml file with a local key pair file
  yamlsign sign -key key.pub -payload <yaml file> 

  # sign a yaml file and add annotations
  yamlsign sign -key key.pub -a key1=value1 -a key2=value2 -payload <yaml file>

  # sign a yaml file with a key pair stored in Google Cloud KMS
  yamlsign sign -key gcpkms://projects/<PROJECT>/locations/global/keyRings/<KEYRING>/cryptoKeys/<KEY> -payload <yaml file>`,
		FlagSet: flagset,
		Exec:    cmd.Exec,
	}

}

func (c *SignYamlCommand) Exec(ctx context.Context, args []string) error {

	keyRef := c.KeyRef
	payloadPath := c.PayloadPath

	// The payload can be specified via a flag to skip generation.
	var payload []byte
	var payloadYaml []byte

	payloadYaml, err := ioutil.ReadFile(filepath.Clean(payloadPath))

	mPayload := make(map[interface{}]interface{})
	err = yaml.Unmarshal([]byte(payloadYaml), &mPayload)
	if err != nil {
		fmt.Errorf("error: %v", err)
	}
	mPayloadMeta, ok := mPayload["metadata"]
	if !ok {
		return fmt.Errorf("there is no `metadata` in this payload")
	}
	mPayloadMetaMap, ok := mPayloadMeta.(map[interface{}]interface{})
	if !ok {
		return fmt.Errorf("`metadata` in this payload is not a yaml object")
	}
	mPayloadAnnotation, ok := mPayloadMetaMap["annotations"]
	if !ok {
		mPayloadAnnotation = make(map[interface{}]interface{})
	}

	mPayloadAnnotationMap, ok := mPayloadAnnotation.(map[interface{}]interface{})
	if !ok {
		return fmt.Errorf("`metadata.annotations` in this payload is not a yaml object")
	}

	msgAnnoKey := IntegrityShieldAnnotationMessage
	sigAnnoKey := IntegrityShieldAnnotationSignature
	certAnnoKey := IntegrityShieldAnnotationCertificate

	delete(mPayloadAnnotationMap, msgAnnoKey)
	delete(mPayloadAnnotationMap, sigAnnoKey)
	delete(mPayloadAnnotationMap, certAnnoKey)

	if len(mPayloadAnnotationMap) == 0 {
		delete(mPayload["metadata"].(map[interface{}]interface{}), "annotations")
	} else {
		mPayload["metadata"].(map[interface{}]interface{})["annotations"] = mPayloadAnnotationMap
	}

	cleanPayloadYaml, err := yaml.Marshal(mPayload)

	payload, _ = gyaml.YAMLToJSON(cleanPayloadYaml)
	fmt.Println("payload")
	fmt.Println(string(payload))
	if err != nil {
		return errors.Wrap(err, "payload")
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

	sig, _, err := signer.Sign(ctx, payload)
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

	m := make(map[interface{}]interface{})

	err = yaml.Unmarshal([]byte(cleanPayloadYaml), &m)
	if err != nil {
		fmt.Errorf("error: %v", err)
	}
	mMeta, ok := m["metadata"]
	if !ok {
		return fmt.Errorf("there is no `metadata` in this payload")
	}
	mMetaMap, ok := mMeta.(map[interface{}]interface{})
	if !ok {
		return fmt.Errorf("`metadata` in this payload is not a yaml object")
	}
	mAnnotation, ok := mMetaMap["annotations"]
	if !ok {
		mAnnotation = make(map[interface{}]interface{})
	}
	mAnnotationMap, ok := mAnnotation.(map[interface{}]interface{})
	if !ok {
		return fmt.Errorf("`metadata.annotations` in this payload is not a yaml object")
	}

	mAnnotationMap[sigAnnoKey] = base64.StdEncoding.EncodeToString(sig)
	mAnnotationMap[msgAnnoKey] = base64.StdEncoding.EncodeToString(cleanPayloadYaml)

	if keyRef == "" {
		mAnnotationMap[certAnnoKey] = base64.StdEncoding.EncodeToString(pemBytes)
	}
	m["metadata"].(map[interface{}]interface{})["annotations"] = mAnnotationMap

	mapBytes, err := yaml.Marshal(m)

	err = ioutil.WriteFile(filepath.Clean(payloadPath+".signed"), mapBytes, 0644)

	out := make(map[interface{}]interface{})

	signed, _ := ioutil.ReadFile(filepath.Clean(payloadPath + ".signed"))

	err = yaml.Unmarshal(signed, &out)
	if err != nil {
		panic(err)
	}

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

	entry, err := cosign.UploadTLog(sig, payload, rekorBytes)
	if err != nil {
		return err
	}
	fmt.Println("tlog entry created with index: ", *entry.LogIndex)
	/*
		bund, err := bundle(entry)
		if err != nil {
			return errors.Wrap(err, "bundle")
		}
			uo.Bundle = bund
			uo.AdditionalAnnotations = annotations(entry)
			if _, err = cosign.Upload(ctx, sig, payload, dstRef, uo); err != nil {
				return errors.Wrap(err, "uploading")
			}
	*/
	return nil
}

/*
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

func annotations(entry *models.LogEntryAnon) map[string]string {
	annts := map[string]string{}
	if bund, err := bundle(entry); err == nil && bund != nil {
		contents, _ := json.Marshal(bund)
		annts[cosign.BundleKey] = string(contents)
	}
	return annts
}
*/
