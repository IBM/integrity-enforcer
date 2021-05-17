//
// Copyright 2020 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package cli

import (
	"context"
	_ "crypto/sha256" // for `crypto.SHA256`
	"encoding/json"
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

	"github.com/IBM/integrity-enforcer/cmd/pkg/yamlsign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"
	"github.com/sigstore/rekor/pkg/generated/models"

	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/sigstore/pkg/kms"
	"github.com/sigstore/sigstore/pkg/signature"
)

// VerifyCommand verifies a signature on a supplied container image
type SignYamlCommand struct {
	KeyRef      string
	Sk          bool
	PayloadPath string
	Pf          cosign.PassFunc
}

func SignYaml() *ffcli.Command {

	cmd := SignYamlCommand{}
	flagset := flag.NewFlagSet("ishieldctl sign", flag.ExitOnError)

	flagset.StringVar(&cmd.KeyRef, "key", "", "path to the public key file, URL, or KMS URI")
	flagset.BoolVar(&cmd.Sk, "sk", false, "whether to use a hardware security key")
	flagset.StringVar(&cmd.PayloadPath, "payload", "", "path to the yaml file")

	return &ffcli.Command{
		Name:       "sign",
		ShortUsage: "ishieldctl sign -key <key path>|<kms uri> [-payload <path>]",
		ShortHelp:  `Sign the supplied yaml file.`,
		LongHelp: `Sign the supplied yaml file.

EXAMPLES
  # sign a yaml file with Google sign-in 
  ishieldctl sign -payload <yaml file> 

  # sign a yaml file with a local key pair file
  ishieldctl sign -key key.pub -payload <yaml file> 

  # sign a yaml file with a key pair stored in Google Cloud KMS
  ishieldctl sign -key gcpkms://projects/<PROJECT>/locations/global/keyRings/<KEYRING>/cryptoKeys/<KEY> -payload <yaml file>`,
		FlagSet: flagset,
		Exec:    cmd.Exec,
	}

}

func (c *SignYamlCommand) Exec(ctx context.Context, args []string) error {

	// prepare yaml payload as json ([] byte]
	payloadPath := c.PayloadPath

	// fetch yaml after removing annotations such as signature, certificate, message, and bundle (if exist)
	mPayload, _ := yamlsign.FetchYamlContent(payloadPath)
	cleanPayloadYaml, err := yaml.Marshal(mPayload)
	var payloadJson []byte
	payloadJson, err = gyaml.YAMLToJSON(cleanPayloadYaml)
	if err != nil {
		return errors.Wrap(err, "Failed to convert payload to json")
	}

	// sign payload and upload to tlog
	sig, cert, entry, err := c.SignPayload(ctx, payloadJson)
	if err != nil {
		return errors.Wrap(err, "Failed to sign payload")
	}

	// prepare bundle as json ([]byte)
	bundleJson, err := prepareBundleJson(entry)
	if err != nil {
		return errors.Wrap(err, "Failed to prepare bundle json")
	}

	// create yaml file with annotations such as signature, certificate, message, and bundle
	err = yamlsign.WriteYamlContent(sig, cert, bundleJson, mPayload, payloadPath)
	if err != nil {
		return errors.Wrap(err, "Failed to create signed yaml file")
	}

	return nil
}

func (c *SignYamlCommand) SignPayload(ctx context.Context, payloadJson []byte) ([]byte, []byte, *models.LogEntryAnon, error) {

	var signer signature.Signer

	var cert string

	switch {
	case c.Sk:
		sk, err := pivkey.NewSignerVerifier()
		if err != nil {
			return nil, nil, nil, err
		}
		signer = sk

	case c.KeyRef != "":
		k, err := loadSignerFromKeyRef(ctx, c.KeyRef, c.Pf)
		if err != nil {
			return nil, nil, nil, errors.Wrap(err, "reading key")
		}
		signer = k
	default: // Keyless!
		fmt.Fprintln(os.Stderr, "Generating ephemeral keys...")
		k, err := fulcio.NewSigner(ctx)
		if err != nil {
			return nil, nil, nil, errors.Wrap(err, "Getting key from Fulcio")
		}
		signer = k
		cert, _ = k.Cert, k.Chain

	}

	sig, _, err := signer.Sign(ctx, payloadJson)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "Error in signing")
	}

	// Upload the cert or the public key, depending on what we have
	var rekorBytes []byte
	if cert != "" {
		rekorBytes = []byte(cert)
	} else {
		pemBytes, err := cosign.PublicKeyPem(ctx, signer)
		if err != nil {
			return nil, nil, nil, errors.Wrap(err, "Error in loading certificate")
		}
		rekorBytes = pemBytes
	}

	entry, err := cosign.UploadTLog(sig, payloadJson, rekorBytes)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "failed to upload to tlog")
	}

	fmt.Println("tlog entry created with index: ", *entry.LogIndex)

	return sig, rekorBytes, entry, nil
}

func prepareBundleJson(entry *models.LogEntryAnon) ([]byte, error) {
	if entry.Verification == nil {
		return nil, nil
	}
	bundle := &cosign.Bundle{
		SignedEntryTimestamp: entry.Verification.SignedEntryTimestamp,
		Body:                 entry.Body,
		IntegratedTime:       entry.IntegratedTime,
		LogIndex:             entry.LogIndex,
	}

	bundleJson, err := json.Marshal(bundle)

	if err != nil {
		return nil, err
	}

	return bundleJson, nil

}

func loadSignerFromKeyRef(ctx context.Context, keyRef string, pf cosign.PassFunc) (signature.Signer, error) {

	for prefix := range kms.ProvidersMux().Providers() {
		if strings.HasPrefix(keyRef, prefix) {
			return kms.Get(ctx, keyRef)
		}
	}

	kb, err := ioutil.ReadFile(filepath.Clean(keyRef))
	if err != nil {
		return signature.ECDSASignerVerifier{}, err
	}
	pass, err := pf(false)
	if err != nil {
		return signature.ECDSASignerVerifier{}, err
	}
	return cosign.LoadECDSAPrivateKey(kb, pass)
}
