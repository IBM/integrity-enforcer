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

package yamlsign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	_ "embed" // To enable the `go:embed` directive.

	gyaml "github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/cmd/rekor-cli/app"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/signature"
	"gopkg.in/yaml.v2"
)

func getTlogEntry(rekorClient *client.Rekor, uuid string) (*models.LogEntryAnon, error) {
	params := entries.NewGetLogEntryByUUIDParams()
	params.SetEntryUUID(uuid)
	resp, err := rekorClient.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}
	for _, e := range resp.Payload {
		return &e, nil
	}
	return nil, errors.New("empty response")
}

// Verify does all the main cosign checks in a loop, returning validated payloads.
// If there were no payloads, we return an error.
func VerifyYaml(ctx context.Context, co *cosign.CheckOpts, payloadPath string) (*cosign.SignedPayload, error) {

	// Fetch signature attached to our yaml file that we know how to parse.
	sp, err := FetchSignedYamlPayload(ctx, payloadPath)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to fetch signed payload")
	}

	// fetch yaml after removing annotations such as signature, certificate, message, and bundle (if exist)
	mPayload, err := FetchYamlContent(payloadPath)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to fetch yaml payload")
	}

	cleanPayloadYaml, err := yaml.Marshal(mPayload)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to convert payload to yaml")
	}

	payloadJson, err := gyaml.YAMLToJSON(cleanPayloadYaml)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to convert payload to json")
	}

	verified, err := VerifyPayload(ctx, co, payloadJson, sp)

	if err != nil {
		return nil, err
	}

	return verified, nil
}

func VerifyPayload(ctx context.Context, co *cosign.CheckOpts, payloadJson []byte, sp *cosign.SignedPayload) (*cosign.SignedPayload, error) {

	validationErrs := []string{}

	err := verifyKeyAndSignature(ctx, co, payloadJson, sp, &validationErrs)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to verify key and signature")
	}

	err = verifyClaims(co, payloadJson, sp, &validationErrs)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to verify claims")
	}

	verified, err := verifyBundleAndTlog(ctx, co, sp, &validationErrs)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to verify payload")
	}

	return verified, nil
}

func verifyKeyAndSignature(ctx context.Context, co *cosign.CheckOpts, payloadJson []byte, sp *cosign.SignedPayload, validationErrs *[]string) error {

	// Enforce this up front.
	if co.Roots == nil && co.PubKey == nil {
		return errors.New("one of public key or cert roots is required")
	}

	switch {
	// We have a public key to check against.
	case co.PubKey != nil:
		if err := sp.VerifyKey(ctx, co.PubKey); err != nil {
			*validationErrs = append(*validationErrs, err.Error())

		}
	// If we don't have a public key to check against, we can try a root cert.
	case co.Roots != nil:
		// There might be signatures with a public key instead of a cert, though
		if sp.Cert == nil {
			*validationErrs = append(*validationErrs, "no certificate found on signature")

		}
		pub := &signature.ECDSAVerifier{Key: sp.Cert.PublicKey.(*ecdsa.PublicKey), HashAlg: crypto.SHA256}
		// Now verify the signature, then the cert.
		if err := sp.VerifyKey(ctx, pub); err != nil {
			*validationErrs = append(*validationErrs, err.Error())

		}
		if err := sp.TrustedCert(co.Roots); err != nil {
			*validationErrs = append(*validationErrs, err.Error())

		}

	}
	return nil
}

func verifyClaims(co *cosign.CheckOpts, payloadJson []byte, sp *cosign.SignedPayload, validationErrs *[]string) error {

	// Enforce this up front.
	if sp.Payload == nil || string(payloadJson) == "" {
		return errors.New("payload is required")
	}

	if co.Claims {
		// verify if the yaml content match with message in annotation
		if string(payloadJson) != string(sp.Payload) {
			*validationErrs = append(*validationErrs, "`annotation.message` in this payload does not match with yaml content")

		}
	}
	return nil
}

func verifyBundleAndTlog(ctx context.Context, co *cosign.CheckOpts, sp *cosign.SignedPayload, validationErrs *[]string) (*cosign.SignedPayload, error) {

	verified, err := sp.VerifyBundle()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to verify offline (%v), checking tlog instead...", err)
	}

	co.VerifyBundle = verified

	if co.Tlog && !verified {
		// Get the right public key to use (key or cert)
		var pemBytes []byte
		if co.PubKey != nil {
			pemBytes, err = cosign.PublicKeyPem(ctx, co.PubKey)
			if err != nil {
				*validationErrs = append(*validationErrs, err.Error())

			}
		} else {
			pemBytes = cosign.CertToPem(sp.Cert)
		}

		// TODO: Figure out if we'll need a client before creating one.
		rekorClient, err := app.GetRekorClient(cosign.TlogServer())
		if err != nil {
			return nil, errors.Wrap(err, "retriving rekor client")
		}

		// Find the uuid then the entry.
		uuid, _, err := sp.VerifyTlog(rekorClient, pemBytes)
		if err != nil {
			*validationErrs = append(*validationErrs, err.Error())

		}

		// if we have a cert, we should check expiry
		if sp.Cert != nil {
			e, err := getTlogEntry(rekorClient, uuid)
			if err != nil {
				*validationErrs = append(*validationErrs, err.Error())

			}
			// Expiry check is only enabled with Tlog support
			if err := checkExpiry(sp.Cert, time.Unix(e.IntegratedTime, 0)); err != nil {
				*validationErrs = append(*validationErrs, err.Error())

			}
		}
	}

	if len(*validationErrs) != 0 {
		return nil, fmt.Errorf("no matching signatures:\n%s", strings.Join(*validationErrs, "\n "))
	} else {
		return sp, nil
	}
}

func checkExpiry(cert *x509.Certificate, it time.Time) error {
	ft := func(t time.Time) string {
		return t.Format(time.RFC3339)
	}
	if cert.NotAfter.Before(it) {
		return fmt.Errorf("certificate expired before signatures were entered in log: %s is before %s",
			ft(cert.NotAfter), ft(it))
	}
	if cert.NotBefore.After(it) {
		return fmt.Errorf("certificate was issued after signatures were entered in log: %s is after %s",
			ft(cert.NotAfter), ft(it))
	}
	return nil
}
