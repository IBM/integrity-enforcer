package signyaml

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	_ "embed" // To enable the `go:embed` directive.

	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/cmd/rekor-cli/app"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

const IntegrityShieldAnnotationMessage = "integrityshield.io/message"
const IntegrityShieldAnnotationSignature = "integrityshield.io/signature"
const IntegrityShieldAnnotationCertificate = "integrityshield.io/certificate"

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
func VerifyYaml(ctx context.Context, co *cosign.CheckOpts, payloadPath string) ([]cosign.SignedPayload, error) {
	// Enforce this up front.
	if co.Roots == nil && co.PubKey == nil {
		return nil, errors.New("one of public key or cert roots is required")
	}
	// TODO: Figure out if we'll need a client before creating one.
	rekorClient, err := app.GetRekorClient(cosign.TlogServer())
	if err != nil {
		return nil, err
	}

	// These are all the signatures attached to our image that we know how to parse.
	allSignatures, err := FetchYamlSignatures(ctx, payloadPath)
	if err != nil {
		return nil, errors.Wrap(err, "fetching signatures")
	}

	validationErrs := []string{}
	checkedSignatures := []cosign.SignedPayload{}
	for _, sp := range allSignatures {
		switch {
		// We have a public key to check against.
		case co.PubKey != nil:
			if err := sp.VerifyKey(ctx, co.PubKey); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}
		// If we don't have a public key to check against, we can try a root cert.
		case co.Roots != nil:
			// There might be signatures with a public key instead of a cert, though
			if sp.Cert == nil {
				validationErrs = append(validationErrs, "no certificate found on signature")
				continue
			}
			pub := &signature.ECDSAVerifier{Key: sp.Cert.PublicKey.(*ecdsa.PublicKey), HashAlg: crypto.SHA256}
			// Now verify the signature, then the cert.
			if err := sp.VerifyKey(ctx, pub); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}
			if err := sp.TrustedCert(co.Roots); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}
		}

		// We can't check annotations without claims, both require unmarshalling the payload.
		if co.Claims {
			ss := &payload.SimpleContainerImage{}
			if err := json.Unmarshal(sp.Payload, ss); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}

			/*if err := sp.VerifyClaims(desc, ss); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}*/

			if co.Annotations != nil {
				if !correctAnnotations(co.Annotations, ss.Optional) {
					validationErrs = append(validationErrs, "missing or incorrect annotation")
					continue
				}
			}
		}

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
					validationErrs = append(validationErrs, err.Error())
					continue
				}
			} else {
				pemBytes = cosign.CertToPem(sp.Cert)
			}

			// Find the uuid then the entry.
			uuid, _, err := sp.VerifyTlog(rekorClient, pemBytes)
			if err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}

			// if we have a cert, we should check expiry
			if sp.Cert != nil {
				e, err := getTlogEntry(rekorClient, uuid)
				if err != nil {
					validationErrs = append(validationErrs, err.Error())
					continue
				}
				// Expiry check is only enabled with Tlog support
				if err := checkExpiry(sp.Cert, time.Unix(e.IntegratedTime, 0)); err != nil {
					validationErrs = append(validationErrs, err.Error())
					continue
				}
			}
		}

		// Phew, we made it.
		checkedSignatures = append(checkedSignatures, sp)
	}
	if len(checkedSignatures) == 0 {
		return nil, fmt.Errorf("no matching signatures:\n%s", strings.Join(validationErrs, "\n "))
	}
	return checkedSignatures, nil
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

func correctAnnotations(wanted, have map[string]interface{}) bool {
	for k, v := range wanted {
		if have[k] != v {
			return false
		}
	}
	return true
}
