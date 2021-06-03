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

package shield

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
	logger "github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	"github.com/sigstore/sigstore/pkg/signature"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

type PublicKey interface {
	signature.Verifier
	signature.PublicKeyProvider
}

func (sci *SigCheckImages) imageSignatureCheck() {
	for i, img := range sci.ImagesToVerify {
		var res ImageVerifyResult
		co := &cosign.CheckOpts{
			Claims: true,
			Tlog:   img.Profile.CosignExperimental,
			Roots:  fulcio.Roots,
		}

		if img.Profile.Key != "" {
			if img.Profile.KeyNamespace == "" {
				break
			} else {
				co.PubKey, _ = loadPubKey(img.Profile.Key, img.Profile.KeyNamespace)
			}
		}

		ref, err := name.ParseReference(img.Image)
		if err != nil {
			res.Error = err
			img.Result = res
			sci.ImagesToVerify[i] = img
			continue
		}
		rekorSever := cli.TlogServer()
		verified, err := cosign.Verify(context.Background(), ref, co, rekorSever)
		if err != nil {
			//  cosign verify err
			res.Allowed = false
			res.Reason = "no valid signature for this image; " + err.Error()
			img.Result = res
			sci.ImagesToVerify[i] = img
			continue
		}
		if len(verified) == 0 {
			//  []cosign.SignedPayload is empty: no valid signature"
			res.Allowed = false
			res.Reason = "no valid signature for this image"
			img.Result = res
			sci.ImagesToVerify[i] = img
			continue
		}
		var commonNames []string
		var digest string
		for _, vp := range verified {
			ss := payload.SimpleContainerImage{}
			err := json.Unmarshal(vp.Payload, &ss)
			if err != nil {
				logger.Warn("error decoding the payload:", err.Error())
			}
			digest = ss.Critical.Image.DockerManifestDigest
			cn := vp.Cert.Subject.CommonName
			commonNames = append(commonNames, cn)
			logger.Trace("digest: ", digest)
			logger.Trace("commonName: ", cn)
		}
		res.Digest = digest
		res.CommonNames = commonNames
		res.Allowed = true
		img.Result = res
		sci.ImagesToVerify[i] = img
		logger.Trace("Image Check Results: ", img.Result)
	}
}

func loadPubKey(keyname, namespace string) (PublicKey, error) {
	config, _ := kubeutil.GetKubeConfig()
	c, _ := corev1client.NewForConfig(config)
	secret, err := c.Secrets(namespace).Get(context.Background(), keyname, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if secretBytes, ok := secret.Data["key"]; ok {
		keyData, err := decodeArmoredKey(secretBytes)
		if err != nil {
			return nil, err
		}
		return keyData, err
	}
	return nil, fmt.Errorf("Key: empty")
}

func decodeArmoredKey(keyBytes []byte) (PublicKey, error) { // (PublicKey, error) (*ecdsa.PublicKey, error)
	if len(keyBytes) == 0 {
		return nil, fmt.Errorf("Key: empty")
	}
	pems := parsePems(keyBytes)
	for _, p := range pems {
		// TODO check header
		key, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			// Error(err, "parsing key", "key", p)
		}
		// return key.(*ecdsa.PublicKey), nil
		return signature.ECDSAVerifier{Key: key.(*ecdsa.PublicKey), HashAlg: crypto.SHA256}, nil
	}
	return nil, fmt.Errorf("Key: empty")
}

func parsePems(b []byte) []*pem.Block {
	p, rest := pem.Decode(b)
	if p == nil {
		return nil
	}
	pems := []*pem.Block{p}

	if rest != nil {
		return append(pems, parsePems(rest)...)
	}
	return pems
}
