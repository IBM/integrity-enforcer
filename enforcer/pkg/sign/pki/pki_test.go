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

package pki

import (
	"io/ioutil"
	"net/http"
	"testing"
)

func TestEndToEndCAVerification(t *testing.T) {

	rootCaURL := "https://cacerts.digicert.com/DigiCertGlobalRootCA.crt"
	response, err := http.Get(rootCaURL)
	if err != nil {
		t.Error(err)
	}

	parentCertBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Error(err)
	}

	caCertificate, prvCaKeyBytes, _, err := CreateCACertificate("cluster_signer@signer.com", parentCertBytes)
	if err != nil {
		t.Error(err)
	}
	signerCertificate, prvSignerKeyBytes, pubSignerKeyBytes, err := CreateSignerCertificate("ns_signer@signer.com", caCertificate, prvCaKeyBytes)

	msg := []byte("abc")

	sig, err := GenerateSignature(msg, prvSignerKeyBytes)
	if err != nil {
		t.Error(err)
	}

	result, err := VerifySignature(msg, sig, pubSignerKeyBytes)
	if !result || err != nil {
		t.Error(err)
	}
	t.Log("successfully verified the signature")

	chains, err := VerifyCertificate(signerCertificate, caCertificate)
	if err != nil {
		t.Error(err)
	}
	t.Log("successfully verified the certificate")
	for i, certChain := range chains {
		for j, cert := range certChain {
			// certBytes, _ := json.Marshal(cert)
			// t.Log(i, j, string(certBytes))

			t.Log(i, j, "subject: ", cert.Subject.CommonName, ", issuer: ", cert.Issuer.CommonName)
		}
	}

}
