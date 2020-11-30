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

package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
)

func TestGenerateCert(t *testing.T) {
	caCertPEMBytes, _, tlsCertPEMBytes, err := GenerateCert("test-service", "test-ns")
	if err != nil {
		t.Error("Failed to generate certs: ", err)
		return
	}

	tlsCertPEMBlock, _ := pem.Decode(tlsCertPEMBytes)
	if tlsCertPEMBlock == nil {
		t.Error("Failed to decode TLS cert PEM bytes: ", err)
		return
	}
	tlsCertBytes := tlsCertPEMBlock.Bytes
	verifyOk, reasonFail, err := verifyCert(tlsCertBytes, caCertPEMBytes)
	if err != nil {
		t.Error("Error occurred in verifying cert: ", err)
		return
	} else if reasonFail != "" {
		t.Error("Failed to verify cert: ", reasonFail)
		return
	} else if verifyOk {
		t.Log("Verified successfully.")
	} else {
		t.Error("Unknown failure")
	}
}

func verifyCert(tlsCertBytes, caCertPEMBytes []byte) (bool, string, error) {
	var reasonFail string
	var err error
	cert, err := x509.ParseCertificate(tlsCertBytes)
	if err != nil {
		reasonFail = fmt.Sprintf("failed to parse tls certificate: %s", err.Error())
		return false, reasonFail, fmt.Errorf(reasonFail)
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(caCertPEMBytes)
	if !ok {
		reasonFail = "failed to append CA cert from PEMBytes"
		return false, reasonFail, fmt.Errorf(reasonFail)
	}
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	_, err = cert.Verify(opts)
	if err != nil {
		reasonFail = fmt.Sprintf("failed to verify certificate: %s", err.Error())
		return false, reasonFail, nil
	}

	return true, "", nil
}
