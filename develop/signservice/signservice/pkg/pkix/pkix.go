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

package pkix

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"path"
	"strings"

	iepkix "github.com/IBM/integrity-enforcer/enforcer/pkg/sign/pkix"
)

const signserviceSecretPath = "/signservice-secret/"

func findKeyCertPair(name string) ([]byte, []byte, error) {
	files, err := ioutil.ReadDir(signserviceSecretPath)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get files from mounted secret dir; %s" + err.Error())
	}
	var certPemBytes []byte
	var prvKeyPemBytes []byte
	for _, f := range files {
		if !f.IsDir() {
			fname := f.Name()
			isCert := strings.HasPrefix(fname, "certificate-")
			if !isCert {
				continue
			}
			fpath := path.Join(signserviceSecretPath, fname)
			certPemBytes, err = ioutil.ReadFile(fpath)
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to read certificate file; %s", err.Error())
			}
			certBytes := iepkix.PEMDecode(certPemBytes, iepkix.PEMTypeCertificate)
			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to load certificate; %s", err.Error())
			}
			if cert.Subject.CommonName != name {
				continue
			}
			prvKeyFName := strings.Replace(fname, "certificate-", "privatekey-", 1)
			prvKeyFPath := path.Join(signserviceSecretPath, prvKeyFName)

			prvKeyPemBytes, err = ioutil.ReadFile(prvKeyFPath)
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to load privatekey; %s", err.Error())
			}
			break
		}
	}
	if prvKeyPemBytes == nil {
		return nil, nil, fmt.Errorf("There is no privatekey with corresponding CA name: %s", name)
	}
	if certPemBytes == nil {
		return nil, nil, fmt.Errorf("There is no certificate with corresponding CA name: %s", name)
	}
	return prvKeyPemBytes, certPemBytes, nil
}

func GenerateSignature(msg []byte, name string) ([]byte, []byte, error) {
	if msg == nil {
		return nil, nil, fmt.Errorf("Message to be signed must not be null")
	}
	prvKeyPemBytes, certPemBytes, err := findKeyCertPair(name)
	if err != nil {
		return nil, nil, err
	}
	sig, err := iepkix.GenerateSignature(msg, prvKeyPemBytes)
	if err != nil {
		return nil, nil, err
	}
	return sig, certPemBytes, nil
}
