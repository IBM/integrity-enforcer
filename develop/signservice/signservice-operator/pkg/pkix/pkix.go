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
	"fmt"
	"strconv"

	iepkix "github.com/IBM/integrity-enforcer/enforcer/pkg/sign/pkix"
)

type SignerCertName struct {
	Name       string `json:"name,omitempty"`
	IssuerName string `json:"issuerName,omitempty"`
	IsCA       bool   `json:"isCA,omitempty"`
}

type KeyBox struct {
	Certificate []byte `json:"certificate"`
	PrivateKey  []byte `json:"privateKey"`
	PublicKey   []byte `json:"publicKey"`
	IsCA        bool   `json:"isCA"`
}

type KeyBoxList struct {
	Items []*KeyBox `json:"items"`
}

func (self *KeyBoxList) ToSecretData() map[string][]byte {
	count := 0
	data := map[string][]byte{}
	for _, keyBox := range self.Items {
		countStr := strconv.Itoa(count)
		certKeyStr := fmt.Sprintf("certificate-%s", countStr)
		priKeyStr := fmt.Sprintf("privatekey-%s", countStr)
		pubKeyStr := fmt.Sprintf("publickey-%s", countStr)
		data[certKeyStr] = keyBox.Certificate
		data[priKeyStr] = keyBox.PrivateKey
		data[pubKeyStr] = keyBox.PublicKey
		count += 1
	}
	return data
}

func (self *KeyBoxList) ToCertPoolData() map[string][]byte {
	count := 0
	data := map[string][]byte{}
	for _, keyBox := range self.Items {
		if !keyBox.IsCA {
			continue
		}
		countStr := strconv.Itoa(count)
		certKeyStr := fmt.Sprintf("certificate-%s.crt", countStr)
		data[certKeyStr] = keyBox.Certificate
		count += 1
	}
	return data
}

func findByName(keyBoxItems []*KeyBox, name string) (*KeyBox, bool) {
	ok := false
	var found *KeyBox
	for _, keyBox := range keyBoxItems {
		certBytes := keyBox.Certificate
		cert, err := iepkix.ParseCertificate(certBytes)
		if err != nil {
			continue
		}
		if cert.Subject.CommonName == name {
			found = keyBox
			ok = true
			break
		}
	}
	return found, ok
}

func CreateKeyBoxListFromSignerChain(chain []SignerCertName) (*KeyBoxList, error) {
	selfSignSignerCerts := []SignerCertName{}
	childSignerCerts := []SignerCertName{}
	for _, certName := range chain {
		if certName.IssuerName == "" || certName.IssuerName == certName.Name {
			selfSignSignerCerts = append(selfSignSignerCerts, certName)
		} else {
			childSignerCerts = append(childSignerCerts, certName)
		}
	}
	items := []*KeyBox{}
	for _, certName := range selfSignSignerCerts {
		cert, prvKey, pubKey, err := iepkix.CreateCertificate(certName.Name, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("Failed to create keyboxlist; ", err.Error())
		}
		keyBox := &KeyBox{
			Certificate: cert,
			PrivateKey:  prvKey,
			PublicKey:   pubKey,
			IsCA:        certName.IsCA,
		}
		items = append(items, keyBox)
	}
	for _, certName := range childSignerCerts {
		parentKeyBox, ok := findByName(items, certName.IssuerName)
		if !ok {
			return nil, fmt.Errorf("There is no cert issuer named", certName.IssuerName)
		}
		cert, prvKey, pubKey, err := iepkix.CreateCertificate(certName.Name, parentKeyBox.Certificate, parentKeyBox.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("Failed to create keyboxlist; ", err.Error())
		}
		keyBox := &KeyBox{
			Certificate: cert,
			PrivateKey:  prvKey,
			PublicKey:   pubKey,
			IsCA:        certName.IsCA,
		}
		items = append(items, keyBox)
	}
	return &KeyBoxList{
		Items: items,
	}, nil
}
