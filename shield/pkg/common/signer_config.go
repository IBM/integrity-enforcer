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

package common

import (
	"path/filepath"
	"strings"

	"github.com/jinzhu/copier"
)

type ScopeType string

const (
	ScopeUndefined  ScopeType = ""
	ScopeNamespaced ScopeType = "Namespaced"
	ScopeCluster    ScopeType = "Cluster"
)

type IntegrityShieldMode string

const (
	UnknownMode IntegrityShieldMode = ""
	EnforceMode IntegrityShieldMode = "enforce"
	DetectMode  IntegrityShieldMode = "detect"
)

const SigStoreDummyKeyName = "SIGSTORE_DUMMY_KEY"

/**********************************************

					SignerConfig

***********************************************/

type SignerConfig struct {
	Signers     []SignerCondition     `json:"signers,omitempty"`
	BreakGlass  []BreakGlassCondition `json:"breakGlass,omitempty"`
	Description string                `json:"description,omitempty"`
}

func (p *SignerConfig) DeepCopyInto(p2 *SignerConfig) {
	copier.Copy(&p2, &p)
}

func (p *SignerConfig) DeepCopy() *SignerConfig {
	p2 := &SignerConfig{}
	p.DeepCopyInto(p2)
	return p2
}

func (self *SignerConfig) GetCandidatePubkeys(ishieldNS string) map[SignatureType][]string {
	candidatePubkeys := map[SignatureType][]string{}
	for _, signerCondition := range self.Signers {
		signatureType := signerCondition.SignatureType
		if string(signatureType) == "" {
			signatureType = SignatureTypePGP
		}
		baseDir := "/tmp"
		keyPath := signerCondition.makeFilePath(ishieldNS)
		keyFullPath := filepath.Join(baseDir, keyPath)
		candidatePubkeys[signatureType] = append(candidatePubkeys[signatureType], keyFullPath)
	}
	return candidatePubkeys
}

func (self *SignerConfig) Match(signer *SignerInfo, verifiedKeyPathList []string, ishieldNS string) (bool, *SignerCondition) {
	for _, signerCondition := range self.Signers {
		keyPath := signerCondition.makeFilePath(ishieldNS)
		keyMatched := false
		for _, verifiedKeyPath := range verifiedKeyPathList {
			if strings.Contains(verifiedKeyPath, keyPath) {
				keyMatched = true
				break
			}
		}
		signerMatched := signerCondition.Match(signer)
		if keyMatched && signerMatched {
			return true, &signerCondition
		}
	}
	return false, nil
}

type SignerCondition struct {
	Name               string                `json:"name,omitempty"`
	SignatureType      SignatureType         `json:"signatureType,omitempty"`
	KeySecretName      string                `json:"keySecretName,omitempty"`
	KeySecretNamespace string                `json:"keySecretNamespace,omitempty"`
	Subjects           []SubjectMatchPattern `json:"subjects,omitempty"`
}

func (sc *SignerCondition) makeFilePath(ishieldNS string) string {
	signatureType := sc.SignatureType
	secretName := sc.KeySecretName
	if signatureType == SignatureTypeSigStore && secretName == "" {
		// TODO: should avoid to use key path list for the key less singing
		secretName = SigStoreDummyKeyName
	}
	secretNamespace := sc.KeySecretNamespace

	if secretNamespace == "" {
		secretNamespace = ishieldNS
	}
	if string(signatureType) == "" {
		signatureType = SignatureTypePGP
	}
	parts := []string{secretNamespace, secretName, string(signatureType)}
	keyPath := filepath.Join(parts...)
	return keyPath
}

func (sc *SignerCondition) Match(signer *SignerInfo) bool {
	matched := false
	for _, sub := range sc.Subjects {
		if sub.Match(signer) {
			matched = true
			break
		}
	}
	return matched
}

type BreakGlassCondition struct {
	Scope      ScopeType `json:"scope,omitempty"`
	Namespaces []string  `json:"namespaces,omitempty"`
}

type SubjectMatchPattern struct {
	Email              string `json:"email,omitempty"`
	Uid                string `json:"uid,omitempty"`
	Country            string `json:"country,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizationalUnit,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Province           string `json:"province,omitempty"`
	StreetAddress      string `json:"streetAddress,omitempty"`
	PostalCode         string `json:"postalCode,omitempty"`
	CommonName         string `json:"commonName,omitempty"`
	SerialNumber       string `json:"serialNumber,omitempty"`
}

func (self *SubjectMatchPattern) Match(signer *SignerInfo) bool {
	return MatchPattern(self.Email, signer.Email) &&
		MatchPattern(self.Uid, signer.Uid) &&
		MatchPattern(self.Country, signer.Country) &&
		MatchPattern(self.Organization, signer.Organization) &&
		MatchPattern(self.OrganizationalUnit, signer.OrganizationalUnit) &&
		MatchPattern(self.Locality, signer.Locality) &&
		MatchPattern(self.Province, signer.Province) &&
		MatchPattern(self.StreetAddress, signer.StreetAddress) &&
		MatchPattern(self.PostalCode, signer.PostalCode) &&
		MatchPattern(self.CommonName, signer.CommonName) &&
		MatchBigInt(self.SerialNumber, signer.SerialNumber)
}
