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
	"fmt"
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

/**********************************************

					SignerConfig

***********************************************/

type SignerConfig struct {
	Policies    []SignerConfigCondition `json:"policies,omitempty"`
	Signers     []SignerCondition       `json:"signers,omitempty"`
	BreakGlass  []BreakGlassCondition   `json:"breakGlass,omitempty"`
	Description string                  `json:"description,omitempty"`
}

func (p *SignerConfig) DeepCopyInto(p2 *SignerConfig) {
	copier.Copy(&p2, &p)
}

func (p *SignerConfig) DeepCopy() *SignerConfig {
	p2 := &SignerConfig{}
	p.DeepCopyInto(p2)
	return p2
}

func (self *SignerConfig) GetSignerMap() map[string][]SubjectCondition {
	signerMap := map[string][]SubjectCondition{}
	for _, si := range self.Signers {
		tmpSC := []SubjectCondition{}
		for _, sj := range si.Subjects {
			sc := SubjectCondition{
				Name:      si.Name,
				KeyConfig: si.KeyConfig,
				Subject:   sj,
			}
			tmpSC = append(tmpSC, sc)
		}
		signerMap[si.Name] = tmpSC
	}
	return signerMap
}

func (self *SignerConfig) Merge(data *SignerConfig) *SignerConfig {
	merged := &SignerConfig{}
	merged.Policies = append(self.Policies, data.Policies...)
	merged.Signers = append(self.Signers, data.Signers...)
	merged.BreakGlass = append(self.BreakGlass, data.BreakGlass...)
	merged.Description = self.Description
	return merged
}

func (self *SignerConfig) GetCandidatePubkeys(keyPathList []string, namespace string) map[SignatureType][]string {
	candidates := []string{}
	for _, spc := range self.Policies {
		var included, excluded bool
		if namespace == "" {
			if spc.Scope == ScopeCluster {
				included = true
				excluded = false
			}
		} else {
			if spc.Scope != ScopeCluster {
				included = MatchWithPatternArray(namespace, spc.Namespaces)
				excluded = MatchWithPatternArray(namespace, spc.ExcludeNamespaces)
			}
		}
		if !included || excluded {
			continue
		}
		for _, signerName := range spc.Signers {
			for _, signerCondition := range self.Signers {
				if signerCondition.Name == signerName {
					candidates = append(candidates, signerCondition.KeyConfig)
				}
			}
		}
	}
	candidateKeys := map[SignatureType][]string{
		SignatureTypePGP:  {},
		SignatureTypeX509: {},
	}
	for _, keyPath := range keyPathList {
		for _, keyConfName := range candidates {
			pgpPattern := fmt.Sprintf("/%s/%s/", keyConfName, string(SignatureTypePGP))
			x509Pattern := fmt.Sprintf("/%s/%s/", keyConfName, string(SignatureTypeX509))
			if strings.Contains(keyPath, pgpPattern) {
				candidateKeys[SignatureTypePGP] = append(candidateKeys[SignatureTypePGP], keyPath)
				break
			} else if strings.Contains(keyPath, x509Pattern) {
				candidateKeys[SignatureTypeX509] = append(candidateKeys[SignatureTypeX509], keyPath)
				break
			}
		}
	}
	return candidateKeys
}

func (self *SignerConfig) Match(namespace string, signer *SignerInfo, verifiedKeyPathList []string) (bool, *SignerConfigCondition) {
	signerMap := self.GetSignerMap()
	for _, spc := range self.Policies {
		var included, excluded bool
		if namespace == "" {
			if spc.Scope == ScopeCluster {
				included = true
				excluded = false
			}
		} else {
			if spc.Scope != ScopeCluster {
				included = MatchWithPatternArray(namespace, spc.Namespaces)
				excluded = MatchWithPatternArray(namespace, spc.ExcludeNamespaces)
			}
		}
		signerMatched := false
		for _, signerName := range spc.Signers {
			subjectConditions, ok := signerMap[signerName]
			if !ok {
				continue
			}
			for _, subjectCondition := range subjectConditions {
				if subjectOk := subjectCondition.Match(signer); !subjectOk {
					continue
				}
				for _, keyPath := range verifiedKeyPathList {
					if strings.Contains(keyPath, fmt.Sprintf("/%s/", subjectCondition.KeyConfig)) {
						signerMatched = true
						break
					}
				}
			}
			if signerMatched {
				break
			}
		}
		matched := included && !excluded && signerMatched
		if matched {
			return true, &spc
		}
	}
	return false, nil
}

type SignerConfigCondition struct {
	Scope             ScopeType `json:"scope,omitempty"`
	Namespaces        []string  `json:"namespaces,omitempty"`
	ExcludeNamespaces []string  `json:"excludeNamespaces,omitempty"`
	Signers           []string  `json:"signers,omitempty"`
}

type SignerCondition struct {
	Name      string                `json:"name,omitempty"`
	KeyConfig string                `json:"keyConfig,omitempty"`
	Subjects  []SubjectMatchPattern `json:"subjects,omitempty"`
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

type SubjectCondition struct {
	Name      string              `json:"name"`
	KeyConfig string              `json:"keyConfig"`
	Subject   SubjectMatchPattern `json:"subject"`
}

func (self *SubjectCondition) Match(signer *SignerInfo) bool {
	return MatchPattern(self.Subject.Email, signer.Email) &&
		MatchPattern(self.Subject.Uid, signer.Uid) &&
		MatchPattern(self.Subject.Country, signer.Country) &&
		MatchPattern(self.Subject.Organization, signer.Organization) &&
		MatchPattern(self.Subject.OrganizationalUnit, signer.OrganizationalUnit) &&
		MatchPattern(self.Subject.Locality, signer.Locality) &&
		MatchPattern(self.Subject.Province, signer.Province) &&
		MatchPattern(self.Subject.StreetAddress, signer.StreetAddress) &&
		MatchPattern(self.Subject.PostalCode, signer.PostalCode) &&
		MatchPattern(self.Subject.CommonName, signer.CommonName) &&
		MatchBigInt(self.Subject.SerialNumber, signer.SerialNumber)
}
