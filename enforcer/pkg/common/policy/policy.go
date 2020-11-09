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

package policy

import (
	"fmt"
	"strings"

	"github.com/IBM/integrity-enforcer/enforcer/pkg/common/common"
	"github.com/jinzhu/copier"
)

type ScopeType string

const (
	ScopeUndefined  ScopeType = ""
	ScopeNamespaced ScopeType = "Namespaced"
	ScopeCluster    ScopeType = "Cluster"
)

type IntegrityEnforcerMode string

const (
	UnknownMode IntegrityEnforcerMode = ""
	EnforceMode IntegrityEnforcerMode = "enforce"
	DetectMode  IntegrityEnforcerMode = "detect"
)

/**********************************************

					SignPolicy

***********************************************/

type SignPolicy struct {
	Policies    []SignPolicyCondition `json:"policies,omitempty"`
	Signers     []SignerCondition     `json:"signers,omitempty"`
	BreakGlass  []BreakGlassCondition `json:"breakGlass,omitempty"`
	Description string                `json:"description,omitempty"`
}

func (p *SignPolicy) DeepCopyInto(p2 *SignPolicy) {
	copier.Copy(&p2, &p)
}

func (p *SignPolicy) DeepCopy() *SignPolicy {
	p2 := &SignPolicy{}
	p.DeepCopyInto(p2)
	return p2
}

func (self *SignPolicy) GetSignerMap() map[string][]SubjectCondition {
	signerMap := map[string][]SubjectCondition{}
	for _, si := range self.Signers {
		tmpSC := []SubjectCondition{}
		for _, sj := range si.Subjects {
			sc := SubjectCondition{
				Name:    si.Name,
				Subject: sj,
			}
			tmpSC = append(tmpSC, sc)
		}
		signerMap[si.Name] = tmpSC
	}
	return signerMap
}

func (self *SignPolicy) Merge(data *SignPolicy) *SignPolicy {
	merged := &SignPolicy{}
	merged.Policies = append(self.Policies, data.Policies...)
	merged.Signers = append(self.Signers, data.Signers...)
	merged.BreakGlass = append(self.BreakGlass, data.BreakGlass...)
	merged.Description = self.Description
	return merged
}

func (self *SignPolicy) GetCandidatePubkeys(keyPathList []string, namespace string) []string {
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
				included = common.MatchWithPatternArray(namespace, spc.Namespaces)
				excluded = common.MatchWithPatternArray(namespace, spc.ExcludeNamespaces)
			}
		}
		if !included || excluded {
			continue
		}
		for _, signerName := range spc.Signers {
			for _, signerCondition := range self.Signers {
				if signerCondition.Name == signerName {
					candidates = append(candidates, signerCondition.Secret)
				}
			}
		}
	}
	candidateKeys := []string{}
	for _, keyPath := range keyPathList {
		for _, secretName := range candidates {
			if strings.HasPrefix(keyPath, fmt.Sprintf("/%s/", secretName)) {
				candidateKeys = append(candidateKeys, keyPath)
				break
			}
		}
	}
	return candidateKeys
}

func (self *SignPolicy) Match(namespace string, signer *common.SignerInfo) (bool, *SignPolicyCondition) {
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
				included = common.MatchWithPatternArray(namespace, spc.Namespaces)
				excluded = common.MatchWithPatternArray(namespace, spc.ExcludeNamespaces)
			}
		}
		signerMatched := false
		for _, signerName := range spc.Signers {
			subjectConditions, ok := signerMap[signerName]
			if !ok {
				continue
			}
			for _, subjectCondition := range subjectConditions {
				if subjectCondition.Match(signer) {
					signerMatched = true
					break
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

type SignPolicyCondition struct {
	Scope             ScopeType `json:"scope,omitempty"`
	Namespaces        []string  `json:"namespaces,omitempty"`
	ExcludeNamespaces []string  `json:"excludeNamespaces,omitempty"`
	Signers           []string  `json:"signers,omitempty"`
}

type SignerCondition struct {
	Name     string                `json:"name,omitempty"`
	Secret   string                `json:"secret,omitempty"`
	Subjects []SubjectMatchPattern `json:"subjects,omitempty"`
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
	Name    string              `json:"name"`
	Subject SubjectMatchPattern `json:"subject"`
}

func (self *SubjectCondition) Match(signer *common.SignerInfo) bool {
	return common.MatchPattern(self.Subject.Email, signer.Email) &&
		common.MatchPattern(self.Subject.Uid, signer.Uid) &&
		common.MatchPattern(self.Subject.Country, signer.Country) &&
		common.MatchPattern(self.Subject.Organization, signer.Organization) &&
		common.MatchPattern(self.Subject.OrganizationalUnit, signer.OrganizationalUnit) &&
		common.MatchPattern(self.Subject.Locality, signer.Locality) &&
		common.MatchPattern(self.Subject.Province, signer.Province) &&
		common.MatchPattern(self.Subject.StreetAddress, signer.StreetAddress) &&
		common.MatchPattern(self.Subject.PostalCode, signer.PostalCode) &&
		common.MatchPattern(self.Subject.CommonName, signer.CommonName) &&
		common.MatchBigInt(self.Subject.SerialNumber, signer.SerialNumber)
}
