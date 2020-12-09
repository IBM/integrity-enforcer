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

package loader

import (
	rspapi "github.com/IBM/integrity-enforcer/verifier/pkg/apis/resourcesigningprofile/v1alpha1"
	"github.com/IBM/integrity-enforcer/verifier/pkg/common/common"
	v1 "k8s.io/api/core/v1"
)

type RuleItem2 struct {
	Profile          rspapi.ResourceSigningProfile `json:"profile,omitempty"`
	TargetNamespaces []string                      `json:"targetNamespaces,omitempty"`
}

type RuleTable2 struct {
	Items             []RuleItem2 `json:"items,omitempty"`
	Namespaces        []string    `json:"namespaces,omitempty"`
	VerifierNamespace string      `json:"verifierNamespace,omitempty"`
}

func NewRuleTable2(profiles []rspapi.ResourceSigningProfile, namespaces []v1.Namespace, verifierNamespace string) *RuleTable2 {
	allTargetNamespaces := []string{}
	items := []RuleItem2{}
	for _, p := range profiles {
		pNamespace := p.GetNamespace()
		targetNamespaces := []string{}
		if pNamespace == verifierNamespace {
			nsSelector := p.Spec.TargetNamespaceSelector
			if nsSelector != nil {
				targetNamespaces = matchNamespaceListWithSelector(namespaces, nsSelector)
			} else {
				targetNamespaces = append(targetNamespaces, pNamespace)
			}
		} else {
			targetNamespaces = append(targetNamespaces, pNamespace)
		}
		items = append(items, RuleItem2{Profile: p, TargetNamespaces: targetNamespaces})
		allTargetNamespaces = common.GetUnionOfArrays(allTargetNamespaces, targetNamespaces)
	}
	return &RuleTable2{
		Items:             items,
		Namespaces:        allTargetNamespaces,
		VerifierNamespace: verifierNamespace,
	}
}

func (self *RuleTable2) IsEmpty() bool {
	return len(self.Items) == 0
}

func (self *RuleTable2) CheckIfTargetNamespace(nsName string) bool {
	if nsName == "" {
		return true
	}
	return common.ExactMatchWithPatternArray(nsName, self.Namespaces)
}

func (self *RuleTable2) CheckIfProtected(reqFields map[string]string) (bool, bool, []rspapi.ResourceSigningProfile) {
	matchedProfiles := []rspapi.ResourceSigningProfile{}
	reqNs := reqFields["Namespace"]
	reqScope := reqFields["ResourceScope"]
	protected := false
	ignoreMatched := false
	for _, item := range self.Items {
		if reqScope == "Namespaced" && !common.ExactMatchWithPatternArray(reqNs, item.TargetNamespaces) {
			continue
		}
		if tmpProtected, matchedRule := item.Profile.Match(reqFields); tmpProtected {
			protected = true
			matchedProfiles = append(matchedProfiles, item.Profile)
		} else if !tmpProtected && matchedRule != nil {
			ignoreMatched = true
		}
	}
	return protected, ignoreMatched, matchedProfiles
}

func matchNamespaceListWithSelector(namespaces []v1.Namespace, nsSelector *common.NamespaceSelector) []string {
	matched := []string{}
	for _, ns := range namespaces {
		if nsSelector.MatchNamespace(&ns) {
			matched = append(matched, (&ns).GetName())
		}
	}
	return matched
}
