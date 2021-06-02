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

package main

import (
	rspapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	"github.com/IBM/integrity-enforcer/shield/pkg/common"
	v1 "k8s.io/api/core/v1"
)

type RuleItem struct {
	Profile          rspapi.ResourceSigningProfile `json:"profile,omitempty"`
	TargetNamespaces []string                      `json:"targetNamespaces,omitempty"`
}

type RuleTable struct {
	Items           []RuleItem `json:"items,omitempty"`
	Namespaces      []string   `json:"namespaces,omitempty"`
	ShieldNamespace string     `json:"shieldNamespace,omitempty"`
}

func NewRuleTable(profiles []rspapi.ResourceSigningProfile, namespaces []v1.Namespace, commonProfile *common.CommonProfile, shieldNamespace string) *RuleTable {
	allTargetNamespaces := []string{}
	items := []RuleItem{}
	commonProfileRSP := rspapi.ResourceSigningProfile{
		Spec: rspapi.ResourceSigningProfileSpec{},
	}
	if commonProfile != nil {
		commonProfileRSP.Spec.Parameters.IgnoreRules = commonProfile.IgnoreRules
		commonProfileRSP.Spec.Parameters.IgnoreAttrs = commonProfile.IgnoreAttrs
	}
	for _, p := range profiles {
		pNamespace := p.GetNamespace()
		targetNamespaces := []string{}
		if pNamespace == shieldNamespace {
			nsSelector := p.Spec.Match.TargetNamespaceSelector
			if nsSelector != nil {
				targetNamespaces = matchNamespaceListWithSelector(namespaces, nsSelector)
			} else {
				targetNamespaces = append(targetNamespaces, pNamespace)
			}
		} else {
			targetNamespaces = append(targetNamespaces, pNamespace)
		}
		pWithCommon := p.Merge(commonProfileRSP)
		items = append(items, RuleItem{Profile: pWithCommon, TargetNamespaces: targetNamespaces})
		allTargetNamespaces = common.GetUnionOfArrays(allTargetNamespaces, targetNamespaces)
	}
	return &RuleTable{
		Items:           items,
		Namespaces:      allTargetNamespaces,
		ShieldNamespace: shieldNamespace,
	}
}

func (self *RuleTable) IsEmpty() bool {
	return len(self.Items) == 0
}

func (self *RuleTable) IsTargetEmpty() bool {
	count := 0
	for _, rl := range self.Items {
		count += len(rl.TargetNamespaces)
	}
	return count == 0
}

func (self *RuleTable) CheckIfTargetNamespace(nsName string) bool {
	if nsName == "" {
		return true
	}
	return common.ExactMatchWithPatternArray(nsName, self.Namespaces)
}

func (self *RuleTable) CheckIfProtected(reqFields map[string]string) (bool, bool, []rspapi.ResourceSigningProfile) {
	matchedProfiles := []rspapi.ResourceSigningProfile{}
	reqNs := reqFields["Namespace"]
	reqScope := reqFields["ResourceScope"]
	protected := false
	ignoreMatched := false
	for _, item := range self.Items {
		if reqScope == "Namespaced" && !common.ExactMatchWithPatternArray(reqNs, item.TargetNamespaces) {
			continue
		}
		if tmpProtected, matchedRule := item.Profile.Match(reqFields, self.ShieldNamespace); tmpProtected {
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

	for i := range namespaces {
		ns := namespaces[i]
		ok := nsSelector.MatchNamespace(&ns)
		if ok {
			matched = append(matched, (&ns).GetName())
		}
	}
	return matched
}
