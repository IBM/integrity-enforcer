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
	profile          rspapi.ResourceSigningProfile `json:"-"`
	targetNamespaces []string                      `json:"-"`
}

type RuleTable2 struct {
	items             []RuleItem2 `json:"-"`
	namespaces        []string    `json:"-"`
	verifierNamespace string      `json:"-"`
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
		items = append(items, RuleItem2{profile: p, targetNamespaces: targetNamespaces})
		allTargetNamespaces = common.GetUnionOfArrays(allTargetNamespaces, targetNamespaces)
	}
	return &RuleTable2{
		items:             items,
		namespaces:        allTargetNamespaces,
		verifierNamespace: verifierNamespace,
	}
}

func (self *RuleTable2) CheckIfTargetNamespace(nsName string) bool {
	if nsName == "" {
		return true
	}
	return common.ExactMatchWithPatternArray(nsName, self.namespaces)
}

func (self *RuleTable2) CheckIfProtected(reqFields map[string]string) (bool, []rspapi.ResourceSigningProfile) {
	matchedProfiles := []rspapi.ResourceSigningProfile{}
	reqNs := reqFields["Namespace"]
	reqScope := reqFields["ResourceScope"]
	matched := false
	for _, item := range self.items {
		if reqScope == "Namespaced" && !common.ExactMatchWithPatternArray(reqNs, item.targetNamespaces) {
			continue
		}
		if item.profile.Match(reqFields) {
			matched = true
			matchedProfiles = append(matchedProfiles, item.profile)
		}
	}
	return matched, matchedProfiles
}

func matchNamespaceListWithSelector(namespaces []v1.Namespace, nsSelector *common.NamespaceSelector) []string {
	matched := []string{}
	for _, ns := range namespaces {
		if nsSelector.MatchNamespace(&ns) {
			matched = append(matched, ns.GetName())
		}
	}
	return matched
}
