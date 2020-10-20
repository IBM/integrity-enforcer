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

package v1alpha1

import (
	"github.com/IBM/integrity-enforcer/enforcer/pkg/protect"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ResourceProtectionProfileSpec defines the desired state of AppEnforcePolicy
type ResourceProtectionProfileSpec struct {
	Disabled bool `json:"disabled,omitempty"`
	Delete   bool `json:"delete,omitempty"`

	ProtectRules      []*protect.Rule             `json:"protectRules,omitempty"`
	IgnoreRules       []*protect.Rule             `json:"ignoreRules,omitempty"`
	ForceCheckRules   []*protect.Rule             `json:"forceCheckRules,omitempty"`
	KustomizePatterns []*protect.KustomizePattern `json:"kustomizePatterns,omitempty"`
	ProtectAttrs      []*protect.AttrsPattern     `json:"protectAttrs,omitempty"`
	UnprotectAttrs    []*protect.AttrsPattern     `json:"unprotectAttrs,omitempty"`
	IgnoreAttrs       []*protect.AttrsPattern     `json:"ignoreAttrs,omitempty"`
}

// ResourceProtectionProfileStatus defines the observed state of AppEnforcePolicy
type ResourceProtectionProfileStatus struct {
	Results []*protect.Result `json:"deniedRequests,omitempty"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=resourceprotectionprofile,scope=Namespaced

// EnforcePolicy is the CRD. Use this command to generate deepcopy for it:
// ./k8s.io/code-generator/generate-groups.sh all github.com/IBM/pas-client-go/pkg/crd/packageadmissionsignature/v1/apis github.com/IBM/pas-client-go/pkg/crd/ "packageadmissionsignature:v1"
// For more details of code-generator, please visit https://github.com/kubernetes/code-generator
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// ResourceProtectionProfile is the CRD. Use this command to generate deepcopy for it:
type ResourceProtectionProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ResourceProtectionProfileSpec   `json:"spec,omitempty"`
	Status ResourceProtectionProfileStatus `json:"status,omitempty"`
}

func (self ResourceProtectionProfile) IsEmpty() bool {
	return len(self.Spec.ProtectRules) == 0
}

func (self ResourceProtectionProfile) Match(reqFields map[string]string) (bool, *protect.Rule) {
	for _, rule := range self.Spec.ProtectRules {
		if rule.MatchWithRequest(reqFields) {
			return true, rule
		}
	}
	return false, nil
}

func (self ResourceProtectionProfile) ToRuleTable() *protect.RuleTable {
	gvk := self.GroupVersionKind()
	source := &v1.ObjectReference{
		APIVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		Namespace:  self.GetNamespace(),
		Name:       self.GetName(),
	}
	table := protect.NewRuleTable()
	table = table.Add(self.Spec.ProtectRules, source)
	return table
}

func (self ResourceProtectionProfile) ToIgnoreRuleTable() *protect.RuleTable {
	gvk := self.GroupVersionKind()
	source := &v1.ObjectReference{
		APIVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		Namespace:  self.GetNamespace(),
		Name:       self.GetName(),
	}
	table := protect.NewRuleTable()
	table = table.Add(self.Spec.IgnoreRules, source)
	return table
}

func (self ResourceProtectionProfile) ToForceCheckRuleTable() *protect.RuleTable {
	gvk := self.GroupVersionKind()
	source := &v1.ObjectReference{
		APIVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		Namespace:  self.GetNamespace(),
		Name:       self.GetName(),
	}
	table := protect.NewRuleTable()
	table = table.Add(self.Spec.ForceCheckRules, source)
	return table
}

func (self ResourceProtectionProfile) Merge(another ResourceProtectionProfile) ResourceProtectionProfile {
	newProfile := self
	newProfile.Spec.ProtectRules = append(newProfile.Spec.ProtectRules, another.Spec.ProtectRules...)
	newProfile.Spec.IgnoreRules = append(newProfile.Spec.IgnoreRules, another.Spec.IgnoreRules...)
	newProfile.Spec.ForceCheckRules = append(newProfile.Spec.ForceCheckRules, another.Spec.ForceCheckRules...)
	newProfile.Spec.ProtectAttrs = append(newProfile.Spec.ProtectAttrs, another.Spec.ProtectAttrs...)
	newProfile.Spec.UnprotectAttrs = append(newProfile.Spec.UnprotectAttrs, another.Spec.UnprotectAttrs...)
	newProfile.Spec.IgnoreAttrs = append(newProfile.Spec.IgnoreAttrs, another.Spec.IgnoreAttrs...)
	return newProfile
}

func (self ResourceProtectionProfile) Kustomize(reqFields map[string]string) []*protect.KustomizePattern {
	patterns := []*protect.KustomizePattern{}
	for _, kustPattern := range self.Spec.KustomizePatterns {
		if kustPattern.MatchWith(reqFields) {
			patterns = append(patterns, kustPattern)
		}
	}
	return patterns
}

func (self ResourceProtectionProfile) ProtectAttrs(reqFields map[string]string) []*protect.AttrsPattern {
	patterns := []*protect.AttrsPattern{}
	for _, attrsPattern := range self.Spec.ProtectAttrs {
		if attrsPattern.MatchWith(reqFields) {
			patterns = append(patterns, attrsPattern)
		}
	}
	return patterns
}

func (self ResourceProtectionProfile) UnprotectAttrs(reqFields map[string]string) []*protect.AttrsPattern {
	patterns := []*protect.AttrsPattern{}
	for _, attrsPattern := range self.Spec.UnprotectAttrs {
		if attrsPattern.MatchWith(reqFields) {
			patterns = append(patterns, attrsPattern)
		}
	}
	return patterns
}

func (self ResourceProtectionProfile) IgnoreAttrs(reqFields map[string]string) []*protect.AttrsPattern {
	patterns := []*protect.AttrsPattern{}
	for _, attrsPattern := range self.Spec.IgnoreAttrs {
		if attrsPattern.MatchWith(reqFields) {
			patterns = append(patterns, attrsPattern)
		}
	}
	return patterns
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ResourceProtectionProfileList contains a list of ResourceProtectionProfile
type ResourceProtectionProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ResourceProtectionProfile `json:"items"`
}
