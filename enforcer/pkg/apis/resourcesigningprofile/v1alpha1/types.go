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
	"time"

	"github.com/IBM/integrity-enforcer/enforcer/pkg/protect"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var layout = "2006-01-02 15:04:05"

const maxHistoryLength = 3

// ResourceSigningProfileSpec defines the desired state of AppEnforcePolicy
type ResourceSigningProfileSpec struct {
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

// ResourceSigningProfileStatus defines the observed state of AppEnforcePolicy
type ResourceSigningProfileStatus struct {
	Details []ProfileStatusDetail `json:"deniedRequests,omitempty"`
}

type ProfileStatusDetail struct {
	Request *protect.Request `json:"request,omitempty"`
	Count   int              `json:"count,omitempty"`
	History []protect.Result `json:"history,omitempty"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=resourcesigningprofile,scope=Namespaced

// EnforcePolicy is the CRD. Use this command to generate deepcopy for it:
// ./k8s.io/code-generator/generate-groups.sh all github.com/IBM/pas-client-go/pkg/crd/packageadmissionsignature/v1/apis github.com/IBM/pas-client-go/pkg/crd/ "packageadmissionsignature:v1"
// For more details of code-generator, please visit https://github.com/kubernetes/code-generator
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// ResourceSigningProfile is the CRD. Use this command to generate deepcopy for it:
type ResourceSigningProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ResourceSigningProfileSpec   `json:"spec,omitempty"`
	Status ResourceSigningProfileStatus `json:"status,omitempty"`
}

func (self ResourceSigningProfile) IsEmpty() bool {
	return len(self.Spec.ProtectRules) == 0
}

func (self ResourceSigningProfile) Match(reqFields map[string]string) (bool, *protect.Rule) {
	for _, rule := range self.Spec.ProtectRules {
		if rule.MatchWithRequest(reqFields) {
			return true, rule
		}
	}
	return false, nil
}

func (self ResourceSigningProfile) ToRuleTable() *protect.RuleTable {
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

func (self ResourceSigningProfile) ToIgnoreRuleTable() *protect.RuleTable {
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

func (self ResourceSigningProfile) ToForceCheckRuleTable() *protect.RuleTable {
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

func (self ResourceSigningProfile) Merge(another ResourceSigningProfile) ResourceSigningProfile {
	newProfile := self
	newProfile.Spec.ProtectRules = append(newProfile.Spec.ProtectRules, another.Spec.ProtectRules...)
	newProfile.Spec.IgnoreRules = append(newProfile.Spec.IgnoreRules, another.Spec.IgnoreRules...)
	newProfile.Spec.ForceCheckRules = append(newProfile.Spec.ForceCheckRules, another.Spec.ForceCheckRules...)
	newProfile.Spec.ProtectAttrs = append(newProfile.Spec.ProtectAttrs, another.Spec.ProtectAttrs...)
	newProfile.Spec.UnprotectAttrs = append(newProfile.Spec.UnprotectAttrs, another.Spec.UnprotectAttrs...)
	newProfile.Spec.IgnoreAttrs = append(newProfile.Spec.IgnoreAttrs, another.Spec.IgnoreAttrs...)
	return newProfile
}

func (self ResourceSigningProfile) Kustomize(reqFields map[string]string) []*protect.KustomizePattern {
	patterns := []*protect.KustomizePattern{}
	for _, kustPattern := range self.Spec.KustomizePatterns {
		if kustPattern.MatchWith(reqFields) {
			patterns = append(patterns, kustPattern)
		}
	}
	return patterns
}

func (self ResourceSigningProfile) ProtectAttrs(reqFields map[string]string) []*protect.AttrsPattern {
	patterns := []*protect.AttrsPattern{}
	for _, attrsPattern := range self.Spec.ProtectAttrs {
		if attrsPattern.MatchWith(reqFields) {
			patterns = append(patterns, attrsPattern)
		}
	}
	return patterns
}

func (self ResourceSigningProfile) UnprotectAttrs(reqFields map[string]string) []*protect.AttrsPattern {
	patterns := []*protect.AttrsPattern{}
	for _, attrsPattern := range self.Spec.UnprotectAttrs {
		if attrsPattern.MatchWith(reqFields) {
			patterns = append(patterns, attrsPattern)
		}
	}
	return patterns
}

func (self ResourceSigningProfile) IgnoreAttrs(reqFields map[string]string) []*protect.AttrsPattern {
	patterns := []*protect.AttrsPattern{}
	for _, attrsPattern := range self.Spec.IgnoreAttrs {
		if attrsPattern.MatchWith(reqFields) {
			patterns = append(patterns, attrsPattern)
		}
	}
	return patterns
}

func (self *ResourceSigningProfile) UpdateStatus(request *protect.Request, errMsg string) *ResourceSigningProfile {
	reqId := -1
	var detail ProfileStatusDetail
	for i, d := range self.Status.Details {
		if request.Equal(d.Request) {
			reqId = i
			detail = d
		}
	}
	if reqId < 0 {
		detail = ProfileStatusDetail{
			Request: request,
			Count:   1,
			History: []protect.Result{
				{
					Message:   errMsg,
					Timestamp: time.Now().UTC().Format(layout),
				},
			},
		}
		self.Status.Details = append(self.Status.Details, detail)
	} else if reqId < len(self.Status.Details) {
		detail.Count = detail.Count + 1
		newResult := protect.Result{
			Message:   errMsg,
			Timestamp: time.Now().UTC().Format(layout),
		}
		detail.History = append(detail.History, newResult)
		currentLen := len(detail.History)
		if currentLen > maxHistoryLength {
			tmpHistory := detail.History[currentLen-3:]
			detail.History = tmpHistory
		}
		self.Status.Details[reqId] = detail
	}
	return self
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ResourceSigningProfileList contains a list of ResourceSigningProfile
type ResourceSigningProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ResourceSigningProfile `json:"items"`
}
