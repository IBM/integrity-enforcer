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

	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var layout = "2006-01-02 15:04:05"

const maxHistoryLength = 3

// ResourceSigningProfileSpec defines the desired state of AppEnforcePolicy
type ResourceSigningProfileSpec struct {
	Match      MatchCondition `json:"match,omitempty"`
	Parameters Parameters     `json:"parameters,omitempty"`
}

type MatchCondition struct {
	// `TargetNamespaceSelector` is used only for profile in iShield NS
	TargetNamespaceSelector *common.NamespaceSelector `json:"targetNamespaceSelector,omitempty"`
	ProtectRules            []*common.Rule            `json:"protectRules,omitempty"`
}

type Parameters struct {
	// Protection
	IgnoreRules  []*common.Rule         `json:"ignoreRules,omitempty"`
	ProtectAttrs []*common.AttrsPattern `json:"protectAttrs,omitempty"`
	IgnoreAttrs  []*common.AttrsPattern `json:"ignoreAttrs,omitempty"`

	// SignerConfig
	SignerConfig *common.SignerConfig `json:"signerConfig,omitempty"`

	// ImageProfile
	ImageProfile *common.ImageProfile `json:"imageProfile,omitempty"`
}

// ResourceSigningProfileStatus defines the observed state of AppEnforcePolicy
type ResourceSigningProfileStatus struct {
	DenyCount int                     `json:"denyCount,omitempty"`
	Summary   []*ProfileStatusSummary `json:"denySummary,omitempty"`
	Latest    []*ProfileStatusDetail  `json:"latestDeniedEvents,omitempty"`
}

type ProfileStatusSummary struct {
	GroupVersionKind string `json:"groupVersionKind,omitempty"`
	Count            int    `json:"count,omitempty"`
}

type ProfileStatusDetail struct {
	Request *common.Request `json:"request,omitempty"`
	Result  *common.Result  `json:"result,omitempty"`
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
	return len(self.Spec.Match.ProtectRules) == 0
}

func (self ResourceSigningProfile) Match(reqFields map[string]string, iShieldNS string) (bool, *common.Rule) {

	rspNS := self.ObjectMeta.Namespace

	scope := "Namespaced"
	if reqScope, ok := reqFields["ResourceScope"]; ok && reqScope == "Cluster" {
		scope = reqScope
	}

	strictMatch := false
	if scope == "Cluster" && rspNS != iShieldNS {
		strictMatch = true
	}

	for _, rule := range self.Spec.Parameters.IgnoreRules {
		if strictMatch && rule.StrictMatchWithRequest(reqFields) {
			return false, rule
		} else if !strictMatch && rule.MatchWithRequest(reqFields) {
			return false, rule
		}
	}
	for _, rule := range self.Spec.Match.ProtectRules {
		if strictMatch && rule.StrictMatchWithRequest(reqFields) {
			return true, rule
		} else if !strictMatch && rule.MatchWithRequest(reqFields) {
			return true, rule
		}
	}

	return false, nil
}

func (self ResourceSigningProfile) Merge(another ResourceSigningProfile) ResourceSigningProfile {
	newProfile := self
	newProfile.Spec.Match.ProtectRules = append(newProfile.Spec.Match.ProtectRules, another.Spec.Match.ProtectRules...)
	newProfile.Spec.Parameters.IgnoreRules = append(newProfile.Spec.Parameters.IgnoreRules, another.Spec.Parameters.IgnoreRules...)
	newProfile.Spec.Parameters.ProtectAttrs = append(newProfile.Spec.Parameters.ProtectAttrs, another.Spec.Parameters.ProtectAttrs...)
	newProfile.Spec.Parameters.IgnoreAttrs = append(newProfile.Spec.Parameters.IgnoreAttrs, another.Spec.Parameters.IgnoreAttrs...)
	return newProfile
}

func (self ResourceSigningProfile) ProtectAttrs(reqFields map[string]string) []*common.AttrsPattern {
	patterns := []*common.AttrsPattern{}
	for _, attrsPattern := range self.Spec.Parameters.ProtectAttrs {
		if attrsPattern.MatchWith(reqFields) {
			patterns = append(patterns, attrsPattern)
		}
	}
	return patterns
}

func (self ResourceSigningProfile) IgnoreAttrs(reqFields map[string]string) []*common.AttrsPattern {
	patterns := []*common.AttrsPattern{}
	for _, attrsPattern := range self.Spec.Parameters.IgnoreAttrs {
		if attrsPattern.MatchWith(reqFields) {
			patterns = append(patterns, attrsPattern)
		}
	}
	return patterns
}

func (self *ResourceSigningProfile) UpdateStatus(request *common.Request, errMsg string) *ResourceSigningProfile {

	// Increment DenyCount
	self.Status.DenyCount = self.Status.DenyCount + 1

	// Update Summary
	sumId := -1
	var singleSummary *ProfileStatusSummary
	for i, s := range self.Status.Summary {
		if request.GroupVersionKind() == s.GroupVersionKind {
			sumId = i
			singleSummary = s
		}
	}
	if sumId < 0 || singleSummary == nil {
		singleSummary = &ProfileStatusSummary{
			GroupVersionKind: request.GroupVersionKind(),
			Count:            1,
		}
		self.Status.Summary = append(self.Status.Summary, singleSummary)
	} else if sumId < len(self.Status.Summary) {
		singleSummary.Count = singleSummary.Count + 1
		self.Status.Summary[sumId] = singleSummary
	}

	// Update Latest events
	result := &common.Result{
		Message:   errMsg,
		Timestamp: time.Now().UTC().Format(layout),
	}
	newLatestEvents := []*ProfileStatusDetail{}
	newSingleEvent := &ProfileStatusDetail{Request: request, Result: result}
	newLatestEvents = append(newLatestEvents, newSingleEvent)
	newLatestEvents = append(newLatestEvents, self.Status.Latest...)
	if len(newLatestEvents) > maxHistoryLength {
		newLatestEvents = newLatestEvents[:maxHistoryLength]
	}
	self.Status.Latest = newLatestEvents
	return self
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ResourceSigningProfileList contains a list of ResourceSigningProfile
type ResourceSigningProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ResourceSigningProfile `json:"items"`
}
