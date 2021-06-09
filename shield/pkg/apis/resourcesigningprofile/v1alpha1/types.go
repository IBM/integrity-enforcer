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
	AdditionalProtectRules []*common.Rule         `json:"additionalProtectRules,omitempty"`
	IgnoreRules            []*common.Rule         `json:"ignoreRules,omitempty"`
	ProtectAttrs           []*common.AttrsPattern `json:"protectAttrs,omitempty"`
	IgnoreAttrs            []*common.AttrsPattern `json:"ignoreAttrs,omitempty"`
	TargetServiceAccount   string                 `json:"targetServiceAccount,omitempty"`

	// ManifestReference
	ManifestReference *ManifestReference `json:"manifestRef,omitempty"`

	// SignerConfig
	SignerConfig *common.SignerConfig `json:"signerConfig,omitempty"`

	// ImageProfile
	ImageProfile *common.ImageProfile `json:"imageProfile,omitempty"`

	// some other controls
	commonProfilesEmbedded bool `json:"-"`
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
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=resourcesigningprofile,scope=Cluster

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

func (self ResourceSigningProfile) Match(reqFields map[string]string) (bool, *common.Rule) {
	scope := "Namespaced"
	if reqScope, ok := reqFields["ResourceScope"]; ok && reqScope == "Cluster" {
		scope = reqScope
	}

	strictMatch := false
	if scope == "Cluster" {
		strictMatch = true
	}

	for _, rule := range self.Spec.Parameters.IgnoreRules {
		if strictMatch && rule.StrictMatchWithRequest(reqFields) {
			return false, rule
		} else if !strictMatch && rule.MatchWithRequest(reqFields) {
			return false, rule
		}
	}
	protectRuleMatched := false
	var matchedRule *common.Rule
	for i, rule := range self.Spec.Match.ProtectRules {
		if strictMatch && rule.StrictMatchWithRequest(reqFields) {
			protectRuleMatched = true
			matchedRule = self.Spec.Match.ProtectRules[i]
			break
		} else if !strictMatch && rule.MatchWithRequest(reqFields) {
			protectRuleMatched = true
			matchedRule = self.Spec.Match.ProtectRules[i]
			break
		}
	}

	if protectRuleMatched && len(self.Spec.Parameters.AdditionalProtectRules) > 0 {
		additionalProtectRuleMatched := false
		for _, rule := range self.Spec.Parameters.AdditionalProtectRules {
			if strictMatch && rule.StrictMatchWithRequest(reqFields) {
				additionalProtectRuleMatched = true
				break
			} else if !strictMatch && rule.MatchWithRequest(reqFields) {
				additionalProtectRuleMatched = true
				break
			}
		}
		protectRuleMatched = (protectRuleMatched && additionalProtectRuleMatched)
	}
	if protectRuleMatched {
		return true, matchedRule
	}

	return false, nil
}

func (self ResourceSigningProfile) EmbedCommonProfiles(another ResourceSigningProfile) ResourceSigningProfile {
	newProfile := self.Merge(another)
	newProfile.Spec.Parameters.commonProfilesEmbedded = true
	return newProfile
}

func (self ResourceSigningProfile) Merge(another ResourceSigningProfile) ResourceSigningProfile {
	newProfile := self
	newProfile.Spec.Match.ProtectRules = append(newProfile.Spec.Match.ProtectRules, another.Spec.Match.ProtectRules...)
	newProfile.Spec.Parameters = newProfile.Spec.Parameters.Merge(another.Spec.Parameters)
	return newProfile
}

func (self ResourceSigningProfile) IsCommonProfilesEmbedded() bool {
	return self.Spec.Parameters.commonProfilesEmbedded
}

func (self Parameters) GetProtectAttrs(reqFields map[string]string) []*common.AttrsPattern {
	patterns := []*common.AttrsPattern{}
	for _, attrsPattern := range self.ProtectAttrs {
		if attrsPattern.MatchWith(reqFields) {
			patterns = append(patterns, attrsPattern)
		}
	}
	return patterns
}

func (self Parameters) GetIgnoreAttrs(reqFields map[string]string) []*common.AttrsPattern {
	patterns := []*common.AttrsPattern{}
	for _, attrsPattern := range self.IgnoreAttrs {
		if attrsPattern.MatchWith(reqFields) {
			patterns = append(patterns, attrsPattern)
		}
	}
	return patterns
}

func (self Parameters) EmbedCommonProfiles(another Parameters) Parameters {
	newParameters := self.Merge(another)
	newParameters.commonProfilesEmbedded = true
	return newParameters
}

func (self Parameters) Merge(another Parameters) Parameters {
	newParameters := self
	newParameters.IgnoreRules = append(newParameters.IgnoreRules, another.IgnoreRules...)
	newParameters.ProtectAttrs = append(newParameters.ProtectAttrs, another.ProtectAttrs...)
	newParameters.IgnoreAttrs = append(newParameters.IgnoreAttrs, another.IgnoreAttrs...)
	return newParameters
}

func (self Parameters) IsCommonProfilesEmbedded() bool {
	return self.commonProfilesEmbedded
}

func (self Parameters) IgnoreMatch(reqFields map[string]string) (bool, *common.Rule) {
	scope := "Namespaced"
	if reqScope, ok := reqFields["ResourceScope"]; ok && reqScope == "Cluster" {
		scope = reqScope
	}

	strictMatch := false
	if scope == "Cluster" {
		strictMatch = true
	}

	for _, rule := range self.IgnoreRules {
		if strictMatch && rule.StrictMatchWithRequest(reqFields) {
			return true, rule
		} else if !strictMatch && rule.MatchWithRequest(reqFields) {
			return true, rule
		}
	}
	return false, nil
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

type ManifestReference struct {
	Image string `json:"image,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ResourceSigningProfileList contains a list of ResourceSigningProfile
type ResourceSigningProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ResourceSigningProfile `json:"items"`
}
