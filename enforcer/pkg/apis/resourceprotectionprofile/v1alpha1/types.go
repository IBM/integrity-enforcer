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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ResourceProtectionProfileSpec defines the desired state of AppEnforcePolicy
type ResourceProtectionProfileSpec struct {
	Disabled bool `json:"disabled,omitempty"`
	Delete   bool `json:"delete,omitempty"`

	Rules                []*protect.Rule                 `json:"rules,omitempty"`
	IgnoreServiceAccount []*protect.ServieAccountPattern `json:"ignoreServiceAccount,omitempty"`
	ProtectAttrs         []*protect.AttrsPattern         `json:"protectAttrs,omitempty"`
	UnprotectAttrs       []*protect.AttrsPattern         `json:"unprotectAttrs,omitempty"`
	IgnoreAttrs          []*protect.AttrsPattern         `json:"ignoreAttrs,omitempty"`
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

func (self *ResourceProtectionProfile) IsEmpty() bool {
	return len(self.Spec.Rules) == 0
}

func (self *ResourceProtectionProfile) Match(reqFields map[string]string) (bool, *protect.Rule) {
	for _, rule := range self.Spec.Rules {
		if rule.MatchWithRequest(reqFields) {
			return true, rule
		}
	}
	return false, nil
}

func (self *ResourceProtectionProfile) Update(reqFields map[string]string, reason string, matchedRule *protect.Rule) {
	results := self.Status.Results
	newResult := &protect.Result{}
	newResult.Update(reqFields, reason, matchedRule)
	results = append(results, newResult)
	self.Status.Results = results
	return
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ResourceProtectionProfileList contains a list of ResourceProtectionProfile
type ResourceProtectionProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ResourceProtectionProfile `json:"items"`
}
