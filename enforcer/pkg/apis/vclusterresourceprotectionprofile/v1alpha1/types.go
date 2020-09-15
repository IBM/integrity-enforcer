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

// VClusterResourceProtectionProfileSpec defines the desired state of AppEnforcePolicy
type VClusterResourceProtectionProfileSpec struct {
	Disabled              bool `json:"disabled,omitempty"`
	Delete                bool `json:"delete,omitempty"`
	CheckPlatformRequests bool `json:"checkPlatformRequests,omitempty"`

	Rules                []*protect.Rule                 `json:"rules,omitempty"`
	IgnoreServiceAccount []*protect.ServieAccountPattern `json:"ignoreServiceAccount,omitempty"`
	ProtectAttrs         []*protect.AttrsPattern         `json:"protectAttrs,omitempty"`
	IgnoreAttrs          []*protect.AttrsPattern         `json:"ignoreAttrs,omitempty"`
}

// VClusterResourceProtectionProfileStatus defines the observed state of AppEnforcePolicy
type VClusterResourceProtectionProfileStatus struct {
	Results []*protect.Result `json:"deniedRequests,omitempty"`
}

// +genclient
// +genclient:noStatus
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=vclusterresourceprotectionprofile,scope=Cluster

// EnforcePolicy is the CRD. Use this command to generate deepcopy for it:
// ./k8s.io/code-generator/generate-groups.sh all github.com/IBM/pas-client-go/pkg/crd/packageadmissionsignature/v1/apis github.com/IBM/pas-client-go/pkg/crd/ "packageadmissionsignature:v1"
// For more details of code-generator, please visit https://github.com/kubernetes/code-generator
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// VClusterResourceProtectionProfile is the CRD. Use this command to generate deepcopy for it:
type VClusterResourceProtectionProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VClusterResourceProtectionProfileSpec   `json:"spec,omitempty"`
	Status VClusterResourceProtectionProfileStatus `json:"status,omitempty"`
}

func (self *VClusterResourceProtectionProfile) IsEmpty() bool {
	return len(self.Spec.Rules) == 0
}

func (self *VClusterResourceProtectionProfile) Match(reqFields map[string]string) (bool, *protect.Rule) {
	for _, rule := range self.Spec.Rules {
		if rule.MatchWithRequest(reqFields) {
			return true, rule
		}
	}
	return false, nil
}

func (self *VClusterResourceProtectionProfile) Update(reqFields map[string]string, matchedRule *protect.Rule) {
	results := self.Status.Results
	newResult := &protect.Result{}
	newResult.Update(reqFields, matchedRule)
	results = append(results, newResult)
	self.Status.Results = results
	return
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient:nonNamespaced
// VClusterResourceProtectionProfileList contains a list of VClusterResourceProtectionProfile
type VClusterResourceProtectionProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VClusterResourceProtectionProfile `json:"items"`
}
