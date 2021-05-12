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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ProtectedResourceIntegritySpec defines the desired state of AppEnforcePolicy
type ProtectedResourceIntegritySpec struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
}

// ProtectedResourceIntegrityStatus defines the observed state of AppEnforcePolicy
type ProtectedResourceIntegrityStatus struct {
	Verified         bool        `json:"verified"`
	Result           string      `json:"result"`
	LastVerified     metav1.Time `json:"lastVerified"`
	LastUpdated      metav1.Time `json:"lastUpdated"`
	Profiles         string      `json:"profiles"`
	AllowedUsernames string      `json:"allowedUsernames"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=ProtectedResourceIntegrity,scope=Namespaced

// EnforcePolicy is the CRD. Use this command to generate deepcopy for it:
// ./k8s.io/code-generator/generate-groups.sh all github.com/IBM/pas-client-go/pkg/crd/packageadmissionsignature/v1/apis github.com/IBM/pas-client-go/pkg/crd/ "packageadmissionsignature:v1"
// For more details of code-generator, please visit https://github.com/kubernetes/code-generator
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// ProtectedResourceIntegrity is the CRD. Use this command to generate deepcopy for it:
type ProtectedResourceIntegrity struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ProtectedResourceIntegritySpec   `json:"spec,omitempty"`
	Status ProtectedResourceIntegrityStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ProtectedResourceIntegrityList contains a list of ProtectedResourceIntegrity
type ProtectedResourceIntegrityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProtectedResourceIntegrity `json:"items"`
}
