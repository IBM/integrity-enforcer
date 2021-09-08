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

package v1

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VerifyResourceConditionSpec defines the desired state of AppEnforcePolicy
type VerifyResourceConditionSpec struct {
	ConstraintName  string         `json:"constraintName"`
	Violation       bool           `json:"violation"`
	TotalViolations int            `json:"totalViolations"`
	Violations      []VerifyResult `json:"violations"`
	NonViolations   []VerifyResult `json:"nonViolations"`
	ObservationTime string         `json:"observationTime"`
}

type VerifyResult struct {
	Namespace  string     `json:"namespace"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind"`
	ApiGroup   string     `json:"apiGroup"`
	ApiVersion string     `json:"apiVersion"`
	Result     string     `json:"result"`
	Signer     string     `json:"signer,omitempty"`
	SignedTime *time.Time `json:"signedTime,omitempty"`
	SigRef     string     `json:"sigRef,omitempty"`
}

// VerifyResourceConditionStatus defines the observed state of VerifyResourceCondition
type VerifyResourceConditionStatus struct {
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=verifyresourcecondition,scope=Namespaced

// EnforcePolicy is the CRD. Use this command to generate deepcopy for it:
// ./k8s.io/code-generator/generate-groups.sh all github.com/IBM/pas-client-go/pkg/crd/packageadmissionsignature/v1/apis github.com/IBM/pas-client-go/pkg/crd/ "packageadmissionsignature:v1"
// For more details of code-generator, please visit https://github.com/kubernetes/code-generator
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// VerifyResourceCondition is the CRD. Use this command to generate deepcopy for it:
type VerifyResourceCondition struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VerifyResourceConditionSpec   `json:"spec,omitempty"`
	Status VerifyResourceConditionStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VerifyResourceConditionList contains a list of VerifyResourceCondition
type VerifyResourceConditionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VerifyResourceCondition `json:"items"`
}
