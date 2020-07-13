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
	pkix "github.com/IBM/integrity-enforcer/develop/signservice/signservice-operator/pkg/pkix"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// SignServiceSpec defines the desired state of SignService
type SignServiceSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	Enabled                  bool                      `json:"enabled,omitempty"`
	KeyRingSecretName        string                    `json:"keyRingSecretName,omitempty"`
	PrivateKeyRingSecretName string                    `json:"privateKeyRingSecretName,omitempty"`
	SignServiceSecretName    string                    `json:"signServiceSecretName,omitempty"`
	IECertPoolSecretName     string                    `json:"ieCertPoolSecretName,omitempty"`
	ImagePullSecrets         []v1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
	ServiceAccountName       string                    `json:"serviceAccountName,omitempty"`
	SignService              SignServiceContainer      `json:"signService,omitempty"`
	Signers                  []string                  `json:"signers,omitempty"`
	InvalidSigners           []string                  `json:"invalidSigners,omitempty"`
	CertSigners              []pkix.SignerCertName     `json:"certSigners,omitempty"`
}

type SignServiceContainer struct {
	Image           string                  `json:"image,omitempty"`
	ImagePullPolicy v1.PullPolicy           `json:"imagePullPolicy,omitempty"`
	Port            int32                   `json:"port,omitempty"`
	Resources       v1.ResourceRequirements `json:"resources,omitempty"`
	AppName         string                  `json:"appName,omitempty"`
}

// SignServiceStatus defines the observed state of SignService
type SignServiceStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SignService is the Schema for the signservices API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=signservices,scope=Namespaced
type SignService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SignServiceSpec   `json:"spec,omitempty"`
	Status SignServiceStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SignServiceList contains a list of SignService
type SignServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SignService `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SignService{}, &SignServiceList{})
}
