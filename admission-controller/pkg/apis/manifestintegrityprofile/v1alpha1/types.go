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
	k8smnfconfig "github.com/IBM/integrity-shield/integrity-shield-server/pkg/config"
	"github.com/jinzhu/copier"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var layout = "2006-01-02 15:04:05"

const maxHistoryLength = 3

// ManifestIntegrityProfileSpec defines the desired state of AppEnforcePolicy
type ManifestIntegrityProfileSpec struct {
	Match      MatchCondition               `json:"match,omitempty"`
	Parameters k8smnfconfig.ParameterObject `json:"parameters,omitempty"`
}

type MatchCondition struct {
	Kinds              []Kinds               `json:"kinds,omitempty"`
	Namespaces         []string              `json:"namespaces,omitempty"`
	ExcludedNamespaces []string              `json:"excludedNamespaces,omitempty"`
	LabelSelector      *metav1.LabelSelector `json:"labelSelector,omitempty"`
	NamespaceSelector  *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

type Kinds struct {
	Kinds     []string `json:"kinds,omitempty"`
	ApiGroups []string `json:"apiGroups,omitempty"`
}

// ManifestIntegrityProfileStatus defines the observed state of AppEnforcePolicy
type ManifestIntegrityProfileStatus struct {
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=manifestintegrityprofile,scope=Cluster

// EnforcePolicy is the CRD. Use this command to generate deepcopy for it:
// ./k8s.io/code-generator/generate-groups.sh all github.com/IBM/pas-client-go/pkg/crd/packageadmissionsignature/v1/apis github.com/IBM/pas-client-go/pkg/crd/ "packageadmissionsignature:v1"
// For more details of code-generator, please visit https://github.com/kubernetes/code-generator
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// ManifestIntegrityProfile is the CRD. Use this command to generate deepcopy for it:
type ManifestIntegrityProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ManifestIntegrityProfileSpec   `json:"spec,omitempty"`
	Status ManifestIntegrityProfileStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ManifestIntegrityProfileList contains a list of ManifestIntegrityProfile
type ManifestIntegrityProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ManifestIntegrityProfile `json:"items"`
}

func (p *MatchCondition) DeepCopyInto(p2 *MatchCondition) {
	copier.Copy(&p2, &p)
}
