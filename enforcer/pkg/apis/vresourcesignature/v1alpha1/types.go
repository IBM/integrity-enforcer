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
	"encoding/base64"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	MatchByExactMatch   string = "exactMatch"
	MatchByKnownFilter  string = "useKnownFilter"
	MatchByCustomFilter string = "customFilter"

	SignatureTypeResource         string = "resource"
	SignatureTypeApplyingResource string = "applyingResource"
	SignatureTypePatch            string = "patch"
	// SignatureTypeHelm string = "helm"
)

const (
	// StatePending means CRD instance is created; Pod info has been updated into CRD instance;
	// Pod has been accepted by the system, but one or more of the containers has not been started.
	StatePending string = "Pending"
	// StateRunning means Pod has been bound to a node and all of the containers have been started.
	StateRunning string = "Running"
	// StateSucceeded means that all containers in the Pod have voluntarily terminated with a container
	// exit code of 0, and the system is not going to restart any of these containers.
	StateSucceeded string = "Succeeded"
	// StateFailed means that all containers in the Pod have terminated, and at least one container has
	// terminated in a failure (exited with a non-zero exit code or was stopped by the system).
	StateFailed string = "Failed"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=vresourcesignature,scope=Namespaced

// VResourceSignature is the CRD. Use this command to generate deepcopy for it:
// ./k8s.io/code-generator/generate-groups.sh all github.com/IBM/pas-client-go/pkg/crd/packageadmissionsignature/v1/apis github.com/IBM/pas-client-go/pkg/crd/ "packageadmissionsignature:v1"
// For more details of code-generator, please visit https://github.com/kubernetes/code-generator
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// VResourceSignature is the CRD. Use this command to generate deepcopy for it:
type VResourceSignature struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata"`
	// Specification of the desired behavior of VResourceSignature.
	Spec VResourceSignatureSpec `json:"spec"`
	// Observed status of VResourceSignature.
	Status VResourceSignatureStatus `json:"status"`
}

func (ss *VResourceSignature) FindMessage(apiVersion, kind, name, namespace string) (string, bool) {
	message := ""
	found := false
	// TODO: implement
	return message, found
}

func (ss *VResourceSignature) FindSignature(apiVersion, kind, name, namespace string) (string, bool) {
	signature := ""
	found := false
	// TODO: implement
	return signature, found
}

func (ss *VResourceSignature) Validate() (bool, string) {
	if ss == nil {
		return false, "VResourceSignature Validation failed. ss is nil."
	}
	if ss.Spec.Data == nil {
		return false, "VResourceSignature Validation failed. ss.Spec.Data is nil."
	}
	// TODO: implement
	return true, ""
}

// VResourceSignatureSpec is a desired state description of VResourceSignature.
type VResourceSignatureSpec struct {
	Data []SignItem `json:"data"`
}

// VResourceSignature describes the lifecycle status of VResourceSignature.
type VResourceSignatureStatus struct {
	State   string `json:"state"`
	Message string `json:"message"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VResourceSignatureList is a list of Workflow resources
type VResourceSignatureList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []VResourceSignature `json:"items"`
}

func (ssl *VResourceSignatureList) FindMessage(apiVersion, kind, name, namespace string) (string, bool) {
	message := ""
	found := false
	// TODO: implement
	return message, found
}

func (ssl *VResourceSignatureList) FindSignature(apiVersion, kind, name, namespace string) (string, bool) {
	signature := ""
	found := false
	// TODO: implement
	return signature, found
}

func (ssl *VResourceSignatureList) FindSignItem(apiVersion, kind, name, namespace string) (SignItem, metav1.ObjectMeta, bool) {
	signItem := SignItem{}
	rsigMeta := metav1.ObjectMeta{}
	found := false
	// TODO: implement
	return signItem, rsigMeta, found
}

type SignItem struct {
	Message      string `json:"message,omitempty"`
	MessageScope string `json:"messageScope,omitempty"`
	MutableAttrs string `json:"mutableAttrs,omitempty"`
	Signature    string `json:"signature"`
	Certificate  string `json:"certificate"`
	Type         string `json:"type"`
}

type ResourceInfo struct {
	ApiVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Name       string `json:"name,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	raw        string // raw yaml of single resource
}

func (si *SignItem) parseMessage() []ResourceInfo {

	return nil
}

func base64decode(str string) string {
	decBytes, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ""
	}
	dec := string(decBytes)
	return dec
}
