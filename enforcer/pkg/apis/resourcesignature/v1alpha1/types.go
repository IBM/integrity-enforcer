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
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/IBM/integrity-enforcer/enforcer/pkg/mapnode"
	yaml "gopkg.in/yaml.v2"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"

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
// +resource:path=resourcesignature,scope=Namespaced

// ResourceSignature is the CRD. Use this command to generate deepcopy for it:
// ./k8s.io/code-generator/generate-groups.sh all github.com/IBM/pas-client-go/pkg/crd/packageadmissionsignature/v1/apis github.com/IBM/pas-client-go/pkg/crd/ "packageadmissionsignature:v1"
// For more details of code-generator, please visit https://github.com/kubernetes/code-generator
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// ResourceSignature is the CRD. Use this command to generate deepcopy for it:
type ResourceSignature struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata"`
	// Specification of the desired behavior of ResourceSignature.
	Spec ResourceSignatureSpec `json:"spec"`
	// Observed status of ResourceSignature.
	Status ResourceSignatureStatus `json:"status"`
}

func (ss *ResourceSignature) FindMessage(apiVersion, kind, name, namespace string) (string, bool) {
	si, _, found := ss.FindSignItem(apiVersion, kind, name, namespace)
	if found {
		return si.Message, true
	}
	return "", false
}

func (ss *ResourceSignature) FindSignature(apiVersion, kind, name, namespace string) (string, bool) {
	si, _, found := ss.FindSignItem(apiVersion, kind, name, namespace)
	if found {
		return si.Signature, true
	}
	return "", false
}

func (ss *ResourceSignature) FindSignItem(apiVersion, kind, name, namespace string) (*SignItem, []byte, bool) {
	signItem := &SignItem{}
	for _, si := range ss.Spec.Data {
		if matched, yamlBytes := si.match(apiVersion, kind, name, namespace); matched {
			return si, yamlBytes, true
		}
	}
	return signItem, nil, false
}

func (ss *ResourceSignature) Validate() (bool, string) {
	if ss == nil {
		return false, "ResourceSignature Validation failed. ss is nil."
	}
	if ss.Spec.Data == nil {
		return false, "ResourceSignature Validation failed. ss.Spec.Data is nil."
	}
	// TODO: implement
	return true, ""
}

// ResourceSignatureSpec is a desired state description of ResourceSignature.
type ResourceSignatureSpec struct {
	Data []*SignItem `json:"data"`
}

// ResourceSignature describes the lifecycle status of ResourceSignature.
type ResourceSignatureStatus struct {
	State   string `json:"state"`
	Message string `json:"message"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ResourceSignatureList is a list of Workflow resources
type ResourceSignatureList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []*ResourceSignature `json:"items"`
}

func (ssl *ResourceSignatureList) FindMessage(apiVersion, kind, name, namespace string) (string, bool) {
	si, _, found := ssl.FindSignItem(apiVersion, kind, name, namespace)
	if found {
		return si.Message, true
	}
	return "", false
}

func (ssl *ResourceSignatureList) FindSignature(apiVersion, kind, name, namespace string) (string, bool) {
	si, _, found := ssl.FindSignItem(apiVersion, kind, name, namespace)
	if found {
		return si.Signature, true
	}
	return "", false
}

func (ssl *ResourceSignatureList) FindSignItem(apiVersion, kind, name, namespace string) (*SignItem, []byte, bool) {
	signItem := &SignItem{}
	for _, ss := range ssl.Items {
		if si, yamlBytes, ok := ss.FindSignItem(apiVersion, kind, name, namespace); ok {
			return si, yamlBytes, true
		}
	}
	return signItem, nil, false
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
	raw        []byte // raw yaml of single resource
}

func (si *SignItem) match(apiVersion, kind, name, namespace string) (bool, []byte) {
	for _, ri := range si.parseMessage() {
		if ri.ApiVersion == apiVersion &&
			ri.Kind == kind &&
			ri.Name == name &&
			(ri.Namespace == namespace || ri.Namespace == "") {
			return true, ri.raw
		}
	}
	return false, nil
}

func (si *SignItem) parseMessage() []ResourceInfo {
	msg := base64decode(si.Message)
	r := bytes.NewReader([]byte(msg))
	dec := k8syaml.NewYAMLToJSONDecoder(r)
	var t interface{}
	resources := []ResourceInfo{}
	for dec.Decode(&t) == nil {
		tB, err := yaml.Marshal(t)
		if err != nil {
			continue
		}
		n, err := mapnode.NewFromYamlBytes(tB)
		if err != nil {
			continue
		}
		apiVersion := n.GetString("apiVersion")
		kind := n.GetString("kind")
		name := n.GetString("metadata.name")
		namespace := n.GetString("metadata.namespace")
		tmp := ResourceInfo{
			ApiVersion: apiVersion,
			Kind:       kind,
			Name:       name,
			Namespace:  namespace,
			raw:        tB,
		}
		resources = append(resources, tmp)
	}
	return resources
}

func base64decode(str string) string {
	decBytes, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ""
	}
	dec := string(decBytes)
	return dec
}

func convert(m map[interface{}]interface{}) map[string]interface{} {
	res := map[string]interface{}{}
	for k, v := range m {
		switch v2 := v.(type) {
		case map[interface{}]interface{}:
			res[fmt.Sprint(k)] = convert(v2)
		default:
			res[fmt.Sprint(k)] = v
		}
	}
	return res
}
