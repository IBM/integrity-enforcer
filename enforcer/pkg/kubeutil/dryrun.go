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

package kubeutil

import (
	"errors"
	"fmt"

	"github.com/ghodss/yaml"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
)

func DryRunCreate(objBytes []byte, namespace string) ([]byte, error) {
	config, err := GetKubeConfig()
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error in getting K8s config; %s", err.Error()))
	}
	dyClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error in createging DynamicClient; %s", err.Error()))
	}

	obj := &unstructured.Unstructured{}
	objJsonBytes, err := yaml.YAMLToJSON(objBytes)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error in converting YamlToJson; %s", err.Error()))
	}
	err = obj.UnmarshalJSON(objJsonBytes)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error in Unmarshal into unstructured obj; %s", err.Error()))
	}
	obj.SetName(fmt.Sprintf("%s-dry-run", obj.GetName()))

	gvk := obj.GroupVersionKind()
	gvr, _ := meta.UnsafeGuessKindToResource(gvk)
	gvClient := dyClient.Resource(gvr)

	var simObj *unstructured.Unstructured
	if namespace == "" {
		simObj, err = gvClient.Create(obj, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	} else {
		simObj, err = gvClient.Namespace(namespace).Create(obj, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	}
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error in createging resource; %s, gvk: %s", err.Error(), gvk))
	}
	simObjBytes, err := yaml.Marshal(simObj)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error in converting ojb to yaml; %s", err.Error()))
	}
	return simObjBytes, nil
}
