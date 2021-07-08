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

package config

import (
	"github.com/jinzhu/copier"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type ParameterObject struct {
	k8smanifest.VerifyOption `json:""`
	InScopeObjects           k8smanifest.ObjectReferenceList `json:"inScopeObjects,omitempty"`
	SkipUsers                ObjectUserBindingList           `json:"skipUsers,omitempty"`
	KeySecertName            string                          `json:"keySecretName,omitempty"`
	KeySecertNamespace       string                          `json:"keySecretNamespace,omitempty"`
	ImageRef                 string                          `json:"imageRef,omitempty"`
	TargetServiceAccount     []string                        `json:"targetServiceAccount,omitempty"`
	ImageProfile             ImageProfile                    `json:"imageProfile,omitempty"`
}

type ObjectUserBindingList []ObjectUserBinding

type ObjectUserBinding struct {
	Objects k8smanifest.ObjectReferenceList `json:"objects,omitempty"`
	Users   []string                        `json:"users,omitempty"`
}

type ImageProfile struct {
}

func (p *ParameterObject) DeepCopyInto(p2 *ParameterObject) {
	copier.Copy(&p2, &p)
}

func (u ObjectUserBinding) Match(obj unstructured.Unstructured, username string) bool {
	if u.Objects.Match(obj) {
		if k8smnfutil.MatchWithPatternArray(username, u.Users) {
			return true
		}
	}
	return false
}

func (l ObjectUserBindingList) Match(obj unstructured.Unstructured, username string) bool {
	if len(l) == 0 {
		return false
	}
	for _, u := range l {
		if u.Match(obj, username) {
			return true
		}
	}
	return false
}
