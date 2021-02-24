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

package common

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNamespaceSelector(t *testing.T) {

	selector1 := &NamespaceSelector{Include: []string{"secure-ns", "test-ns"}}
	selector2 := &NamespaceSelector{Include: []string{"test-ns"}, Exclude: []string{"kube-*", "openshift-*"}}
	selector := selector1.Merge(selector2)
	ok1 := selector.MatchNamespaceName("secure-ns")
	if !ok1 {
		t.Error("TestNamespaceSelector() Failed")
		return
	}
	ok2 := selector.MatchNamespaceName("kube-system")
	if ok2 {
		t.Error("TestNamespaceSelector() Failed")
		return
	}
	selector.LabelSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"testLabel": "true"}}
	ns1 := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", Labels: map[string]string{"testLabel": "true"}}}
	ok3 := selector.MatchNamespace(ns1)
	if !ok3 {
		t.Error("TestNamespaceSelector() Failed")
		return
	}
	_ = selector.DeepCopy()
}

func TestResourceRef(t *testing.T) {
	ref1 := &ResourceRef{
		Name:       "test-deploy",
		Namespace:  "test-ns",
		ApiVersion: "apps/v1",
		Kind:       "Deployment",
	}
	ref2 := &ResourceRef{
		Name:       "test-deploy",
		Namespace:  "test-ns",
		ApiVersion: "extensions/v1beta1",
		Kind:       "Deployment",
	}
	if ok1 := ref1.Equals(ref2); ok1 {
		t.Error("TestResourceRef() Failed")
		return
	}
	if ok2 := ref1.EqualsWithoutVersionCheck(ref2); !ok2 {
		t.Error("TestResourceRef() Failed")
		return
	}
}
