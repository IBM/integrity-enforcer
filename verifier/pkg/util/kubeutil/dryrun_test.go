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
	"io/ioutil"
	"testing"
)

func TestSimulator(t *testing.T) {
	testObj, err := ioutil.ReadFile("testdata/sample_configmap.yaml")
	if err != nil {
		t.Error(err)
	}
	simObj, err := DryRunCreate(testObj, "default")
	if err != nil {
		t.Error(err)
	}
	t.Log(string(simObj))
}

func TestGetApplyPatchBytes(t *testing.T) {
	testObj, err := ioutil.ReadFile("testdata/sample_configmap_after.yaml")
	if err != nil {
		t.Error(err)
	}
	patch, simObj, err := GetApplyPatchBytes(testObj, "default")
	if err != nil {
		t.Error(err)
	}
	t.Log("patch: ", string(patch))
	t.Log("patchedObject: ", string(simObj))
}
