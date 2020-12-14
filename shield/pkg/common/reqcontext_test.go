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
	"bytes"
	"encoding/json"
	"io/ioutil"
	"testing"

	v1beta1 "k8s.io/api/admission/v1beta1"
)

const reqcPath = "./testdata/reqc_1.json"

func TestReqContext(t *testing.T) {
	reqcBytes, err := ioutil.ReadFile(reqcPath)
	if err != nil {
		t.Error(err)
	}

	var reqc *ReqContext
	err = json.Unmarshal(reqcBytes, &reqc)
	if err != nil {
		t.Error(err)
		return
	}
	var req *v1beta1.AdmissionRequest
	err = json.Unmarshal([]byte(reqc.RequestJsonStr), &req)
	if err != nil {
		t.Error(err)
		return
	}

	actualReqc := NewReqContext(req)
	actualReqcBytes, err := json.Marshal(actualReqc)
	if err != nil {
		t.Error(err)
		return
	}
	if !bytes.Equal(reqcBytes, actualReqcBytes) {
		t.Errorf("TestReqContext() Failed;\nexpected:\n  %s\nactual:\n  %s", string(reqcBytes), string(actualReqcBytes))
	} else {
		t.Log("TestReqContext() passed")
	}

}
