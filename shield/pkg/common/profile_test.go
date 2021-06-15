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
	"encoding/json"
	"io/ioutil"
	"testing"
)

func TestProfile(t *testing.T) {
	reqcBytes, err := ioutil.ReadFile(reqcPath)
	if err != nil {
		t.Error(err)
	}

	var reqc *RequestContext
	err = json.Unmarshal(reqcBytes, &reqc)
	if err != nil {
		t.Error(err)
		return
	}
	var rule *Rule
	ruleBytes := []byte(`{"match":[{"kind":"ConfigMap","name":"sample-cm"}]}`)
	err = json.Unmarshal(ruleBytes, &rule)
	if err != nil {
		t.Error(err)
		return
	}
	reqFields := reqc.Map()
	ok1 := rule.MatchWithRequest(reqFields)
	ruleStr := rule.String()

	// t.Log(reqFields)
	// t.Log(ruleStr)
	if !ok1 {
		t.Errorf("Rule does not match; Rule: %s, RequestRef: %s", ruleStr, reqc.ResourceRef())
		return
	}

	reqFields["ResourceScope"] = "Cluster"
	reqFields["Kind"] = "ClusterRole"
	reqFields["Name"] = "sample-clusterrole"
	reqFields["Namespace"] = ""
	reqFields["ApiGroup"] = "rbac.authorization.k8s.io"
	reqFields["ApiVersion"] = "v1"

	ruleBytes = []byte(`{"match":[{"kind":"ClusterRole"}]}`)
	err = json.Unmarshal(ruleBytes, &rule)
	if err != nil {
		t.Error(err)
		return
	}
	ok2 := rule.MatchWithRequest(reqFields)
	ruleStr = rule.String()

	// t.Log(reqFields)
	// t.Log(ruleStr)
	if ok2 {
		t.Errorf("Rule does not match; Rule: %s, RequestRef: %s", ruleStr, reqc.ResourceRef())
		return
	}

	sampleClusterRoleName := RulePattern("sample-clusterrole")
	rule.Match[0].Name = &sampleClusterRoleName
	ok3 := rule.MatchWithRequest(reqFields)
	ruleStr = rule.String()
	if !ok3 {
		t.Errorf("Rule does not match; Rule: %s, RequestRef: %s", ruleStr, reqc.ResourceRef())
		return
	}

	request1 := NewRequestFromReqContext(reqc)
	request2 := NewRequestFromReqContext(reqc)
	request1Str := request1.String()
	request2Str := request2.String()
	if !request1.Equal(request2) {
		t.Errorf("Request does not match; Request1: %s, Request2: %s", request1Str, request2Str)
		return
	}

}

func TestKustomizePattern(t *testing.T) {
	reqcBytes, err := ioutil.ReadFile(reqcPath)
	if err != nil {
		t.Error(err)
	}

	var reqc *RequestContext
	err = json.Unmarshal(reqcBytes, &reqc)
	if err != nil {
		t.Error(err)
		return
	}
	originalName := reqc.Name
	reqc.Name = "prefix." + reqc.Name

	var kust *MetadataChangePattern
	kustBytes := []byte(`{"match":[{"kind":"ConfigMap"}],"namePrefix":"*.","allowNamespaceChange":true}`)
	err = json.Unmarshal(kustBytes, &kust)
	if err != nil {
		t.Error(err)
		return
	}
	reqFields := reqc.Map()
	if ok := kust.MatchWith(reqFields); !ok {
		t.Errorf("ReqContext does not match with MetadataChangePattern: %s", string(kustBytes))
		return
	}
	rawRef := reqc.ResourceRef()
	kustRef := kust.Override(rawRef)
	if kustRef.Name != originalName {
		t.Errorf("OverrideName() returns wrong result; expected: %s, actual: %s", originalName, kustRef.Name)
		return
	}
}
