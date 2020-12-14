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

	var reqc *ReqContext
	err = json.Unmarshal(reqcBytes, &reqc)
	if err != nil {
		t.Error(err)
		return
	}
	ruleBytes := []byte(`{"match":[{"scope":"Namespaced","kind":"ConfigMap"}],"exclude":[]}`)
	var rule *Rule
	err = json.Unmarshal(ruleBytes, &rule)
	if err != nil {
		t.Error(err)
		return
	}
	reqFields := reqc.Map()
	ok := rule.MatchWithRequest(reqFields)
	ruleStr := rule.String()
	if !ok {
		t.Errorf("Rule does not match the request; Rule: %s", ruleStr)
	} else {
		t.Log("TestProfile() passed")
	}

}
