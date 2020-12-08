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

package verifier

import (
	"encoding/json"
	"io/ioutil"
	"reflect"
	"testing"

	rspapi "github.com/IBM/integrity-enforcer/verifier/pkg/apis/resourcesigningprofile/v1alpha1"
	"github.com/IBM/integrity-enforcer/verifier/pkg/common/common"
	"github.com/IBM/integrity-enforcer/verifier/pkg/verifier/config"
)

const (
	testReqcFile   = "testdata/reqc.json"
	testConfigFile = "testdata/config.json"
	testDataFile   = "testdata/data.json"
	testCtxFile    = "testdata/ctx.json"
	testDrFile     = "testdata/dr.json"
	testProf2File  = "testdata/prof2.json"
	testDr2File    = "testdata/dr2.json"
)

func getTestData() (*common.ReqContext, *config.VerifierConfig, *RunData, *CheckContext, *DecisionResult, rspapi.ResourceSigningProfile, *DecisionResult) {
	var reqc *common.ReqContext
	var config *config.VerifierConfig
	var data *RunData
	var ctx *CheckContext
	var dr *DecisionResult
	var prof2 rspapi.ResourceSigningProfile
	var dr2 *DecisionResult
	reqcBytes, _ := ioutil.ReadFile(testReqcFile)
	configBytes, _ := ioutil.ReadFile(testConfigFile)
	dataBytes, _ := ioutil.ReadFile(testDataFile)
	ctxBytes, _ := ioutil.ReadFile(testCtxFile)
	drBytes, _ := ioutil.ReadFile(testDrFile)
	prof2Bytes, _ := ioutil.ReadFile(testProf2File)
	dr2Bytes, _ := ioutil.ReadFile(testDr2File)
	_ = json.Unmarshal(reqcBytes, &reqc)
	_ = json.Unmarshal(configBytes, &config)
	_ = json.Unmarshal(dataBytes, &data)
	_ = json.Unmarshal(ctxBytes, &ctx)
	_ = json.Unmarshal(drBytes, &dr)
	_ = json.Unmarshal(prof2Bytes, &prof2)
	_ = json.Unmarshal(dr2Bytes, &dr2)
	dr = &DecisionResult{
		Type: common.DecisionUndetermined,
	}
	return reqc, config, data, ctx, dr, prof2, dr2
}

func TestInScopeCheck(t *testing.T) {
	reqc, config, data, ctx, expectedDr, _, _ := getTestData()
	actualDr := inScopeCheck(reqc, config, data, ctx)

	if !reflect.DeepEqual(actualDr, expectedDr) {
		actDrBytes, _ := json.Marshal(actualDr)
		expDrBytes, _ := json.Marshal(expectedDr)
		t.Errorf("Test failed for inScopeCheck()\nexpected:\n  %s\nactual:\n  %s", string(actDrBytes), string(expDrBytes))
	} else {
		t.Log("Test for inScopeCheck() passed.")
	}
}

func TestFormatCheck(t *testing.T) {
	reqc, config, data, ctx, expectedDr, _, _ := getTestData()
	actualDr := formatCheck(reqc, config, data, ctx)

	if !reflect.DeepEqual(actualDr, expectedDr) {
		actDrBytes, _ := json.Marshal(actualDr)
		expDrBytes, _ := json.Marshal(expectedDr)
		t.Errorf("Test failed for formatCheck()\nexpected:\n  %s\nactual\n  %s", string(actDrBytes), string(expDrBytes))
	} else {
		t.Log("Test for formatCheck() passed.")
	}
}

func TestIVResourceCheck(t *testing.T) {
	reqc, config, data, ctx, expectedDr, _, _ := getTestData()
	actualDr := ivResourceCheck(reqc, config, data, ctx)

	if !reflect.DeepEqual(actualDr, expectedDr) {
		actDrBytes, _ := json.Marshal(actualDr)
		expDrBytes, _ := json.Marshal(expectedDr)
		t.Errorf("Test failed for ivResourceCheck()\nexpected:\n  %s\nactual:\n  %s", string(actDrBytes), string(expDrBytes))
	} else {
		t.Log("Test for ivResourceCheck() passed.")
	}
}

func TestDeleteCheck(t *testing.T) {
	reqc, config, data, ctx, expectedDr, _, _ := getTestData()
	actualDr := deleteCheck(reqc, config, data, ctx)

	if !reflect.DeepEqual(actualDr, expectedDr) {
		actDrBytes, _ := json.Marshal(actualDr)
		expDrBytes, _ := json.Marshal(expectedDr)
		t.Errorf("Test failed for deleteCheck()\nexpected:\n  %s\nactual:\n  %s", string(actDrBytes), string(expDrBytes))
	} else {
		t.Log("Test for deleteCheck() passed.")
	}
}

func TestProtectedCheck(t *testing.T) {
	reqc, config, data, ctx, expectedDr, expectedMatchedProf, _ := getTestData()
	actualDr, actualMatchedProfiles := protectedCheck(reqc, config, data, ctx)

	if !reflect.DeepEqual(actualDr, expectedDr) {
		actDrBytes, _ := json.Marshal(actualDr)
		expDrBytes, _ := json.Marshal(expectedDr)
		t.Errorf("Test failed for protectedCheck()\nexpected:\n  %s\nactual:\n  %s", string(actDrBytes), string(expDrBytes))
	}
	if len(actualMatchedProfiles) != 1 || !reflect.DeepEqual(actualMatchedProfiles[0], expectedMatchedProf) {
		actProfBytes, _ := json.Marshal(actualMatchedProfiles[0])
		expProfBytes, _ := json.Marshal(expectedMatchedProf)
		t.Errorf("Test failed for protectedCheck()\nexpected :\n  %s\nactual:\n  %s", string(actProfBytes), string(expProfBytes))
	} else {
		t.Log("Test for protectedCheck() passed.")
	}
}

func TestRSPCheck(t *testing.T) {
	reqc, config, data, ctx, _, prof, expectedDr := getTestData()
	actualDr := resourceSigningProfileCheck(prof, reqc, config, data, ctx)
	actualDr.denyRSP = nil // `denyRSP` is an internal-use attribute. this must be ignored for checking equivalent

	if !reflect.DeepEqual(actualDr, expectedDr) {
		actDrBytes, _ := json.Marshal(actualDr)
		expDrBytes, _ := json.Marshal(expectedDr)
		t.Errorf("Test failed for resourceSigningProfileCheck()\nexpected:\n  %s\nactual:\n  %s", string(actDrBytes), string(expDrBytes))
	} else {
		t.Log("Test for resourceSigningProfileCheck() passed.")
	}
}
