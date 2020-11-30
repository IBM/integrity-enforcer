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

package loader

import (
	"encoding/json"
	"reflect"
	"strconv"
	"testing"

	rspapi "github.com/IBM/integrity-enforcer/verifier/pkg/apis/resourcesigningprofile/v1alpha1"
	profile "github.com/IBM/integrity-enforcer/verifier/pkg/common/profile"
	"github.com/mohae/deepcopy"
)

const testVerifierNamespace = "test-verifier-ns"

func loadProfileListTestData(profileListBytes []byte) []rspapi.ResourceSigningProfile {
	var profiles rspapi.ResourceSigningProfileList
	_ = json.Unmarshal(profileListBytes, &profiles)
	return profiles.Items
}

func loadTableTestData(tableBytes []byte) *RuleTable {
	var table *RuleTable
	_ = json.Unmarshal(tableBytes, &table)
	return table
}

type RuleTableTestCase struct {
	Profile   *rspapi.ResourceSigningProfileList
	Table     *RuleTable
	ReqDigest ReqDigest
	Protected bool
}

type ReqDigest struct {
	ResourceScope string `json:"ResourceScope,omitempty"`
	Namespace     string `json:"Namespace,omitempty"`
	Name          string `json:"Name,omitempty"`
	ApiGroup      string `json:"ApiGroup,omitempty"`
	ApiVersion    string `json:"ApiVersion,omitempty"`
	Kind          string `json:"Kind,omitempty"`
	Operation     string `json:"Operation,omitempty"`
	UserName      string `json:"UserName,omitempty"`
}

func deepCopyTestInstances(profiles *rspapi.ResourceSigningProfileList, table *RuleTable) (*rspapi.ResourceSigningProfileList, *RuleTable) {
	var tmpProfiles *rspapi.ResourceSigningProfileList
	var tmpTable *RuleTable
	tmpProfilesIf := deepcopy.Copy(profiles)
	tmpProfiles, _ = tmpProfilesIf.(*rspapi.ResourceSigningProfileList)
	tmpTableIf := deepcopy.Copy(table)
	tmpTable, _ = tmpTableIf.(*RuleTable)
	return tmpProfiles, tmpTable
}

func createTestCases(t *testing.T) []RuleTableTestCase {
	var err error

	baseProfileBytes := []byte(`{"apiVersion":"v1","items":[{"apiVersion":"apis.integrityverifier.io/v1alpha1","kind":"ResourceSigningProfile","metadata":{"creationTimestamp":"2020-11-25T04:20:39Z","generation":1,"managedFields":[{"apiVersion":"apis.integrityverifier.io/v1alpha1","fieldsType":"FieldsV1","fieldsV1":{"f:spec":{".":{},"f:protectRules":{}}},"manager":"kubectl-create","operation":"Update","time":"2020-11-25T04:20:39Z"}],"name":"sample-rsp","namespace":"secure-ns","resourceVersion":"2263276","selfLink":"/apis/apis.integrityverifier.io/v1alpha1/namespaces/secure-ns/resourcesigningprofiles/sample-rsp","uid":"4be992d1-b352-495c-80ff-d1b011a23dfc"},"spec":{"protectRules":[{"match":[{"kind":"ConfigMap"}]}]}}],"kind":"List","metadata":{"resourceVersion":"","selfLink":""}}`)
	baseTableBytes := []byte(`[{"rule":{"match":[{"kind":"ConfigMap"}]},"source":{"kind":"ResourceSigningProfile","namespace":"secure-ns","name":"sample-rsp","apiVersion":"apis.integrityverifier.io/v1alpha1"},"namespaces":["secure-ns"]}]`)

	var baseProfiles, tmpProfiles *rspapi.ResourceSigningProfileList
	err = json.Unmarshal(baseProfileBytes, &baseProfiles)
	if err != nil {
		t.Error(err)
	}

	var baseTable, tmpTable *RuleTable
	err = json.Unmarshal(baseTableBytes, &baseTable)
	if err != nil {
		t.Error(err)
	}

	var tmpRuleItem RuleItem

	var reqDgst ReqDigest
	var protected bool

	configmapPattern := profile.RulePattern("ConfigMap")
	deploymentPattern := profile.RulePattern("Deployment")
	clusterRolePattern := profile.RulePattern("ClusterRole")
	testUserNamePattern := profile.RulePattern("test:test-*")
	testClusterRoleNamePattern := profile.RulePattern("tmp-clusterrole")

	cases := []RuleTableTestCase{}

	// case 1
	tmpProfiles, tmpTable = deepCopyTestInstances(baseProfiles, baseTable)
	tmpProfiles.Items[0].Spec.ProtectRules[0].Match[0] = &profile.RequestPattern{Kind: &configmapPattern}
	tmpRuleItem = (*tmpTable)[0]
	tmpRuleItem.Rule = &profile.Rule{Match: []*profile.RequestPattern{{Kind: &configmapPattern}}}
	tmpTable = &RuleTable{tmpRuleItem}
	reqDgst = ReqDigest{ResourceScope: "Namespaced", Namespace: "secure-ns", Name: "tmp-configmap", ApiVersion: "v1", Kind: "ConfigMap", UserName: "test:test-user"}
	protected = true
	cases = append(cases, RuleTableTestCase{Profile: tmpProfiles, Table: tmpTable, ReqDigest: reqDgst, Protected: protected})

	// case 2
	tmpProfiles, tmpTable = deepCopyTestInstances(baseProfiles, baseTable)
	tmpProfiles.Items[0].Spec.ProtectRules[0].Match[0] = &profile.RequestPattern{Kind: &configmapPattern}
	tmpRuleItem = (*tmpTable)[0]
	tmpRuleItem.Rule = &profile.Rule{Match: []*profile.RequestPattern{{Kind: &configmapPattern}}}
	tmpTable = &RuleTable{tmpRuleItem}
	reqDgst = ReqDigest{ResourceScope: "Namespaced", Namespace: "secure-ns", Name: "tmp-deploy", ApiGroup: "apps", ApiVersion: "v1", Kind: "Deployment", UserName: "test:test-user"}
	protected = false
	cases = append(cases, RuleTableTestCase{Profile: tmpProfiles, Table: tmpTable, ReqDigest: reqDgst, Protected: protected})

	// case 3
	tmpProfiles, tmpTable = deepCopyTestInstances(baseProfiles, baseTable)
	tmpProfiles.Items[0].Spec.ProtectRules[0].Match[0] = &profile.RequestPattern{Kind: &deploymentPattern}
	tmpRuleItem = (*tmpTable)[0]
	tmpRuleItem.Rule = &profile.Rule{Match: []*profile.RequestPattern{{Kind: &deploymentPattern}}}
	tmpTable = &RuleTable{tmpRuleItem}
	reqDgst = ReqDigest{ResourceScope: "Namespaced", Namespace: "secure-ns", Name: "tmp-deploy", ApiGroup: "apps", ApiVersion: "v1", Kind: "Deployment", UserName: "test:test-user"}
	protected = true
	cases = append(cases, RuleTableTestCase{Profile: tmpProfiles, Table: tmpTable, ReqDigest: reqDgst, Protected: protected})

	// case 4
	tmpProfiles, tmpTable = deepCopyTestInstances(baseProfiles, baseTable)
	tmpProfiles.Items[0].Spec.ProtectRules[0].Match[0] = &profile.RequestPattern{UserName: &testUserNamePattern}
	tmpRuleItem = (*tmpTable)[0]
	tmpRuleItem.Rule = &profile.Rule{Match: []*profile.RequestPattern{{UserName: &testUserNamePattern}}}
	tmpTable = &RuleTable{tmpRuleItem}
	reqDgst = ReqDigest{ResourceScope: "Namespaced", Namespace: "secure-ns", Name: "tmp-deploy", ApiGroup: "apps", ApiVersion: "v1", Kind: "Deployment", UserName: "test:test-user"}
	protected = true
	cases = append(cases, RuleTableTestCase{Profile: tmpProfiles, Table: tmpTable, ReqDigest: reqDgst, Protected: protected})

	// case 5
	tmpProfiles, tmpTable = deepCopyTestInstances(baseProfiles, baseTable)
	tmpProfiles.Items[0].Spec.ProtectRules[0].Match[0] = &profile.RequestPattern{Kind: &clusterRolePattern}
	tmpRuleItem = (*tmpTable)[0]
	tmpRuleItem.Rule = &profile.Rule{Match: []*profile.RequestPattern{{Kind: &clusterRolePattern}}}
	tmpTable = &RuleTable{tmpRuleItem}
	reqDgst = ReqDigest{ResourceScope: "Cluster", Name: "tmp-clusterrole", ApiGroup: "rbac.authorization.k8s.io", ApiVersion: "v1", Kind: "ClusterRole", UserName: "test:test-cluster-user"}
	protected = false
	cases = append(cases, RuleTableTestCase{Profile: tmpProfiles, Table: tmpTable, ReqDigest: reqDgst, Protected: protected})

	// case 6
	tmpProfiles, tmpTable = deepCopyTestInstances(baseProfiles, baseTable)
	tmpProfiles.Items[0].Spec.ProtectRules[0].Match[0] = &profile.RequestPattern{Kind: &clusterRolePattern, Name: &testClusterRoleNamePattern}
	tmpRuleItem = (*tmpTable)[0]
	tmpRuleItem.Rule = &profile.Rule{Match: []*profile.RequestPattern{{Kind: &clusterRolePattern, Name: &testClusterRoleNamePattern}}}
	tmpTable = &RuleTable{tmpRuleItem}
	reqDgst = ReqDigest{ResourceScope: "Cluster", Name: "tmp-clusterrole", ApiGroup: "rbac.authorization.k8s.io", ApiVersion: "v1", Kind: "ClusterRole", UserName: "test:test-cluster-user"}
	protected = true
	cases = append(cases, RuleTableTestCase{Profile: tmpProfiles, Table: tmpTable, ReqDigest: reqDgst, Protected: protected})

	return cases
}

func singleTestForMakingRuleTable(profiles *rspapi.ResourceSigningProfileList, expectedTable *RuleTable) (bool, *RuleTable, *RuleTable) {
	table := NewRuleTable()
	for _, profile := range profiles.Items {
		tmpTable := NewRuleTableFromProfile(profile, RuleTableTypeProtect, testVerifierNamespace, nil)
		if tmpTable != nil {
			table = table.Merge(tmpTable)
		}
	}
	equal := reflect.DeepEqual(table, expectedTable)
	if !equal {
		return false, table, expectedTable
	}
	return true, table, expectedTable
}

func TestMakingRuleTable(t *testing.T) {
	testCases := createTestCases(t)
	for i, caseData := range testCases {
		profile := caseData.Profile
		expectedTable := caseData.Table

		singleTestOk, actual, expected := singleTestForMakingRuleTable(profile, expectedTable)
		if !singleTestOk {
			expectedBytes, _ := json.Marshal(expected)
			actualBytes, _ := json.Marshal(actual)
			t.Errorf("RuleTable test failed.\nCase %s:\n  expected:\n    %s\nactual:\n    %s", strconv.Itoa(i+1), string(expectedBytes), string(actualBytes))
		}

	}
}

func singleTestForMatchingRequest(table *RuleTable, reqDgst ReqDigest, expected bool) (bool, bool, bool) {
	var reqFields map[string]string
	tmp, _ := json.Marshal(reqDgst)
	_ = json.Unmarshal(tmp, &reqFields)
	actual, _ := table.Match(reqFields, testVerifierNamespace)
	return (actual == expected), actual, expected
}

func TestMatchWithRequest(t *testing.T) {
	testCases := createTestCases(t)
	for i, caseData := range testCases {
		table := caseData.Table
		reqDgst := caseData.ReqDigest
		protected := caseData.Protected

		singleTestOk, actual, expected := singleTestForMatchingRequest(table, reqDgst, protected)
		if !singleTestOk {
			t.Errorf("RuleTable test failed.\nCase %s:\n  expected:\n    %s\n  actual:\n    %s", strconv.Itoa(i+1), strconv.FormatBool(expected), strconv.FormatBool(actual))
		}

	}
}
