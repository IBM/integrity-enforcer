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

package shield

import (
	"context"
	"encoding/json"
	"fmt"

	rspapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	rspclient "github.com/IBM/integrity-enforcer/shield/pkg/client/resourcesigningprofile/clientset/versioned/typed/resourcesigningprofile/v1alpha1"
	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	kubeutil "github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
	gkmatch "github.com/open-policy-agent/gatekeeper/apis/mutations/v1alpha1"
	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func AdmissionRequestToReqFields(req *admv1.AdmissionRequest) map[string]string {
	reqFields := map[string]string{}
	scope := "Namespaced"
	if req.Namespace == "" {
		scope = "Cluster"
	}
	reqFields["ResourceScope"] = scope
	reqFields["Namespace"] = req.Namespace
	reqFields["ApiGroup"] = req.Kind.Group
	reqFields["ApiVersion"] = req.Kind.Version
	reqFields["Kind"] = req.Kind.Kind
	reqFields["Name"] = req.Name
	reqFields["Operation"] = string(req.Operation)
	reqFields["UserName"] = req.UserInfo.Username

	return reqFields
}

func ResourceToReqFields(res *unstructured.Unstructured) map[string]string {
	reqFields := map[string]string{}
	scope := "Namespaced"
	if res.GetNamespace() == "" {
		scope = "Cluster"
	}
	apiVer := res.GetAPIVersion()
	gv, _ := schema.ParseGroupVersion(apiVer)
	reqFields["ResourceScope"] = scope
	reqFields["Namespace"] = res.GetNamespace()
	reqFields["ApiGroup"] = gv.Group
	reqFields["ApiVersion"] = gv.Version
	reqFields["Kind"] = res.GetKind()
	reqFields["Name"] = res.GetName()

	return reqFields
}

func GetMatchedProfilesWithRequest(req *admv1.AdmissionRequest, ishieldNS string) ([]rspapi.ResourceSigningProfile, error) {
	rspList, err := ListProfiles()
	if err != nil {
		return nil, err
	}
	reqFeilds := AdmissionRequestToReqFields(req)
	matchedProfiles := []rspapi.ResourceSigningProfile{}
	for _, rsp := range rspList {
		if matched, _ := rsp.Match(reqFeilds); matched {
			matchedProfiles = append(matchedProfiles, rsp)
		}
	}
	return matchedProfiles, nil
}

func GetMatchedProfilesWithResource(res *unstructured.Unstructured, ishieldNS string) ([]rspapi.ResourceSigningProfile, error) {
	rspList, err := ListProfiles()
	if err != nil {
		return nil, err
	}
	reqFeilds := ResourceToReqFields(res)
	matchedProfiles := []rspapi.ResourceSigningProfile{}
	for _, rsp := range rspList {
		if matched, _ := rsp.Match(reqFeilds); matched {
			matchedProfiles = append(matchedProfiles, rsp)
		}
	}
	return matchedProfiles, nil
}

func GetMatchedGeneralProfilesWithResource(res *unstructured.Unstructured, ishieldNS string) ([]rspapi.ResourceSigningProfile, error) {
	matchedRSPs, err := GetMatchedProfilesWithResource(res, ishieldNS)
	if err == nil && len(matchedRSPs) > 0 {
		return matchedRSPs, nil
	} else {
		// try get matching profiles of gatekeeper constraint
		allProfiles, err := ListProfilesOfConstraints()
		if err != nil {
			return nil, err
		}
		reqFeilds := ResourceToReqFields(res)
		resname := res.GetName()
		matchedProfiles := []rspapi.ResourceSigningProfile{}
		for _, rsp := range allProfiles {
			matched := false
			// a constraint without any match rules is understood as a matched profile by gatekeeper
			if len(rsp.Spec.Match.ProtectRules) == 0 {
				matched = true
			} else {
				tmpMatched, _ := rsp.Match(reqFeilds)
				if tmpMatched {
					matched = true
				}
			}
			if matched {
				matchedProfiles = append(matchedProfiles, rsp)
			}
			fmt.Println("[DEBUG] resname:", resname, "check profile matching: ", rsp.GetName(), ", ", matched)
		}
		matchedProfilesBytes, _ := json.Marshal(matchedProfiles)
		fmt.Println("[DEBUG] resname:", resname, "matched profiles: ", string(matchedProfilesBytes))
		return matchedProfiles, nil
	}
}

func ListProfiles() ([]rspapi.ResourceSigningProfile, error) {
	cfg, err := kubeutil.GetKubeConfig()
	if err != nil {
		return nil, err
	}
	rspClient, err := rspclient.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	rspList, err := rspClient.ResourceSigningProfiles().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return rspList.Items, nil
}

func constraintToResourceSigningProfile(constraint *unstructured.Unstructured) rspapi.ResourceSigningProfile {
	constraintName := constraint.GetName()
	var rsp rspapi.ResourceSigningProfile
	constBytes, _ := json.Marshal(constraint)
	var tmp map[string]interface{}
	_ = json.Unmarshal(constBytes, &tmp)
	specIf := tmp["spec"]
	rspParameters := rspapi.Parameters{}
	rspMatchCondition := rspapi.MatchCondition{}
	if specMap, ok := specIf.(map[string]interface{}); ok {
		matchIf := specMap["match"]
		matchBytes, _ := json.Marshal(matchIf)
		var gkMatch gkmatch.Match
		_ = json.Unmarshal(matchBytes, &gkMatch)

		nsSelector := &common.NamespaceSelector{
			Include:       gkMatch.Namespaces,
			Exclude:       gkMatch.ExcludedNamespaces,
			LabelSelector: gkMatch.NamespaceSelector,
		}
		protectRules := []*common.Rule{}
		for _, m := range gkMatch.Kinds {
			for _, kind := range m.Kinds {
				rulePattern := common.RulePattern(kind)
				protectRules = append(protectRules, &common.Rule{
					Match: []*common.RequestPatternWithNamespace{
						{
							RequestPattern: &common.RequestPattern{
								Kind: &rulePattern,
							},
						},
					},
				})
			}
		}
		rspMatchCondition.TargetNamespaceSelector = nsSelector
		rspMatchCondition.ProtectRules = protectRules

		parametersIf := specMap["parameters"]
		parametersBytes, _ := json.Marshal(parametersIf)
		var parameters rspapi.Parameters
		_ = json.Unmarshal(parametersBytes, &parameters)
		rspParameters = parameters
	}
	specBytes, _ := json.Marshal(specIf)
	var rspSpec rspapi.ResourceSigningProfileSpec
	_ = json.Unmarshal(specBytes, &rspSpec)
	rsp = rspapi.ResourceSigningProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: constraintName,
		},
		Spec: rspapi.ResourceSigningProfileSpec{
			Match:      rspMatchCondition,
			Parameters: rspParameters,
		},
	}
	return rsp
}

func ListProfilesOfConstraints() ([]rspapi.ResourceSigningProfile, error) {
	constraints, err := kubeutil.ListResources("constraints.gatekeeper.sh/v1beta1", "IntegrityShieldCheck", "")
	if err != nil {
		return nil, err
	}
	rsps := []rspapi.ResourceSigningProfile{}
	for _, constraint := range constraints {
		rsp := constraintToResourceSigningProfile(constraint)
		rsps = append(rsps, rsp)
	}

	return rsps, nil
}

func SummarizeMultipleAdmissionResponses(multiResps []*admv1.AdmissionResponse) (*admv1.AdmissionResponse, int) {
	allow := true
	msg := ""
	lastDenyMsg := ""
	index := -1
	lastDenyIndex := -1
	for i, resp := range multiResps {
		if !resp.Allowed {
			allow = false
			lastDenyMsg = multiResps[i].Result.Message
			lastDenyIndex = i
		}
		msg = resp.Result.Message
		index = i
	}
	if !allow {
		msg = lastDenyMsg
		index = lastDenyIndex
	}
	return &admv1.AdmissionResponse{
		Allowed: allow,
		Result: &metav1.Status{
			Message: msg,
		},
	}, index
}

func SummarizeMultipleDecisionResults(multiResults []*common.DecisionResult) (*common.DecisionResult, int) {

	lastAllowDR := common.UndeterminedDecision()
	lastDenyDR := common.UndeterminedDecision()
	lastAllowIndex := -1
	lastDenyIndex := -1
	for i, result := range multiResults {
		if result.IsAllowed() {
			lastAllowDR = multiResults[i]
			lastAllowIndex = i
		} else if result.IsDenied() {
			lastDenyDR = multiResults[i]
			lastDenyIndex = i
		}
	}
	if lastDenyDR.IsDenied() {
		return lastDenyDR, lastDenyIndex
	}
	if lastAllowDR.IsAllowed() {
		return lastAllowDR, lastAllowIndex
	}
	return common.UndeterminedDecision(), -1
}
