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

	rspapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	rspclient "github.com/IBM/integrity-enforcer/shield/pkg/client/resourcesigningprofile/clientset/versioned/typed/resourcesigningprofile/v1alpha1"
	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	kubeutil "github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
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
		if matched, _ := rsp.Match(reqFeilds, ishieldNS); matched {
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
		if matched, _ := rsp.Match(reqFeilds, ishieldNS); matched {
			matchedProfiles = append(matchedProfiles, rsp)
		}
	}
	return matchedProfiles, nil
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
	rspList, err := rspClient.ResourceSigningProfiles("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return rspList.Items, nil
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
