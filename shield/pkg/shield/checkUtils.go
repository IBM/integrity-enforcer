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
	"fmt"
	"strings"
	"time"

	rspapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	sigconfapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/signerconfig/v1alpha1"
	rspclient "github.com/IBM/integrity-enforcer/shield/pkg/client/resourcesigningprofile/clientset/versioned/typed/resourcesigningprofile/v1alpha1"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"

	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	config "github.com/IBM/integrity-enforcer/shield/pkg/shield/config"
	v1beta1 "k8s.io/api/admission/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func createAdmissionResponse(allowed bool, msg string) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Allowed: allowed,
		Result: &metav1.Status{
			Message: msg,
		},
	}
}

func createOrUpdateEvent(reqc *common.ReqContext, ctx *CheckContext, shieldNamespace string) error {
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	resultStr := "deny"
	if ctx.Allow {
		resultStr = "allow"
	}

	sourceName := "IntegrityShield"
	evtName := fmt.Sprintf("ishield-%s-%s-%s-%s", resultStr, strings.ToLower(reqc.Operation), strings.ToLower(reqc.Kind), reqc.Name)
	evtNamespace := reqc.Namespace
	involvedObject := v1.ObjectReference{
		Namespace:  reqc.Namespace,
		APIVersion: reqc.GroupVersion(),
		Kind:       reqc.Kind,
		Name:       reqc.Name,
	}
	resource := involvedObject.String()

	// report cluster scope object events as event of IShield itself
	if reqc.ResourceScope == "Cluster" {
		evtNamespace = shieldNamespace
		involvedObject = v1.ObjectReference{
			Namespace:  shieldNamespace,
			APIVersion: "apps/v1",
			Kind:       "Deployment",
			Name:       "ishield-server",
		}
	}

	now := time.Now()
	evt := &v1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name: evtName,
		},
		InvolvedObject:      involvedObject,
		Type:                sourceName,
		Source:              v1.EventSource{Component: sourceName},
		ReportingController: sourceName,
		ReportingInstance:   evtName,
		Action:              evtName,
		FirstTimestamp:      metav1.NewTime(now),
	}
	isExistingEvent := false
	current, getErr := client.CoreV1().Events(evtNamespace).Get(context.Background(), evtName, metav1.GetOptions{})
	if current != nil && getErr == nil {
		isExistingEvent = true
		evt = current
	}

	evt.Message = fmt.Sprintf("%s, Resource: %s", ctx.Message, resource)
	evt.Reason = common.ReasonCodeMap[ctx.ReasonCode].Code
	evt.Count = evt.Count + 1
	evt.EventTime = metav1.NewMicroTime(now)
	evt.LastTimestamp = metav1.NewTime(now)

	if isExistingEvent {
		_, err = client.CoreV1().Events(evtNamespace).Update(context.Background(), evt, metav1.UpdateOptions{})
	} else {
		_, err = client.CoreV1().Events(evtNamespace).Create(context.Background(), evt, metav1.CreateOptions{})
	}
	if err != nil {
		return err
	}
	return nil
}

func updateRSPStatus(rsp *rspapi.ResourceSigningProfile, reqc *common.ReqContext, errMsg string) error {
	if rsp == nil {
		return nil
	}

	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return err
	}
	client, err := rspclient.NewForConfig(config)
	if err != nil {
		return err
	}

	rspNamespace := rsp.GetNamespace()
	rspName := rsp.GetName()
	rspOrg, err := client.ResourceSigningProfiles(rspNamespace).Get(context.Background(), rspName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	req := common.NewRequestFromReqContext(reqc)
	rspNew := rspOrg.UpdateStatus(req, errMsg)

	_, err = client.ResourceSigningProfiles(rspNamespace).Update(context.Background(), rspNew, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func checkIfProfileTargetNamespace(reqNamespace, shieldNamespace string, data *RunData) bool {
	ruleTable := data.GetRuleTable(shieldNamespace)
	if ruleTable == nil {
		return false
	}
	return ruleTable.CheckIfTargetNamespace(reqNamespace)
}

func checkIfInScopeNamespace(reqNamespace string, config *config.ShieldConfig) bool {
	inScopeNSSelector := config.InScopeNamespaceSelector
	if inScopeNSSelector == nil {
		return false
	}
	return inScopeNSSelector.MatchNamespaceName(reqNamespace)
}

func checkIfDryRunAdmission(reqc *common.ReqContext) bool {
	return reqc.DryRun
}

func checkIfUnprocessedInIShield(reqc *common.ReqContext, config *config.ShieldConfig) bool {
	for _, d := range config.Ignore {
		if d.Match(reqc.Map()) {
			return true
		}
	}
	return false
}

func getRequestNamespace(req *v1beta1.AdmissionRequest) string {
	reqNamespace := ""
	if req.Kind.Kind != "Namespace" && req.Namespace != "" {
		reqNamespace = req.Namespace
	}
	return reqNamespace
}

func getRequestNamespaceFromReqContext(reqc *common.ReqContext) string {
	reqNamespace := ""
	if reqc.Kind != "Namespace" && reqc.Namespace != "" {
		reqNamespace = reqc.Namespace
	}
	return reqNamespace
}

func checkIfIShieldAdminRequest(reqc *common.ReqContext, config *config.ShieldConfig) bool {
	groupMatched := false
	if config.IShieldAdminUserGroup != "" {
		groupMatched = common.MatchPatternWithArray(config.IShieldAdminUserGroup, reqc.UserGroups)
	}
	userMatched := false
	if config.IShieldAdminUserName != "" {
		userMatched = common.MatchPattern(config.IShieldAdminUserName, reqc.UserName)
	}
	isAdmin := (groupMatched || userMatched)
	return isAdmin
}

func checkIfIShieldServerRequest(reqc *common.ReqContext, config *config.ShieldConfig) bool {
	return common.MatchPattern(config.IShieldServerUserName, reqc.UserName) //"service account for integrity-shield"
}

func checkIfIShieldOperatorRequest(reqc *common.ReqContext, config *config.ShieldConfig) bool {
	return common.ExactMatch(config.IShieldResourceCondition.OperatorServiceAccount, reqc.UserName) //"service account for integrity-shield-operator"
}

func getBreakGlassConditions(signerConfig *sigconfapi.SignerConfig) []common.BreakGlassCondition {
	conditions := []common.BreakGlassCondition{}
	if signerConfig != nil {
		conditions = append(conditions, signerConfig.Spec.Config.BreakGlass...)
	}
	return conditions
}

func checkIfBreakGlassEnabled(reqc *common.ReqContext, signerConfig *sigconfapi.SignerConfig) bool {

	conditions := getBreakGlassConditions(signerConfig)
	breakGlassEnabled := false
	if reqc.ResourceScope == "Namespaced" {
		reqNs := reqc.Namespace
		for _, d := range conditions {
			if d.Scope == common.ScopeUndefined || d.Scope == common.ScopeNamespaced {
				for _, ns := range d.Namespaces {
					if reqNs == ns {
						breakGlassEnabled = true
						break
					}
				}
			}
			if breakGlassEnabled {
				break
			}
		}
	} else {
		for _, d := range conditions {
			if d.Scope == common.ScopeCluster {
				breakGlassEnabled = true
				break
			}
		}
	}
	return breakGlassEnabled
}

func checkIfDetectOnly(sconf *config.ShieldConfig) bool {
	return (sconf.Mode == config.DetectMode)
}
