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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	rspapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	rspclient "github.com/IBM/integrity-enforcer/shield/pkg/client/resourcesigningprofile/clientset/versioned/typed/resourcesigningprofile/v1alpha1"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"

	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	config "github.com/IBM/integrity-enforcer/shield/pkg/config"
	admv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
)

func createAdmissionResponse(allowed bool, msg string, req *admv1.AdmissionRequest, ctx *common.CheckContext, conf *config.ShieldConfig) *admv1.AdmissionResponse {
	var patchBytes []byte
	if conf.PatchEnabled(req.Kind.Kind, req.Kind.Group) && ctx != nil {
		// `patchBytes` will be nil if no patch
		patchBytes = common.GeneratePatchBytes(req.Name, req.Object.Raw, ctx)
	}
	responseMessage := fmt.Sprintf("%s (Request: %s)", msg, reqToInfo(req))
	resp := &admv1.AdmissionResponse{
		Allowed: allowed,
		Result: &metav1.Status{
			Message: responseMessage,
		},
	}
	if patchBytes != nil {
		patchType := admv1.PatchTypeJSONPatch
		resp.Patch = patchBytes
		resp.PatchType = &patchType
	}
	return resp
}

func reqToInfo(req *admv1.AdmissionRequest) string {
	info := map[string]string{}
	info["group"] = req.Kind.Group
	info["version"] = req.Kind.Version
	info["kind"] = req.Kind.Kind
	info["namespace"] = req.Namespace
	info["name"] = req.Name
	infoBytes, _ := json.Marshal(info)
	return string(infoBytes)
}

func createOrUpdateEvent(req *admv1.AdmissionRequest, dr *common.DecisionResult, sconfig *config.ShieldConfig, denyRSP *rspapi.ResourceSigningProfile) error {
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	resultStr := "deny"
	eventResult := common.EventResultValueDeny
	if dr.IsAllowed() {
		resultStr = "allow"
		eventResult = common.EventResultValueAllow
	}

	sourceName := "IntegrityShield"
	evtName := fmt.Sprintf("ishield-%s-%s-%s-%s", resultStr, strings.ToLower(string(req.Operation)), strings.ToLower(req.Kind.Kind), req.Name)

	gv := schema.GroupVersion{Group: req.Kind.Group, Version: req.Kind.Version}
	evtNamespace := req.Namespace
	involvedObject := v1.ObjectReference{
		Namespace:  req.Namespace,
		APIVersion: gv.String(),
		Kind:       req.Kind.Kind,
		Name:       req.Name,
	}
	if req.Namespace == "" {
		evtNamespace = sconfig.Namespace
		involvedObject = v1.ObjectReference{
			Namespace:  sconfig.Namespace,
			APIVersion: common.IShieldCustomResourceAPIVersion,
			Kind:       common.IShieldCustomResourceKind,
			Name:       sconfig.IShieldCRName,
		}
	}

	now := time.Now()
	evt := &v1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name: evtName,
			Annotations: map[string]string{
				common.EventTypeAnnotationKey:   common.EventTypeValueVerifyResult,
				common.EventResultAnnotationKey: eventResult,
			},
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

	rspInfo := ""
	if denyRSP != nil {
		rspInfo = fmt.Sprintf(" (RSP `namespace: %s, name: %s`)", denyRSP.GetNamespace(), denyRSP.GetName())
	}
	responseMessage := fmt.Sprintf("Result: %s, Reason: \"%s\"%s, Request: %s", resultStr, dr.Message, rspInfo, reqToInfo(req))
	tmpMessage := fmt.Sprintf("[IntegrityShieldEvent] %s", responseMessage)
	// Event.Message can have 1024 chars at most
	if len(tmpMessage) > 1024 {
		tmpMessage = tmpMessage[:950] + " ... Trimmed. `Event.Message` can have 1024 chars at maximum."
	}
	evt.Message = tmpMessage
	evt.Reason = common.ReasonCodeMap[dr.ReasonCode].Code
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

func updateRSPStatus(rsp *rspapi.ResourceSigningProfile, req *admv1.AdmissionRequest, errMsg string) error {
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

	rspName := rsp.GetName()
	rspOrg, err := client.ResourceSigningProfiles().Get(context.Background(), rspName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	cmreq := common.NewRequestFromAdmissionRequest(req)
	rspNew := rspOrg.UpdateStatus(cmreq, errMsg)

	_, err = client.ResourceSigningProfiles().Update(context.Background(), rspNew, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func checkIfDryRunAdmission(reqc *common.RequestContext) bool {
	return reqc.DryRun
}

func checkIfUnprocessedInIShield(reqFeilds map[string]string, config *config.ShieldConfig) bool {
	for _, d := range config.Ignore {
		if d.Match(reqFeilds) {
			return true
		}
	}
	return false
}

func checkIfIShieldServerRequest(username string, sconfig *config.ShieldConfig) bool {
	return common.MatchPattern(sconfig.IShieldServerUserName, username) //"service account for integrity-shield"
}

func checkIfIShieldOperatorRequest(username string, sconfig *config.ShieldConfig) bool {
	return common.ExactMatch(sconfig.IShieldResourceCondition.OperatorServiceAccount, username) //"service account for integrity-shield-operator"
}

func getRequestNamespace(req *admv1.AdmissionRequest) string {
	reqNamespace := ""
	if req.Kind.Kind != "Namespace" && req.Namespace != "" {
		reqNamespace = req.Namespace
	}
	return reqNamespace
}

func getRequestNamespaceFromRequestContext(reqc *common.RequestContext) string {
	reqNamespace := ""
	if reqc.Kind != "Namespace" && reqc.Namespace != "" {
		reqNamespace = reqc.Namespace
	}
	return reqNamespace
}

func getRequestNamespaceFromResourceContext(resc *common.ResourceContext) string {
	reqNamespace := ""
	if resc.Kind != "Namespace" && resc.Namespace != "" {
		reqNamespace = resc.Namespace
	}
	return reqNamespace
}

func checkIfIShieldAdminRequest(username string, usergroups []string, sconfig *config.ShieldConfig) bool {
	groupMatched := false
	if sconfig.IShieldAdminUserGroup != "" {
		groupMatched = common.MatchPatternWithArray(sconfig.IShieldAdminUserGroup, usergroups)
	}
	userMatched := false
	if sconfig.IShieldAdminUserName != "" {
		userMatched = common.MatchPattern(sconfig.IShieldAdminUserName, username)
	}
	// TODO: delete this block after OLM SA will be added to `config.IShieldAdminUserName` in CR
	if common.MatchPattern("system:serviceaccount:openshift-operator-lifecycle-manager:olm-operator-serviceaccount", username) {
		userMatched = true
	}
	isAdmin := (groupMatched || userMatched)
	return isAdmin
}

func checkIfGarbageCollectorRequest(username string) bool {
	// TODO: should be configurable?
	return username == "system:serviceaccount:kube-system:generic-garbage-collector"
}

func checkIfSpecialServiceAccountRequest(username string) bool {
	// TODO: should be configurable?
	if strings.HasPrefix(username, "system:serviceaccount:kube-") {
		return true
	} else if strings.HasPrefix(username, "system:serviceaccount:openshift-") {
		return true
	} else if strings.HasPrefix(username, "system:serviceaccount:openshift:") {
		return true
	} else if strings.HasPrefix(username, "system:serviceaccount:open-cluster-") {
		return true
	} else if strings.HasPrefix(username, "system:serviceaccount:olm:") {
		return true
	}

	return false
}
