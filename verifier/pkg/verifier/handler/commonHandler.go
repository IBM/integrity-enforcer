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
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	common "github.com/IBM/integrity-enforcer/verifier/pkg/common/common"
	policy "github.com/IBM/integrity-enforcer/verifier/pkg/common/policy"
	kubeutil "github.com/IBM/integrity-enforcer/verifier/pkg/util/kubeutil"
	logger "github.com/IBM/integrity-enforcer/verifier/pkg/util/logger"
	config "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/config"
	handlerutil "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/handlerutil"
	loader "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/loader"
	log "github.com/sirupsen/logrus"
	v1beta1 "k8s.io/api/admission/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

/**********************************************

				commonHandler

***********************************************/

type commonHandler struct {
	config *config.VerifierConfig
	loader *loader.Loader
	ctx    *CheckContext
	reqc   *common.ReqContext
}

func (self *commonHandler) inScopeCheck(req *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {
	reqNamespace := ""
	if req.Kind.Kind != "Namespace" && req.Namespace != "" {
		reqNamespace = req.Namespace
	}

	//init loader
	self.loader = loader.NewLoader(self.config, reqNamespace)

	// check if reqNamespace matches VerifierConfig.MonitoringNamespace and check if any RSP is targeting the namespace
	// this check is done only for Namespaced request, and skip this for Cluster-scope request
	if reqNamespace != "" && !self.checkIfInScopeNamespace(reqNamespace) && !self.checkIfProfileTargetNamespace(reqNamespace) {
		resp := createAdmissionResponse(true, "this namespace is not monitored")
		return resp
	}

	// init ReqContext
	self.reqc = common.NewReqContext(req)

	if self.checkIfDryRunAdmission() {
		resp := createAdmissionResponse(true, "request is dry run")
		return resp
	}

	if self.checkIfUnprocessedInIV() {
		resp := createAdmissionResponse(true, "request is not processed by IV")
		return resp
	}

	return nil
}

func (self *commonHandler) abort(reason string, err error) {
	self.ctx.Aborted = true
	self.ctx.AbortReason = reason
	self.ctx.Error = err
}

func (self *commonHandler) createPatch() []byte {

	var patch []byte
	if self.ctx.Allow {
		labels := map[string]string{}
		deleteKeys := []string{}

		if !self.ctx.Verified {
			labels[common.ResourceIntegrityLabelKey] = common.LabelValueUnverified
			labels[common.ReasonLabelKey] = common.ReasonCodeMap[self.ctx.ReasonCode].Code
		} else if self.ctx.SignatureEvalResult.Allow {
			labels[common.ResourceIntegrityLabelKey] = common.LabelValueVerified
			labels[common.ReasonLabelKey] = common.ReasonCodeMap[self.ctx.ReasonCode].Code
		} else {
			deleteKeys = append(deleteKeys, common.ResourceIntegrityLabelKey)
			deleteKeys = append(deleteKeys, common.ReasonLabelKey)
		}
		name := self.reqc.Name
		reqJson := self.reqc.RequestJsonStr
		if self.config.PatchEnabled() {
			patch = handlerutil.CreatePatch(name, reqJson, labels, deleteKeys)
		}
	}
	return patch
}

func (self *commonHandler) checkIfProfileTargetNamespace(reqNamespace string) bool {
	profileTargetNamespaces := self.loader.ProfileTargetNamespaces()
	if len(profileTargetNamespaces) == 0 {
		return false
	}
	return common.ExactMatchWithPatternArray(reqNamespace, profileTargetNamespaces)
}

func (self *commonHandler) checkIfInScopeNamespace(reqNamespace string) bool {
	inScopeNSSelector := self.config.InScopeNamespaceSelector
	if inScopeNSSelector == nil {
		return false
	}
	return inScopeNSSelector.MatchNamespace(reqNamespace)
}

func (self *commonHandler) checkIfDryRunAdmission() bool {
	return self.reqc.DryRun
}

func (self *commonHandler) checkIfUnprocessedInIV() bool {
	for _, d := range self.config.Ignore {
		if d.Match(self.reqc.Map()) {
			return true
		}
	}
	return false
}

func (self *commonHandler) logEntry() {
	if self.CheckIfConsoleLogEnabled() {
		sLogger := logger.GetSessionLogger()
		sLogger.Trace("New Admission Request Received")
	}
}

func (self *commonHandler) logContext() {
	if self.CheckIfContextLogEnabled() {
		cLogger := logger.GetContextLogger()
		logRecord := self.ctx.convertToLogRecord(self.reqc)
		if self.config.Log.IncludeRequest && !self.reqc.IsSecret() {
			logRecord["request.dump"] = self.reqc.RequestJsonStr
		}
		logBytes, err := json.Marshal(logRecord)
		if err != nil {
			logger.Error(err)
			logBytes = []byte("")
		}
		if self.reqc.ResourceScope == "Namespaced" || (self.reqc.ResourceScope == "Cluster" && self.ctx.Protected) {
			cLogger.SendLog(logBytes)
		}
	}
}

func (self *commonHandler) logExit() {
	if self.CheckIfConsoleLogEnabled() {
		sLogger := logger.GetSessionLogger()
		sLogger.WithFields(log.Fields{
			"allowed": self.ctx.Allow,
			"aborted": self.ctx.Aborted,
		}).Trace("New Admission Request Sent")
	}
}

func (self *commonHandler) logResponse(req *v1beta1.AdmissionRequest, resp *v1beta1.AdmissionResponse) {
	respData := map[string]interface{}{}
	respData["allowed"] = resp.Allowed
	respData["operation"] = req.Operation
	respData["kind"] = req.Kind
	respData["namespace"] = req.Namespace
	respData["name"] = req.Name
	respData["message"] = resp.Result.Message
	respDataBytes, err := json.Marshal(respData)
	if err != nil {
		logger.Error(err.Error())
		return
	}
	logger.Trace(fmt.Sprintf("[AdmissionResponse] %s", string(respDataBytes)))
	return
}

func (self *commonHandler) CheckIfConsoleLogEnabled() bool {
	return self.config.Log.ConsoleLog.IsInScope(self.reqc)
}

func (self *commonHandler) CheckIfContextLogEnabled() bool {
	return self.config.Log.ContextLog.IsInScope(self.reqc)
}

func (self *commonHandler) checkIfProfileResource() bool {
	return self.reqc.Kind == common.ProfileCustomResourceKind
}

func (self *commonHandler) checkIfNamespaceRequest() bool {
	return self.reqc.Kind == "Namespace"
}

func (self *commonHandler) checkIfIVAdminRequest() bool {
	if self.config.IVAdminUserGroup == "" {
		return false
	}
	return common.MatchPatternWithArray(self.config.IVAdminUserGroup, self.reqc.UserGroups) //"system:masters"
}

func (self *commonHandler) checkIfIVServerRequest() bool {
	return common.MatchPattern(self.config.IVServerUserName, self.reqc.UserName) //"service account for integrity-verifier"
}

func (self *commonHandler) checkIfIVOperatorRequest() bool {
	return common.ExactMatch(self.config.IVResourceCondition.OperatorServiceAccount, self.reqc.UserName) //"service account for integrity-verifier-operator"
}

func (self *commonHandler) GetEnabledPlugins() map[string]bool {
	return self.config.GetEnabledPlugins()
}

func (self *commonHandler) checkIfProtected() (bool, []*v1.ObjectReference) {
	reqFields := self.reqc.Map()
	table := self.loader.ProtectRules()
	protected, matchedProfileRefs := table.Match(reqFields, self.config.Namespace)
	return protected, matchedProfileRefs
}

func (self *commonHandler) checkIfIgnored() (bool, []*v1.ObjectReference) {
	reqFields := self.reqc.Map()
	table := self.loader.IgnoreRules()
	matched, matchedProfileRefs := table.Match(reqFields, self.config.Namespace)
	return matched, matchedProfileRefs
}

func (self *commonHandler) checkIfForced() (bool, []*v1.ObjectReference) {
	reqFields := self.reqc.Map()
	table := self.loader.ForceCheckRules()
	matched, matchedProfileRefs := table.Match(reqFields, self.config.Namespace)
	return matched, matchedProfileRefs
}

func (self *commonHandler) CheckIfBreakGlassEnabled() bool {

	conditions := self.loader.BreakGlassConditions()
	breakGlassEnabled := false
	if self.reqc.ResourceScope == "Namespaced" {
		reqNs := self.reqc.Namespace
		for _, d := range conditions {
			if d.Scope == policy.ScopeUndefined || d.Scope == policy.ScopeNamespaced {
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
			if d.Scope == policy.ScopeCluster {
				breakGlassEnabled = true
				break
			}
		}
	}
	return breakGlassEnabled
}

func (self *commonHandler) CheckIfDetectOnly() bool {
	return (self.config.Mode == config.DetectMode)
}

func (self *commonHandler) createOrUpdateEvent() error {
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	resultStr := "deny"
	if self.ctx.Allow {
		resultStr = "allow"
	}

	sourceName := "IntegrityVerifier"
	evtName := fmt.Sprintf("iv-%s-%s-%s-%s", resultStr, strings.ToLower(self.reqc.Operation), strings.ToLower(self.reqc.Kind), self.reqc.Name)
	evtNamespace := self.reqc.Namespace
	involvedObject := v1.ObjectReference{
		Namespace:  self.reqc.Namespace,
		APIVersion: self.reqc.GroupVersion(),
		Kind:       self.reqc.Kind,
		Name:       self.reqc.Name,
	}
	resource := involvedObject.String()

	// report cluster scope object events as event of IV itself
	if self.reqc.ResourceScope == "Cluster" {
		evtNamespace = self.config.Namespace
		involvedObject = v1.ObjectReference{
			Namespace:  self.config.Namespace,
			APIVersion: "apps/v1",
			Kind:       "Deployment",
			Name:       "iv-server",
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

	evt.Message = fmt.Sprintf("%s, Resource: %s", self.ctx.Message, resource)
	evt.Reason = common.ReasonCodeMap[self.ctx.ReasonCode].Code
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
