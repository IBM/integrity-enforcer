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
	profile "github.com/IBM/integrity-enforcer/verifier/pkg/common/profile"
	kubeutil "github.com/IBM/integrity-enforcer/verifier/pkg/util/kubeutil"
	logger "github.com/IBM/integrity-enforcer/verifier/pkg/util/logger"
	config "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/config"
	handlerutil "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/handlerutil"
	loader "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/loader"
	sign "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/sign"
	log "github.com/sirupsen/logrus"
	v1beta1 "k8s.io/api/admission/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

/**********************************************

				RequestHandler

***********************************************/

type RequestHandler struct {
	config *config.VerifierConfig
	ctx    *CheckContext
	loader *loader.Loader
	reqc   *common.ReqContext
}

func NewRequestHandler(config *config.VerifierConfig) *RequestHandler {
	cc := InitCheckContext(config)
	return &RequestHandler{config: config, loader: &loader.Loader{}, ctx: cc}
}

func (self *RequestHandler) Run(req *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {

	reqNamespace := req.Namespace
	//init loader
	self.loader = loader.NewLoader(self.config, reqNamespace)

	// check if reqNamespace matches VerifierConfig.MonitoringNamespace and check if any RSP is targeting the namespace
	// this check is done only for Namespaced request, and skip this for Cluster-scope request
	if reqNamespace != "" && !self.checkIfInScopeNamespace(reqNamespace) && !self.checkIfProfileTargetNamespace(reqNamespace) {
		return createAdmissionResponse(true, "this namespace is not monitored")
	}

	// init ReqContext
	reqc := common.NewReqContext(req)
	self.reqc = reqc

	if self.checkIfDryRunAdmission() {
		return createAdmissionResponse(true, "request is dry run")
	}

	if self.checkIfUnprocessedInIV() {
		return createAdmissionResponse(true, "request is not processed by IV")
	}

	// Start IV world from here ...

	//init logger
	logger.InitSessionLogger(reqc.Namespace,
		reqc.Name,
		reqc.ResourceRef().ApiVersion,
		reqc.Kind,
		reqc.Operation)

	self.logEntry()

	profileReferences := []*v1.ObjectReference{}
	allowed := false
	evalReason := common.REASON_UNEXPECTED

	if ok, msg := self.validateIVCustomResource(); !ok {
		return createAdmissionResponse(false, msg)
	}

	if self.checkIfIVResource() {
		self.ctx.IVResource = true
		if self.checkIfIVAdminRequest() || self.checkIfIVServerRequest() || self.checkIfIVOperatorRequest() {
			allowed = true
			evalReason = common.REASON_IV_ADMIN
		} else {
			self.ctx.Protected = true
		}
	} else {
		forceMatched, forcedProfileRefs := self.checkIfForced()
		if forceMatched {
			self.ctx.Protected = true
			profileReferences = append(profileReferences, forcedProfileRefs...)
		}

		if !forceMatched {
			ignoreMatched, _ := self.checkIfIgnored()
			if ignoreMatched {
				self.ctx.IgnoredSA = true
				allowed = true
				evalReason = common.REASON_IGNORED_SA
			}
		}

		protected := false
		if !self.ctx.Aborted && !allowed {
			tmpProtected, matchedProfileRefs := self.checkIfProtected()
			if tmpProtected {
				protected = true
				profileReferences = append(profileReferences, matchedProfileRefs...)
			}
		}
		if !forceMatched && !protected {
			allowed = true
			evalReason = common.REASON_NOT_PROTECTED
		} else {
			self.ctx.Protected = true
		}
	}

	var errMsg string
	var denyingProfile profile.SigningProfile
	if !self.ctx.Aborted && !self.ctx.IVResource && self.ctx.Protected && !allowed {

		signingProfiles := self.loader.SigningProfile(profileReferences)
		allowCount := 0
		for i, signingProfile := range signingProfiles {

			allowedForThisProfile := false
			var errMsgForThisProfile string
			evalReasonForThisProfile := common.REASON_UNEXPECTED
			var signResultForThisProfile *common.SignatureEvalResult
			var mutationResultForThisProfile *common.MutationEvalResult

			//check signature
			if !self.ctx.Aborted && !allowedForThisProfile {
				if r, err := self.evalSignature(signingProfile); err != nil {
					self.abort("Error when evaluating sign policy", err)
				} else {
					signResultForThisProfile = r
					if r.Checked && r.Allow {
						allowedForThisProfile = true
						evalReasonForThisProfile = common.REASON_VALID_SIG
					}
					if r.Error != nil {
						errMsgForThisProfile = r.Error.MakeMessage()
						if strings.HasPrefix(errMsgForThisProfile, common.ReasonCodeMap[common.REASON_INVALID_SIG].Message) {
							evalReasonForThisProfile = common.REASON_INVALID_SIG
						} else if strings.HasPrefix(errMsgForThisProfile, common.ReasonCodeMap[common.REASON_NO_POLICY].Message) {
							evalReasonForThisProfile = common.REASON_NO_POLICY
						} else if errMsgForThisProfile == common.ReasonCodeMap[common.REASON_NO_SIG].Message {
							evalReasonForThisProfile = common.REASON_NO_SIG
						} else {
							evalReasonForThisProfile = common.REASON_ERROR
						}
					}
				}
			}

			//check mutation
			if !self.ctx.Aborted && !allowedForThisProfile && reqc.IsUpdateRequest() && !self.ctx.IVResource {
				if r, err := self.evalMutation(signingProfile); err != nil {
					self.abort("Error when evaluating mutation", err)
				} else {
					mutationResultForThisProfile = r
					if r.Checked && !r.IsMutated {
						allowedForThisProfile = true
						evalReasonForThisProfile = common.REASON_NO_MUTATION
					}
				}
			}

			if !allowedForThisProfile {
				denyingProfile = signingProfile
				allowed = false
				evalReason = evalReasonForThisProfile
				errMsg = errMsgForThisProfile
				self.ctx.SignatureEvalResult = signResultForThisProfile
				self.ctx.MutationEvalResult = mutationResultForThisProfile
				break
			} else {
				allowCount += 1
			}
			if i == len(signingProfiles)-1 && allowCount == len(signingProfiles) {
				allowed = true
				evalReason = evalReasonForThisProfile
				errMsg = errMsgForThisProfile
				self.ctx.SignatureEvalResult = signResultForThisProfile
				self.ctx.MutationEvalResult = mutationResultForThisProfile
			}
		}

	}

	self.ctx.BreakGlassModeEnabled = self.CheckIfBreakGlassEnabled()
	self.ctx.DetectOnlyModeEnabled = self.CheckIfDetectOnly()

	var dr *DecisionResult
	if self.ctx.IVResource {
		dr = self.evalFinalDecisionForIVResource(allowed, evalReason, errMsg)
	} else {
		dr = self.evalFinalDecision(allowed, evalReason, errMsg)
	}

	self.ctx.Allow = dr.Allow
	self.ctx.Verified = dr.Verified
	self.ctx.ReasonCode = dr.ReasonCode
	self.ctx.Message = dr.Message

	//create admission response
	admissionResponse := createAdmissionResponse(self.ctx.Allow, self.ctx.Message)

	patch := self.createPatch()

	if !reqc.IsDeleteRequest() && len(patch) > 0 {
		admissionResponse.Patch = patch
		admissionResponse.PatchType = func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}()
	}

	// Reload RuleTable only when RSP/namespace request is allowed.
	// however, RSP request by IV server is exception because it is just updating only `status` about denied request.
	if self.ctx.Allow && (self.checkIfProfileResource() && !self.checkIfIVServerRequest() || self.checkIfNamespaceRequest()) {
		err := self.loader.ReloadRuleTable(self.reqc)
		if err != nil {
			logger.Error("Failed to reload RuleTable; ", err)
		}
	}

	if !self.ctx.Allow && !self.ctx.IVResource && denyingProfile != nil {
		err := self.loader.UpdateProfileStatus(denyingProfile, reqc, errMsg)
		if err != nil {
			logger.Error("Failed to update status; ", err)
		}

		err = self.createOrUpdateEvent()
		if err != nil {
			logger.Error("Failed to create an event; ", err)
		}
	}

	//log context
	self.logContext()

	//log exit
	self.logExit()

	return admissionResponse

}

type DecisionResult struct {
	Allow      bool
	Verified   bool
	ReasonCode int
	Message    string
}

func (self *RequestHandler) evalFinalDecision(allowed bool, evalReason int, errMsg string) *DecisionResult {

	dr := &DecisionResult{}

	if self.reqc.IsDeleteRequest() {
		dr.Allow = true
		dr.Verified = true
		dr.ReasonCode = common.REASON_SKIP_DELETE
		dr.Message = common.ReasonCodeMap[common.REASON_SKIP_DELETE].Message
	} else if self.ctx.Aborted {
		dr.Allow = false
		dr.Verified = false
		dr.Message = self.ctx.AbortReason
		dr.ReasonCode = common.REASON_ABORTED
	} else if allowed {
		dr.Allow = true
		dr.Verified = true
		dr.ReasonCode = evalReason
		dr.Message = common.ReasonCodeMap[evalReason].Message
	} else {
		dr.Allow = false
		dr.Verified = false
		dr.Message = errMsg
		dr.ReasonCode = evalReason
	}

	if !dr.Allow && self.ctx.DetectOnlyModeEnabled {
		dr.Allow = true
		dr.Verified = false
		dr.Message = common.ReasonCodeMap[common.REASON_DETECTION].Message
		dr.ReasonCode = common.REASON_DETECTION
	} else if !dr.Allow && self.ctx.BreakGlassModeEnabled {
		dr.Allow = true
		dr.Verified = false
		dr.Message = common.ReasonCodeMap[common.REASON_BREAK_GLASS].Message
		dr.ReasonCode = common.REASON_BREAK_GLASS
	}

	if evalReason == common.REASON_UNEXPECTED {
		dr.ReasonCode = evalReason
	}

	return dr
}

func (self *RequestHandler) evalFinalDecisionForIVResource(allowed bool, evalReason int, errMsg string) *DecisionResult {

	dr := &DecisionResult{}

	if self.ctx.Aborted {
		dr.Allow = false
		dr.Verified = false
		dr.Message = self.ctx.AbortReason
		dr.ReasonCode = common.REASON_ABORTED
	} else if !self.checkIfIVAdminRequest() && !self.checkIfIVServerRequest() && !self.checkIfIVOperatorRequest() {
		dr.Allow = false
		dr.Verified = true
		dr.ReasonCode = common.REASON_BLOCK_IV_RESOURCE_OPERATION
		dr.Message = common.ReasonCodeMap[common.REASON_BLOCK_IV_RESOURCE_OPERATION].Message
	} else if allowed {
		dr.Allow = true
		dr.Verified = true
		dr.ReasonCode = evalReason
		dr.Message = common.ReasonCodeMap[evalReason].Message
	} else {
		dr.Allow = false
		dr.Verified = false
		dr.Message = errMsg
		dr.ReasonCode = evalReason
	}

	if !dr.Allow && self.ctx.DetectOnlyModeEnabled {
		dr.Allow = true
		dr.Verified = false
		dr.Message = common.ReasonCodeMap[common.REASON_DETECTION].Message
		dr.ReasonCode = common.REASON_DETECTION
	}

	if evalReason == common.REASON_UNEXPECTED {
		dr.ReasonCode = evalReason
	}

	return dr
}

func (self *RequestHandler) validateIVCustomResource() (bool, string) {
	if self.reqc.IsDeleteRequest() {
		return true, ""
	}

	if self.reqc.Kind == common.ProfileCustomResourceKind {
		ok, err := handlerutil.ValidateResourceSigningProfile(self.reqc, self.config.Namespace)
		if err != nil {
			return false, fmt.Sprintf("Validation error; %s", err.Error())
		}
		return ok, ""
	}

	if self.reqc.Kind == common.SignatureCustomResourceKind {
		ok, err := handlerutil.ValidateResourceSignature(self.reqc)
		if err != nil {
			return false, fmt.Sprintf("Validation error; %s", err.Error())
		}
		return ok, ""
	}

	return true, ""
}

func createAdmissionResponse(allowed bool, msg string) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Allowed: allowed,
		Result: &metav1.Status{
			Message: msg,
		}}
}

func (self *RequestHandler) logEntry() {
	if self.CheckIfConsoleLogEnabled() {
		sLogger := logger.GetSessionLogger()
		sLogger.Trace("New Admission Request Received")
	}
}

func (self *RequestHandler) logContext() {
	// avoid to log events for IV to update RuleTables
	if self.checkIfIVResource() && self.checkIfIVServerRequest() {
		return
	}
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

func (self *RequestHandler) logExit() {
	if self.CheckIfConsoleLogEnabled() {
		sLogger := logger.GetSessionLogger()
		sLogger.WithFields(log.Fields{
			"allowed": self.ctx.Allow,
			"aborted": self.ctx.Aborted,
		}).Trace("New Admission Request Sent")
	}
}

func (self *RequestHandler) createPatch() []byte {

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

func (self *RequestHandler) evalSignature(signingProfile profile.SigningProfile) (*common.SignatureEvalResult, error) {
	signPolicy := self.loader.GetSignPolicy()
	plugins := self.GetEnabledPlugins()
	if evaluator, err := sign.NewSignatureEvaluator(self.config, signPolicy, plugins); err != nil {
		return nil, err
	} else {
		reqc := self.reqc
		resSigList := self.loader.ResSigList(reqc)
		return evaluator.Eval(reqc, resSigList, signingProfile)
	}
}

func (self *RequestHandler) evalMutation(signingProfile profile.SigningProfile) (*common.MutationEvalResult, error) {
	reqc := self.reqc
	checker := handlerutil.NewMutationChecker()
	return checker.Eval(reqc, signingProfile)
}

func (self *RequestHandler) abort(reason string, err error) {
	self.ctx.Aborted = true
	self.ctx.AbortReason = reason
	self.ctx.Error = err
}

func (self *RequestHandler) checkIfDryRunAdmission() bool {
	return self.reqc.DryRun
}

func (self *RequestHandler) checkIfProfileTargetNamespace(reqNamespace string) bool {
	profileTargetNamespaces := self.loader.ProfileTargetNamespaces()
	if len(profileTargetNamespaces) == 0 {
		return false
	}
	return common.ExactMatchWithPatternArray(reqNamespace, profileTargetNamespaces)
}

func (self *RequestHandler) checkIfInScopeNamespace(reqNamespace string) bool {
	inScopeNSSelector := self.config.InScopeNamespaceSelector
	if inScopeNSSelector == nil {
		return false
	}
	return inScopeNSSelector.MatchNamespace(reqNamespace)
}

func (self *RequestHandler) checkIfUnprocessedInIV() bool {
	reqc := self.reqc
	for _, d := range self.config.Ignore {
		if d.Match(reqc.Map()) {
			return true
		}
	}
	return false
}

func (self *RequestHandler) checkIfIVResource() bool {
	ieResCondition := self.config.IVResourceCondition
	isIVResouce := ieResCondition.Match(self.reqc)
	return isIVResouce
}

func (self *RequestHandler) checkIfProfileResource() bool {
	return self.reqc.Kind == common.ProfileCustomResourceKind
}

func (self *RequestHandler) checkIfNamespaceRequest() bool {
	return self.reqc.Kind == "Namespace"
}

func (self *RequestHandler) checkIfIVAdminRequest() bool {
	if self.config.IVAdminUserGroup == "" {
		return false
	}
	return common.MatchPatternWithArray(self.config.IVAdminUserGroup, self.reqc.UserGroups) //"system:masters"
}

func (self *RequestHandler) checkIfIVServerRequest() bool {
	return common.MatchPattern(self.config.IVServerUserName, self.reqc.UserName) //"service account for integrity-verifier"
}

func (self *RequestHandler) checkIfIVOperatorRequest() bool {
	return common.ExactMatch(self.config.IVResourceCondition.OperatorServiceAccount, self.reqc.UserName) //"service account for integrity-verifier-operator"
}

func (self *RequestHandler) GetEnabledPlugins() map[string]bool {
	return self.config.GetEnabledPlugins()
}

func (self *RequestHandler) checkIfProtected() (bool, []*v1.ObjectReference) {
	reqFields := self.reqc.Map()
	table := self.loader.ProtectRules()
	protected, matchedProfileRefs := table.Match(reqFields, self.config.Namespace)
	return protected, matchedProfileRefs
}

func (self *RequestHandler) checkIfIgnored() (bool, []*v1.ObjectReference) {
	reqFields := self.reqc.Map()
	table := self.loader.IgnoreRules()
	matched, matchedProfileRefs := table.Match(reqFields, self.config.Namespace)
	return matched, matchedProfileRefs
}

func (self *RequestHandler) checkIfForced() (bool, []*v1.ObjectReference) {
	reqFields := self.reqc.Map()
	table := self.loader.ForceCheckRules()
	matched, matchedProfileRefs := table.Match(reqFields, self.config.Namespace)
	return matched, matchedProfileRefs
}

func (self *RequestHandler) CheckIfBreakGlassEnabled() bool {

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

func (self *RequestHandler) CheckIfDetectOnly() bool {
	return (self.config.Mode == config.DetectMode)
}

func (self *RequestHandler) CheckIfConsoleLogEnabled() bool {
	return self.config.Log.ConsoleLog.IsInScope(self.reqc)
}

func (self *RequestHandler) CheckIfContextLogEnabled() bool {
	return self.config.Log.ContextLog.IsInScope(self.reqc)
}

func (self *RequestHandler) createOrUpdateEvent() error {
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	sourceName := "IntegrityVerifier"
	evtName := fmt.Sprintf("iv-deny-%s-%s-%s", strings.ToLower(self.reqc.Operation), strings.ToLower(self.reqc.Kind), self.reqc.Name)
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
