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

package enforcer

import (
	"fmt"
	"strings"

	rsig "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/vresourcesignature/v1alpha1"
	"github.com/IBM/integrity-enforcer/enforcer/pkg/config"
	common "github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
	ctlconfig "github.com/IBM/integrity-enforcer/enforcer/pkg/control/config"
	patchutil "github.com/IBM/integrity-enforcer/enforcer/pkg/control/patch"
	sign "github.com/IBM/integrity-enforcer/enforcer/pkg/control/sign"
	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/logger"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/policy"
	"github.com/IBM/integrity-enforcer/enforcer/pkg/protect"
	log "github.com/sirupsen/logrus"
	v1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

/**********************************************

				VCheckContext

***********************************************/

type RequestHandler struct {
	config *config.EnforcerConfig
	ctx    *VCheckContext
	loader *Loader
	reqc   *common.ReqContext
}

func NewRequestHandler(config *config.EnforcerConfig) *RequestHandler {
	cc := InitCheckContext(config)
	return &RequestHandler{config: config, loader: &Loader{Config: config}, ctx: cc}
}

func (self *RequestHandler) Run(req *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {

	// init
	reqc := common.NewReqContext(req)
	self.reqc = reqc

	if self.checkIfDryRunAdmission() {
		return createAdmissionResponse(true, "request is dry run")
	}

	if self.checkIfUnprocessedInIE() {
		return createAdmissionResponse(true, "request is not processed by IE")
	}

	if self.checkIfIEResource() {
		return self.processRequestForIEResource()
	}

	// Start IE world from here ...

	//init loader
	self.initLoader()

	//init logger
	logger.InitSessionLogger(reqc.Namespace,
		reqc.Name,
		reqc.ResourceRef().ApiVersion,
		reqc.Kind,
		reqc.Operation)

	if self.config.Log.IncludeRequest {
		self.ctx.IncludeRequest = true
	}

	if self.config.Log.ConsoleLog.IsInScope(reqc) {
		self.ctx.ConsoleLogEnabled = true
	}

	if self.config.Log.ContextLog.IsInScope(reqc) {
		self.ctx.ContextLogEnabled = true
	}

	self.logEntry()

	requireChk := true

	if ignoredSA, err := self.checkIfIgnoredSA(); err != nil {
		self.abort("Error when checking if ignored service accounts", err)
	} else if ignoredSA {
		self.ctx.IgnoredSA = ignoredSA
		requireChk = false
	}

	if !self.ctx.Aborted && requireChk {
		if protected, err := self.checkIfProtected(); err != nil {
			self.abort("Error when check if the resource is protected", err)
		} else {
			self.ctx.Protected = protected
		}
	}

	allowed := true
	evalReason := common.REASON_UNEXPECTED
	var errMsg string
	if !self.ctx.Aborted && self.ctx.Protected {
		allowed = false

		//init annotation store (singleton)
		annotationStoreInstance = &ConcreteAnnotationStore{}

		//evaluate sign policy
		if !self.ctx.Aborted && !allowed {
			if r, err := self.evalSignPolicy(); err != nil {
				self.abort("Error when evaluating sign policy", err)
			} else {
				self.ctx.Result.SignPolicyEvalResult = r
				if r.Checked && r.Allow {
					allowed = true
					evalReason = common.REASON_VALID_SIG
				}
				if r.Error != nil {
					errMsg = r.Error.MakeMessage()
					if strings.HasPrefix(errMsg, common.ReasonCodeMap[common.REASON_INVALID_SIG].Message) {
						evalReason = common.REASON_INVALID_SIG
					} else if strings.HasPrefix(errMsg, common.ReasonCodeMap[common.REASON_NO_POLICY].Message) {
						evalReason = common.REASON_NO_POLICY
					} else if errMsg == common.ReasonCodeMap[common.REASON_NO_SIG].Message {
						evalReason = common.REASON_NO_SIG
					} else {
						evalReason = common.REASON_ERROR
					}
				}
			}
		}

		//check mutation
		if !self.ctx.Aborted && !allowed && reqc.IsUpdateRequest() {
			if r, err := self.evalMutation(); err != nil {
				self.abort("Error when evaluating mutation", err)
			} else {
				self.ctx.Result.MutationEvalResult = r
				if r.Checked && !r.IsMutated {
					allowed = true
					evalReason = common.REASON_NO_MUTATION
				}
			}
		}
	}

	self.ctx.BreakGlassModeEnabled = self.CheckIfBreakGlassEnabled()
	self.ctx.DetectOnlyModeEnabled = self.CheckIfDetectOnly()

	/********************************************
				Decision Step [3/3]

		input: allowed, evalReason, errMsg (&matchedPolicy)
		output: AdmissionResponse
	********************************************/

	if reqc.IsDeleteRequest() {
		self.ctx.Allow = true
		self.ctx.Verified = true
		self.ctx.ReasonCode = common.REASON_SKIP_DELETE
		self.ctx.Message = common.ReasonCodeMap[common.REASON_SKIP_DELETE].Message
	} else if self.ctx.Aborted {
		self.ctx.Allow = false
		self.ctx.Verified = false
		self.ctx.Message = self.ctx.AbortReason
		self.ctx.ReasonCode = common.REASON_ABORTED
	} else if allowed {
		self.ctx.Allow = true
		self.ctx.Verified = true
		self.ctx.ReasonCode = evalReason
		self.ctx.Message = common.ReasonCodeMap[evalReason].Message
	} else {
		self.ctx.Allow = false
		self.ctx.Verified = false
		self.ctx.Message = errMsg
		self.ctx.ReasonCode = evalReason
	}

	if !self.ctx.Allow && self.ctx.DetectOnlyModeEnabled {
		self.ctx.Allow = true
		self.ctx.Verified = false
		self.ctx.AllowByDetectOnlyMode = true
		self.ctx.Message = common.ReasonCodeMap[common.REASON_DETECTION].Message
		self.ctx.ReasonCode = common.REASON_DETECTION
	} else if !self.ctx.Allow && self.ctx.BreakGlassModeEnabled {
		self.ctx.Allow = true
		self.ctx.Verified = false
		self.ctx.AllowByBreakGlassMode = true
		self.ctx.Message = common.ReasonCodeMap[common.REASON_UNVERIFIED].Message
		self.ctx.ReasonCode = common.REASON_UNVERIFIED
	}

	if evalReason == common.REASON_UNEXPECTED {
		self.ctx.ReasonCode = evalReason
	}

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

	if !self.ctx.Allow {
		self.updateRPP()
	}

	//log context
	self.logContext()

	//log exit
	self.logExit()

	return admissionResponse

}

func createAdmissionResponse(allowed bool, msg string) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Allowed: allowed,
		Result: &metav1.Status{
			Message: msg,
		}}
}

func (self *RequestHandler) logEntry() {
	if self.ctx.ConsoleLogEnabled {
		sLogger := logger.GetSessionLogger()
		sLogger.Trace("New Admission Request Received")
	}
}

func (self *RequestHandler) logContext() {
	if self.ctx.ContextLogEnabled {
		cLogger := logger.GetContextLogger()
		logBytes := self.ctx.convertToLogBytes(self.reqc)
		cLogger.SendLog(logBytes)
	}
}

func (self *RequestHandler) logExit() {
	if self.ctx.ConsoleLogEnabled {
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
		} else if self.ctx.Result.SignPolicyEvalResult.Allow {
			labels[common.ResourceIntegrityLabelKey] = common.LabelValueVerified
			labels[common.ReasonLabelKey] = common.ReasonCodeMap[self.ctx.ReasonCode].Code
		} else {
			deleteKeys = append(deleteKeys, common.ResourceIntegrityLabelKey)
			deleteKeys = append(deleteKeys, common.ReasonLabelKey)
		}
		name := self.reqc.Name
		reqJson := self.reqc.RequestJsonStr
		if self.config.PatchEnabled() {
			patch = patchutil.CreatePatch(name, reqJson, labels, deleteKeys)
		}
	}
	return patch
}

func (self *RequestHandler) evalSignPolicy() (*common.SignPolicyEvalResult, error) {
	signPolicy := self.loader.MergedSignPolicy()
	plugins := self.GetEnabledPlugins()
	if evaluator, err := sign.NewSignPolicyEvaluator(self.config, signPolicy, plugins); err != nil {
		return nil, err
	} else {
		reqc := self.reqc
		resSigList := self.loader.ResSigList(reqc)
		return evaluator.Eval(reqc, resSigList)
	}
}

func (self *RequestHandler) evalMutation() (*common.MutationEvalResult, error) {
	reqc := self.reqc
	owners := []*common.Owner{}
	//ignoreAttrs := self.GetIgnoreAttrs()
	if checker, err := NewMutationChecker(owners); err != nil {
		return nil, err
	} else {
		rules := self.loader.IgnoreAttrsPatterns(reqc.ResourceScope)
		return checker.Eval(reqc, rules)
	}
}

func (self *RequestHandler) abort(reason string, err error) {
	self.ctx.Aborted = true
	self.ctx.AbortReason = reason
	self.ctx.Error = err
}

func (self *RequestHandler) initLoader() {
	enforcerNamespace := self.config.Namespace
	requestNamespace := self.reqc.Namespace
	signatureNamespace := self.config.SignatureNamespace // for cluster scope request
	loader := &Loader{
		Config:            self.config,
		SignPolicy:        ctlconfig.NewSignPolicyLoader(enforcerNamespace),
		RPP:               ctlconfig.NewRPPLoader(enforcerNamespace, requestNamespace),
		CRPP:              ctlconfig.NewCRPPLoader(),
		ResourceSignature: ctlconfig.NewResSigLoader(signatureNamespace, requestNamespace),
	}
	self.loader = loader
}

func (self *RequestHandler) checkIfDryRunAdmission() bool {
	return self.reqc.DryRun
}

func (self *RequestHandler) checkIfUnprocessedInIE() bool {
	reqc := self.reqc
	for _, d := range self.loader.UnprotectedRequestMatchPattern() {
		if d.Match(reqc.Map()) {
			return true
		}
	}
	return false
}

func (self *RequestHandler) checkIfIEResource() bool {
	// TODO: implement
	// with reqc + enforceconfig
	return false
}

func (self *RequestHandler) processRequestForIEResource() *v1beta1.AdmissionResponse {
	// TODO: implement
	// with reqc + enforceconfig
	return nil
}

func (self *RequestHandler) GetEnabledPlugins() map[string]bool {
	return self.config.GetEnabledPlugins()
}

func (self *RequestHandler) checkIfProtected() (bool, error) {
	resourceScope := self.reqc.ResourceScope
	reqFields := self.reqc.Map()
	if resourceScope == "Cluster" || resourceScope == "Namespaced" {
		rules := self.loader.ProtectRules(resourceScope)
		for _, r := range rules {
			if matched := r.MatchWithRequest(reqFields); matched {
				return true, nil
			}
		}
		return false, nil
	} else {
		return false, fmt.Errorf("invalid resource scope")
	}
}

func (self *RequestHandler) checkIfIgnoredSA() (bool, error) {
	reqc := self.reqc
	reqFields := reqc.Map()
	patterns := self.loader.IgnoreServiceAccountPatterns(reqc.ResourceScope)
	ignoredSA := false
	for _, d := range patterns {
		saMatch := false
		for _, sa := range d.ServiceAccountName {
			if reqc.UserName == sa {
				saMatch = true
				break
			}
		}
		if saMatch && d.Match.Match(reqFields) {
			ignoredSA = true
			break
		}
	}
	return ignoredSA, nil
}

func (self *RequestHandler) CheckIfBreakGlassEnabled() bool {
	reqNs := self.reqc.Namespace
	conditions := self.loader.BreakGlassConditions()
	breakGlassEnabled := false
	for _, d := range conditions {
		if d.Scope == policy.ScopeNamespaced {
			for _, ns := range d.Namespaces {
				if reqNs == ns {
					breakGlassEnabled = true
					break
				}
			}
		} else {
			//TODO need implement
			//cluster scope
		}
		if breakGlassEnabled {
			break
		}
	}
	return breakGlassEnabled
}

func (self *RequestHandler) CheckIfDetectOnly() bool {
	return self.loader.DetectOnlyMode()
}

func (self *RequestHandler) updateRPP() error {
	// TODO: implement
	// self.protectRule.Update(self.ReqC.Map(), self.MatchedRPP)
	return nil
}

/**********************************************

				Loader

***********************************************/

type Loader struct {
	Config            *config.EnforcerConfig
	SignPolicy        *ctlconfig.SignPolicyLoader
	RPP               *ctlconfig.RPPLoader
	CRPP              *ctlconfig.CRPPLoader
	ResourceSignature *ctlconfig.ResSigLoader
}

func (self *Loader) UnprotectedRequestMatchPattern() []protect.RequestPattern {
	return self.Config.Ignore
}

func (self *Loader) ProtectRules(resourceScope string) []*protect.Rule {
	rules := []*protect.Rule{}
	if resourceScope == "Namespaced" {
		rpps := self.RPP.GetData()
		for _, d := range rpps {
			rules = append(rules, d.Spec.Rules...)
		}
	} else if resourceScope == "Cluster" {
		rpps := self.CRPP.GetData()
		for _, d := range rpps {
			rules = append(rules, d.Spec.Rules...)
		}
	}
	return rules
}

func (self *Loader) IgnoreServiceAccountPatterns(resourceScope string) []*protect.ServieAccountPattern {
	patterns := []*protect.ServieAccountPattern{}
	if resourceScope == "Namespaced" {
		rpps := self.RPP.GetData()
		for _, d := range rpps {
			patterns = append(patterns, d.Spec.IgnoreServiceAccount...)
		}
	} else if resourceScope == "Cluster" {
		rpps := self.CRPP.GetData()
		for _, d := range rpps {
			patterns = append(patterns, d.Spec.IgnoreServiceAccount...)
		}
	}
	return patterns
}

func (self *Loader) IgnoreAttrsPatterns(resourceScope string) []*protect.AttrsPattern {
	patterns := []*protect.AttrsPattern{}
	if resourceScope == "Namespaced" {
		rpps := self.RPP.GetData()
		for _, d := range rpps {
			patterns = append(patterns, d.Spec.IgnoreAttrs...)
		}
	} else if resourceScope == "Cluster" {
		rpps := self.CRPP.GetData()
		for _, d := range rpps {
			patterns = append(patterns, d.Spec.IgnoreAttrs...)
		}
	}
	return patterns

}

func (self *Loader) BreakGlassConditions() []policy.BreakGlassCondition {
	sp := self.SignPolicy.GetData()
	conditions := []policy.BreakGlassCondition{}
	if sp != nil {
		conditions = append(conditions, sp.Spec.VSignPolicy.BreakGlass...)
	}
	return conditions
}

func (self *Loader) DetectOnlyMode() bool {
	return self.Config.Mode == config.DetectMode
}

func (self *Loader) MergedSignPolicy() *policy.VSignPolicy {
	iepol := self.Config.SignPolicy
	spol := self.SignPolicy.GetData()

	data := &policy.VSignPolicy{}
	data = data.Merge(iepol)
	data = data.Merge(spol.Spec.VSignPolicy)
	return data
}

func (self *Loader) ResSigList(reqc *common.ReqContext) *rsig.VResourceSignatureList {
	items := self.ResourceSignature.GetData()

	return &rsig.VResourceSignatureList{Items: items}
}
