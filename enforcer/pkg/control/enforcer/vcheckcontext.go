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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

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

				CheckResult

***********************************************/

type CheckResult struct {
	SignPolicyEvalResult *common.SignPolicyEvalResult `json:"signpolicy"`
	ResolveOwnerResult   *common.ResolveOwnerResult   `json:"owner"`
	MutationEvalResult   *common.MutationEvalResult   `json:"mutation"`
}

/**********************************************

				VCheckContext

***********************************************/

type VCheckContext struct {
	ResourceScope string `json:"resourceScope,omitempty"`

	config *config.EnforcerConfig
	Loader *Loader

	// request context
	ReqC *common.ReqContext `json:"-"`

	DetectOnlyModeEnabled bool `json:"detectOnly"`
	BreakGlassModeEnabled bool `json:"breakGlass"`

	Result *CheckResult `json:"result"`

	DryRun      bool   `json:"dryRun"`
	Unprocessed bool   `json:"unprocessed"`
	IgnoredSA   bool   `json:"ignoredSA"`
	Protected   bool   `json:"protected"`
	Allow       bool   `json:"allow"`
	Verified    bool   `json:"verified"`
	Aborted     bool   `json:"aborted"`
	AbortReason string `json:"abortReason"`
	Error       error  `json:"error"`
	Message     string `json:"msg"`

	ConsoleLogEnabled bool `json:"-"`
	ContextLogEnabled bool `json:"-"`

	ReasonCode int `json:"reasonCode"`

	AllowByBreakGlassMode bool `json:"allowByBreakGlassMode"`
	AllowByDetectOnlyMode bool `json:"allowByDetectOnlyMode"`
}

type VCheckResult struct {
	SignPolicyEvalResult *common.SignPolicyEvalResult `json:"signpolicy"`
	ResolveOwnerResult   *common.ResolveOwnerResult   `json:"owner"`
	MutationEvalResult   *common.MutationEvalResult   `json:"mutation"`
}

func NewVCheckContext(config *config.EnforcerConfig) *VCheckContext {
	cc := &VCheckContext{
		config: config,
		Loader: nil,

		IgnoredSA: false,
		Protected: false,
		Aborted:   false,
		Allow:     false,
		Verified:  false,
		Result: &CheckResult{
			SignPolicyEvalResult: &common.SignPolicyEvalResult{
				Allow:   false,
				Checked: false,
			},
			ResolveOwnerResult: &common.ResolveOwnerResult{
				Owners:  &common.OwnerList{},
				Checked: false,
			},
			MutationEvalResult: &common.MutationEvalResult{
				IsMutated: false,
				Checked:   false,
			},
		},
	}
	return cc
}

func (self *VCheckContext) ProcessRequest(req *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {

	// init
	reqc := common.NewReqContext(req)
	self.ReqC = reqc
	if reqc.Namespace == "" {
		self.ResourceScope = "Cluster"
	} else {
		self.ResourceScope = "Namespaced"
	}

	self.DryRun = self.checkIfDryRunAdmission()

	if self.DryRun {
		return createAdmissionResponse(true, "request is dry run")
	}

	self.Unprocessed = self.checkIfUnprocessedInIE()
	if self.Unprocessed {
		return createAdmissionResponse(true, "request is not processed by IE")
	}

	if self.checkIfIEResource() {
		return self.processRequestForIEResource()
	}

	// Start IE world from here ...

	//init loader
	self.initLoader()

	//init logger
	logger.InitSessionLogger(self.ReqC.Namespace,
		self.ReqC.Name,
		self.ReqC.ResourceRef().ApiVersion,
		self.ReqC.Kind,
		self.ReqC.Operation)

	if self.config.Log.ConsoleLog.IsInScope(self.ReqC) {
		self.ConsoleLogEnabled = true
	}

	if self.config.Log.ContextLog.IsInScope(self.ReqC) {
		self.ContextLogEnabled = true
	}

	self.logEntry()

	requireChk := true

	if ignoredSA, err := self.checkIfIgnoredSA(); err != nil {
		self.abort("Error when checking if ignored service accounts", err)
	} else if ignoredSA {
		self.IgnoredSA = ignoredSA
		requireChk = false
	}

	if !self.Aborted && requireChk {
		if protected, err := self.checkIfProtected(); err != nil {
			self.abort("Error when check if the resource is protected", err)
		} else {
			self.Protected = protected
		}
	}

	allowed := true
	evalReason := common.REASON_UNEXPECTED
	var errMsg string
	if !self.Aborted && self.Protected {
		allowed = false

		//init annotation store (singleton)
		annotationStoreInstance = &ConcreteAnnotationStore{}

		//evaluate sign policy
		if !self.Aborted && !allowed {
			if r, err := self.evalSignPolicy(); err != nil {
				self.abort("Error when evaluating sign policy", err)
			} else {
				self.Result.SignPolicyEvalResult = r
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
		if !self.Aborted && !allowed && self.ReqC.IsUpdateRequest() {
			if r, err := self.evalMutation(); err != nil {
				self.abort("Error when evaluating mutation", err)
			} else {
				self.Result.MutationEvalResult = r
				if r.Checked && !r.IsMutated {
					allowed = true
					evalReason = common.REASON_NO_MUTATION
				}
			}
		}
	}

	self.BreakGlassModeEnabled = self.CheckIfBreakGlassEnabled()
	self.DetectOnlyModeEnabled = self.CheckIfDetectOnly()

	/********************************************
				Decision Step [3/3]

		input: allowed, evalReason, errMsg (&matchedPolicy)
		output: AdmissionResponse
	********************************************/

	if self.ReqC.IsDeleteRequest() {
		self.Allow = true
		self.Verified = true
		self.ReasonCode = common.REASON_SKIP_DELETE
		self.Message = common.ReasonCodeMap[common.REASON_SKIP_DELETE].Message
	} else if self.Aborted {
		self.Allow = false
		self.Verified = false
		self.Message = self.AbortReason
		self.ReasonCode = common.REASON_ABORTED
	} else if allowed {
		self.Allow = true
		self.Verified = true
		self.ReasonCode = evalReason
		self.Message = common.ReasonCodeMap[evalReason].Message
	} else {
		self.Allow = false
		self.Verified = false
		self.Message = errMsg
		self.ReasonCode = evalReason
	}

	if !self.Allow && self.DetectOnlyModeEnabled {
		self.Allow = true
		self.Verified = false
		self.AllowByDetectOnlyMode = true
		self.Message = common.ReasonCodeMap[common.REASON_DETECTION].Message
		self.ReasonCode = common.REASON_DETECTION
	} else if !self.Allow && self.BreakGlassModeEnabled {
		self.Allow = true
		self.Verified = false
		self.AllowByBreakGlassMode = true
		self.Message = common.ReasonCodeMap[common.REASON_UNVERIFIED].Message
		self.ReasonCode = common.REASON_UNVERIFIED
	}

	if evalReason == common.REASON_UNEXPECTED {
		self.ReasonCode = evalReason
	}

	//create admission response
	admissionResponse := createAdmissionResponse(self.Allow, self.Message)

	patch := self.createPatch()

	if !self.ReqC.IsDeleteRequest() && len(patch) > 0 {
		admissionResponse.Patch = patch
		admissionResponse.PatchType = func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}()
	}

	if !self.Allow {
		self.updateRPP()
	}

	//log context
	self.logContext()

	//log exit
	self.logExit()

	return admissionResponse

}

func (self *VCheckContext) logEntry() {
	if self.ConsoleLogEnabled {
		sLogger := logger.GetSessionLogger()
		sLogger.Trace("New Admission Request Received")
	}
}

func (self *VCheckContext) logContext() {
	if self.ContextLogEnabled {
		cLogger := logger.GetContextLogger()
		logBytes := self.convertToLogBytes()
		cLogger.SendLog(logBytes)
	}
}

func (self *VCheckContext) logExit() {
	if self.ConsoleLogEnabled {
		sLogger := logger.GetSessionLogger()
		sLogger.WithFields(log.Fields{
			"allowed": self.Allow,
			"aborted": self.Aborted,
		}).Trace("New Admission Request Sent")
	}
}

func createAdmissionResponse(allowed bool, msg string) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Allowed: allowed,
		Result: &metav1.Status{
			Message: msg,
		}}
}

func (self *VCheckContext) createPatch() []byte {

	var patch []byte
	if self.Allow {
		labels := map[string]string{}
		deleteKeys := []string{}

		if !self.Verified {
			labels[common.ResourceIntegrityLabelKey] = common.LabelValueUnverified
			labels[common.ReasonLabelKey] = common.ReasonCodeMap[self.ReasonCode].Code
		} else if self.Result.SignPolicyEvalResult.Allow {
			labels[common.ResourceIntegrityLabelKey] = common.LabelValueVerified
			labels[common.ReasonLabelKey] = common.ReasonCodeMap[self.ReasonCode].Code
		} else {
			deleteKeys = append(deleteKeys, common.ResourceIntegrityLabelKey)
			deleteKeys = append(deleteKeys, common.ReasonLabelKey)
		}
		name := self.ReqC.Name
		reqJson := self.ReqC.RequestJsonStr
		if self.config.PatchEnabled() {
			patch = patchutil.CreatePatch(name, reqJson, labels, deleteKeys)
		}
	}
	return patch
}

func (self *VCheckContext) evalSignPolicy() (*common.SignPolicyEvalResult, error) {
	reqc := self.ReqC
	signPolicy := self.GetVSignPolicy()
	resSigList := self.GetResourceSigantures()
	plugins := self.GetEnabledPlugins()
	if signPolicy, err := sign.NewSignPolicy(self.config, signPolicy, resSigList, plugins); err != nil {
		return nil, err
	} else {
		return signPolicy.Eval(reqc)
	}
}

func (self *VCheckContext) evalMutation() (*common.MutationEvalResult, error) {
	reqc := self.ReqC
	owners := []*common.Owner{}
	//ignoreAttrs := self.GetIgnoreAttrs()
	if checker, err := NewMutationChecker(owners); err != nil {
		return nil, err
	} else {
		return checker.Eval(reqc, nil) // TODO: implement ignoreAttr from RPP
	}
}

func (self *VCheckContext) abort(reason string, err error) {
	self.Aborted = true
	self.AbortReason = reason
	self.Error = err
}

func (self *VCheckContext) convertToLogBytes() []byte {

	reqc := self.ReqC

	// cc := self
	logRecord := map[string]interface{}{
		// request context
		"namespace":    reqc.Namespace,
		"name":         reqc.Name,
		"apiGroup":     reqc.ApiGroup,
		"apiVersion":   reqc.ApiVersion,
		"kind":         reqc.Kind,
		"operation":    reqc.Operation,
		"userInfo":     reqc.UserInfo,
		"objLabels":    reqc.ObjLabels,
		"objMetaName":  reqc.ObjMetaName,
		"userName":     reqc.UserName,
		"request.uid":  reqc.RequestUid,
		"type":         reqc.Type,
		"request.dump": "",
		"creator":      reqc.OrgMetadata.Annotations.CreatedBy(),

		//context
		"requestScope": self.ResourceScope,
		"dryrun":       self.DryRun,
		"unprocessed":  self.Unprocessed,
		"ignoreSA":     self.IgnoredSA,
		"protected":    self.Protected,
		"allowed":      self.Allow,
		"verified":     self.Verified,
		"aborted":      self.Aborted,
		"abortReason":  self.AbortReason,
		"msg":          self.Message,
		"breakglass":   self.BreakGlassModeEnabled,
		"detectOnly":   self.DetectOnlyModeEnabled,

		//reason code
		"reasonCode": common.ReasonCodeMap[self.ReasonCode].Code,
	}

	if self.Error != nil {
		logRecord["error"] = self.Error.Error()
	}

	if reqc.OrgMetadata != nil {
		md := reqc.OrgMetadata
		if md.OwnerRef != nil {
			logRecord["org.ownerKind"] = md.OwnerRef.Kind
			logRecord["org.ownerName"] = md.OwnerRef.Name
			logRecord["org.ownerNamespace"] = md.OwnerRef.Namespace
			logRecord["org.ownerApiVersion"] = md.OwnerRef.ApiVersion
		}
		// logRecord["org.integrityVerified"] = strconv.FormatBool(md.IntegrityVerified)
	}

	if reqc.ClaimedMetadata != nil {
		md := reqc.ClaimedMetadata
		if md.OwnerRef != nil {
			logRecord["claim.ownerKind"] = md.OwnerRef.Kind
			logRecord["claim.ownerName"] = md.OwnerRef.Name
			logRecord["claim.ownerNamespace"] = md.OwnerRef.Namespace
			logRecord["claim.ownerApiVersion"] = md.OwnerRef.ApiVersion
		}
	}

	if reqc.IntegrityValue != nil {
		logRecord["maIntegrity.serviceAccount"] = reqc.IntegrityValue.ServiceAccount
		logRecord["maIntegrity.signature"] = reqc.IntegrityValue.Signature
	}

	//context from sign policy eval
	if self.Result != nil && self.Result.SignPolicyEvalResult != nil {
		r := self.Result.SignPolicyEvalResult
		if r.Signer != nil {
			logRecord["sig.signer.email"] = r.Signer.Email
			logRecord["sig.signer.name"] = r.Signer.Name
			logRecord["sig.signer.comment"] = r.Signer.Comment
			logRecord["sig.signer.displayName"] = r.GetSignerName()
		}
		logRecord["sig.allow"] = r.Allow
		if r.Error != nil {
			logRecord["sig.errOccured"] = true
			logRecord["sig.errMsg"] = r.Error.Msg
			logRecord["sig.errReason"] = r.Error.Reason
			if r.Error.Error != nil {
				logRecord["sig.error"] = r.Error.Error.Error()
			}
		} else {
			logRecord["sig.errOccured"] = false
		}
	}

	//context from owner resolve
	if self.Result != nil && self.Result.ResolveOwnerResult != nil {
		r := self.Result.ResolveOwnerResult
		if r.Error != nil {
			logRecord["own.errOccured"] = true
			logRecord["own.errMsg"] = r.Error.Msg
			logRecord["own.errReason"] = r.Error.Reason
			if r.Error.Error != nil {
				logRecord["own.error"] = r.Error.Error.Error()
			}
		} else {
			logRecord["own.errOccured"] = false
		}
		if r.Owners != nil {
			logRecord["own.verified"] = r.Verified
			vowners := r.Owners.VerifiedOwners()
			if len(vowners) > 0 {
				vownerRef := vowners[len(vowners)-1].Ref
				logRecord["own.kind"] = vownerRef.Kind
				logRecord["own.name"] = vownerRef.Name
				logRecord["own.apiVersion"] = vownerRef.ApiVersion
				logRecord["own.namespace"] = vownerRef.Namespace
			}
			s, _ := json.Marshal(r.Owners.OwnerRefs())
			logRecord["own.owners"] = string(s)
		}
	}

	//context from mutation eval
	if self.Result != nil && self.Result.MutationEvalResult != nil {
		r := self.Result.MutationEvalResult
		if r.Error != nil {
			logRecord["ma.errOccured"] = true
			logRecord["ma.errMsg"] = r.Error.Msg
			logRecord["ma.errReason"] = r.Error.Reason
			if r.Error.Error != nil {
				logRecord["ma.error"] = r.Error.Error.Error()
			}
		} else {
			logRecord["ma.errOccured"] = false
		}
		logRecord["ma.mutated"] = strconv.FormatBool(r.IsMutated)
		logRecord["ma.diff"] = r.Diff
		logRecord["ma.filtered"] = r.Filtered
		logRecord["ma.checked"] = strconv.FormatBool(r.Checked)

	}

	if self.config.Log.IncludeRequest && !reqc.IsSecret() {
		logRecord["request.dump"] = reqc.RequestJsonStr
	}
	logRecord["request.objectHashType"] = reqc.ObjectHashType
	logRecord["request.objectHash"] = reqc.ObjectHash

	logRecord["sessionTrace"] = logger.GetSessionTraceString()

	currentTime := time.Now()
	ts := currentTime.Format("2006-01-02T15:04:05.000Z")

	logRecord["timestamp"] = ts

	logBytes, err := json.Marshal(logRecord)
	if err != nil {
		logger.Error(err)
		return []byte("")
	}
	return logBytes
}

/**********************************************

				VCheckContext

***********************************************/

type Loader struct {
	Config            *config.EnforcerConfig
	SignPolicy        *ctlconfig.SignPolicyLoader
	RPP               *ctlconfig.RPPLoader
	CRPP              *ctlconfig.CRPPLoader
	ResourceSignature *ctlconfig.ResSigLoader
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

func (self *Loader) BreakGlassConditions() []policy.BreakGlassCondition {
	sp := self.SignPolicy.GetData()
	conditions := []policy.BreakGlassCondition{}
	if sp != nil {
		conditions = append(conditions, sp.Spec.VSignPolicy.BreakGlass...)
	}
	return conditions
}

func (self *Loader) DetectOnlyMode() bool {
	return self.Config.Policy.Mode == policy.DetectMode
}

func (self *VCheckContext) initLoader() {
	enforcerNamespace := self.config.Namespace
	requestNamespace := self.ReqC.Namespace
	signatureNamespace := self.config.SignatureNamespace // for cluster scope request
	loader := &Loader{
		Config:            self.config,
		SignPolicy:        ctlconfig.NewSignPolicyLoader(enforcerNamespace),
		RPP:               ctlconfig.NewRPPLoader(enforcerNamespace, requestNamespace),
		CRPP:              ctlconfig.NewCRPPLoader(),
		ResourceSignature: ctlconfig.NewResSigLoader(signatureNamespace, requestNamespace),
	}
	self.Loader = loader
}

func (self *VCheckContext) checkIfDryRunAdmission() bool {
	return self.ReqC.DryRun
}

func (self *VCheckContext) checkIfUnprocessedInIE() bool {
	reqc := self.ReqC
	for _, d := range self.config.Policy.Ignore {
		if d.Match(reqc) {
			return true
		}
	}
	return false
}

func (self *VCheckContext) checkIfIEResource() bool {
	// TODO: implement
	// with reqc + enforceconfig
	return false
}

func (self *VCheckContext) processRequestForIEResource() *v1beta1.AdmissionResponse {
	// TODO: implement
	// with reqc + enforceconfig
	return nil
}

func (self *VCheckContext) GetVSignPolicy() *policy.VSignPolicy {
	iepol := self.config.Policy
	spol := self.Loader.SignPolicy.GetData()

	data := &policy.VSignPolicy{}
	data = data.Merge(iepol.Sign)
	data = data.Merge(spol.Spec.VSignPolicy)
	return data
}

func (self *VCheckContext) GetEnabledPlugins() map[string]bool {
	return self.config.Policy.GetEnabledPlugins()
}

func (self *VCheckContext) GetResourceSigantures() *rsig.VResourceSignatureList {
	// TODO: implement
	return nil
}

func (self *VCheckContext) GetIgnoreAttrs() *string {
	// TODO: implement (replace *string with correct struct)
	return nil
}

func (self *VCheckContext) checkIfProtected() (bool, error) {
	reqFields := self.ReqC.Map()
	if self.ResourceScope == "Cluster" || self.ResourceScope == "Namespaced" {
		rules := self.Loader.ProtectRules(self.ResourceScope)
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

func (self *VCheckContext) checkIfIgnoredSA() (bool, error) {
	reqc := self.ReqC
	reqFields := self.ReqC.Map()
	patterns := self.Loader.IgnoreServiceAccountPatterns(self.ResourceScope)
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

func (self *VCheckContext) CheckIfBreakGlassEnabled() bool {
	reqNs := self.ReqC.Namespace
	conditions := self.Loader.BreakGlassConditions()
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

func (self *VCheckContext) CheckIfDetectOnly() bool {
	return self.Loader.DetectOnlyMode()
}

func (self *VCheckContext) updateRPP() error {
	// TODO: implement
	// self.protectRule.Update(self.ReqC.Map(), self.MatchedRPP)
	return nil
}
