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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/rego"

	crppapi "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/vclusterresourceprotectionprofile/v1alpha1"
	rppapi "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/vresourceprotectionprofile/v1alpha1"

	"github.com/IBM/integrity-enforcer/enforcer/pkg/config"
	common "github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
	ctlconfig "github.com/IBM/integrity-enforcer/enforcer/pkg/control/config"
	sign "github.com/IBM/integrity-enforcer/enforcer/pkg/control/sign"
	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/logger"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/policy"
	log "github.com/sirupsen/logrus"
	v1beta1 "k8s.io/api/admission/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ModeDefault      string = "Default"
	ModeDryRun       string = "DryRun"
	ModeNotProtected string = "NotProtected"
	ModeDetect       string = "Detect"
	ModeUnverified   string = "Unverified" //BreakGlass
)

/**********************************************

				CheckContext

***********************************************/

type CheckContext struct {
	Mode          string `json:"mode"`
	Scope         string `json:"scope,omitempty"`
	RequireChecks bool   `json:"RequireChecks"`

	// request context
	config           *config.EnforcerConfig
	signPolicyLoader *ctlconfig.SignPolicyLoader
	rppLoader        *ctlconfig.RPPLoader
	crppLoader       *ctlconfig.CRPPLoader
	resSigLoader     *ctlconfig.ResSigLoader

	ReqC                  *common.ReqContext `json:"-"`
	ServiceAccount        *v1.ServiceAccount `json:"serviceAccount"`
	DryRun                bool               `json:"dryRun"`
	DetectionModeEnabled  bool               `json:"detectionModeEnabled"`
	UnverifiedModeEnabled bool               `json:"unverifiedModeEnabled"`

	Result *CheckResult `json:"result"`

	Enforced    bool   `json:"enforced"`
	Ignored     bool   `json:"ignored"`
	Allow       bool   `json:"allow"`
	Verified    bool   `json:"verified"`
	Aborted     bool   `json:"aborted"`
	AbortReason string `json:"abortReason"`
	Error       error  `json:"error"`
	Message     string `json:"msg"`

	mergedPolicy *policy.PolicyList

	MatchedPolicy string                                     `json:"matchedPolicy"`
	MatchedRPP    *rppapi.VResourceProtectionProfile         `json:"matchedRPP"`
	MatchedCRPP   *crppapi.VClusterResourceProtectionProfile `json:"matchedCRPP"`

	ConsoleLogEnabled bool `json:"-"`
	ContextLogEnabled bool `json:"-"`

	ReasonCode int `json:"reasonCode"`

	AllowByUnverifiedMode bool `json:"allowByUnverifiedMode"`
	AllowByDetectionMode  bool `json:"allowByDetectionMode"`
}

type CheckResult struct {
	SignPolicyEvalResult *common.SignPolicyEvalResult `json:"signpolicy"`
	ResolveOwnerResult   *common.ResolveOwnerResult   `json:"owner"`
	MutationEvalResult   *common.MutationEvalResult   `json:"mutation"`
}

func NewCheckContext(config *config.EnforcerConfig, policy *ctlconfig.PolicyLoader) *CheckContext {
	cc := &CheckContext{
		Mode:             ModeDefault,
		RequireChecks:    false,
		config:           config,
		signPolicyLoader: nil,
		rppLoader:        nil,
		crppLoader:       nil,
		resSigLoader:     nil,

		// policy:      policy,
		// protectRule: ctlconfig.NewProtectRuleLoader(),
		Enforced: true,
		Ignored:  false,
		Aborted:  false,
		Allow:    false,
		Verified: false,
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

func (self *CheckContext) setReqContextAndScope(req *v1beta1.AdmissionRequest) {
	reqc := common.NewReqContext(req)
	self.ReqC = reqc
	if reqc.Namespace == "" {
		self.Scope = "Cluster"
	} else {
		self.Scope = "Namespaced"
	}
	return
}

func (self *CheckContext) isIgnore() bool {
	// TODO: implement
	// check isDryRun(reqc), isIgnoreKind(reqc+enforcerconfig), isIgnoreSA(reqc+rpp/crpp) <== isIgnoreSA should be separated(?)
	return false
}

func (self *CheckContext) isIEProtectingCR() bool {
	// TODO: implement
	// RPP, CRPP...
	return false
}

func (self *CheckContext) initLoaders() {
	enforcerNamespace := self.config.Namespace
	requestNamespace := self.ReqC.Namespace
	signatureNamespace := self.config.SignStore.SignatureNamespace // for cluster scope request
	self.signPolicyLoader = ctlconfig.NewSignPolicyLoader(enforcerNamespace)
	self.rppLoader = ctlconfig.NewRPPLoader(enforcerNamespace, requestNamespace)
	self.crppLoader = ctlconfig.NewCRPPLoader()
	self.resSigLoader = ctlconfig.NewResSigLoader(signatureNamespace, requestNamespace)
	return
}

func (self *CheckContext) loadResourcesByLoader() {
	self.signPolicyLoader.Load()
	self.rppLoader.Load()
	self.crppLoader.Load()
	self.resSigLoader.Load()
}

func (self *CheckContext) setProtectMode() {

	if self.isIgnore() {
		self.RequireChecks = false
		return
	} else {
		self.loadResourcesByLoader()
	}

	/********************************************
			Protected Mode Check (2/4)
	********************************************/
	var isProtected bool
	var tmpMatchedRPP *rppapi.VResourceProtectionProfile
	isProtected, tmpMatchedRPP = self.isProtectedByProfile()

	if isProtected {
		self.MatchedRPP = tmpMatchedRPP
		self.RequireChecks = true
	} else {
		self.Mode = ModeNotProtected
		return
	}

	/********************************************
			Detection Mode Check (3/4)
	********************************************/
	var detectionModeEnabled bool
	var tmpMatchedPolicy string

	polList := []*policy.Policy{self.config.Policy.Policy()}
	polList2 := []*policy.Policy{}
	for _, d := range self.signPolicyLoader.Data {
		polList2 = append(polList2, d.Spec.VSignPolicy.Policy())
	}
	polList = append(polList, polList2...)
	polMerged := &policy.PolicyList{Items: polList}

	self.mergedPolicy = polMerged

	policyChecker := policy.NewPolicyChecker(polMerged, self.ReqC)

	detectionModeEnabled, tmpMatchedPolicy = policyChecker.IsDetectionModeEnabled()
	if detectionModeEnabled {
		self.Mode = ModeDetect
		self.MatchedPolicy = tmpMatchedPolicy
		self.DetectionModeEnabled = true
		return
	}

	/********************************************
			Unverified Mode Check (4/4)
	********************************************/
	var unverifiedModeEnabled bool
	unverifiedModeEnabled, tmpMatchedPolicy = policyChecker.IsTrustStateEnforcementDisabled()
	if unverifiedModeEnabled {
		self.Mode = ModeUnverified
		self.MatchedPolicy = tmpMatchedPolicy
		self.UnverifiedModeEnabled = true
		return
	}

	return
}

func (self *CheckContext) isProtectedREGO(req *v1beta1.AdmissionRequest) bool {
	ctx := context.Background()

	reqB, err := json.Marshal(req)
	if err != nil {
		panic(err)
	}
	fmt.Println("request:", string(reqB))

	d := json.NewDecoder(bytes.NewBufferString(string(reqB)))
	d.UseNumber()

	var input interface{}
	if err := d.Decode(&input); err != nil {
		panic(err)
	}

	// Create a simple query
	r := rego.New(
		//rego.Query("input.review.kind.kind == \"ConfigMap\""),
		rego.Query("input.kind.kind == \"ConfigMap\""),
		rego.Input(input),
	)

	// // Prepare for evaluation
	// pq, err := r.PrepareForEval(ctx)

	// if err != nil {
	// 	// Handle error.
	// }

	// // Raw input data that will be used in the first evaluation
	// input := map[string]interface{}{"x": 2}

	// Run the evaluation
	rs, err := r.Eval(ctx)
	if err != nil {
		panic(err)
	}

	rsB, err := json.Marshal(rs)
	if err != nil {
		panic(err)
	}
	// Inspect results.
	fmt.Println("result set:", string(rsB))

	protected, err := strconv.ParseBool(rs[0].Expressions[0].String())
	if err != nil {
		panic(err)
	}
	return protected
}

func (self *CheckContext) ProcessRequest(req *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {

	// init
	self.setReqContextAndScope(req)
	self.initLoaders()

	/********************************************
				Preparation Step [1/3]

		input: AdmissionRequest
		output: RequireChecks flag (& matchedRule, matchedPolicy, modeInfo)
	********************************************/

	// "self.RequireChecks" must be set here
	self.setProtectMode()

	// OPA version of isProtected()
	// self.RequireChecks = self.isProtectedREGO(req)

	/********************************************
			Process Request Step [2/3]

		input: RequireChecks flag, ReqContext, Policy
		output: allowed, evalReason, errMsg (&matchedPolicy)
	********************************************/

	// log init
	logger.InitSessionLogger(self.ReqC.Namespace, self.ReqC.Name, self.ReqC.ResourceRef().ApiVersion, self.ReqC.Kind, self.ReqC.Operation)
	if !self.Ignored && self.config.Log.ConsoleLog.IsInScope(self.ReqC) {
		self.ConsoleLogEnabled = true
	}
	if !self.Ignored && self.config.Log.ContextLog.IsInScope(self.ReqC) {
		self.ContextLogEnabled = true
	}
	self.logEntry()

	allowed := true
	evalReason := common.REASON_UNEXPECTED
	matchedPolicy := ""
	var errMsg string
	if self.RequireChecks {
		allowed = false

		//init annotation store (singleton)
		annotationStoreInstance = &ConcreteAnnotationStore{}
		//init sign store (singleton)
		sign.InitSignStore(self.config.SignStore)

		//evaluate sign policy
		if !self.Aborted && !allowed {
			if r, err := self.evalSignPolicy(self.mergedPolicy); err != nil {
				self.abort("Error when evaluating sign policy", err)
			} else {
				self.Result.SignPolicyEvalResult = r
				if r.Checked && r.Allow {
					allowed = true
					evalReason = common.REASON_VALID_SIG
					matchedPolicy = r.MatchedPolicy
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
			if r, err := self.evalMutation(self.mergedPolicy); err != nil {
				self.abort("Error when evaluating mutation", err)
			} else {
				self.Result.MutationEvalResult = r
				if r.Checked && !r.IsMutated {
					allowed = true
					evalReason = common.REASON_NO_MUTATION
					matchedPolicy = r.MatchedPolicy
				}
			}
		}
	}

	/********************************************
				Decision Step [3/3]

		input: allowed, evalReason, errMsg (&matchedPolicy)
		output: AdmissionResponse
	********************************************/

	if !self.Enforced {
		self.Allow = true
		self.Verified = true
		self.ReasonCode = common.REASON_NOT_ENFORCED
		self.Message = common.ReasonCodeMap[common.REASON_NOT_ENFORCED].Message
	} else if self.ReqC.IsDeleteRequest() {
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
		self.MatchedPolicy = matchedPolicy
	} else {
		self.Allow = false
		self.Verified = false
		self.Message = errMsg
		self.ReasonCode = evalReason
	}

	if !self.Allow && self.DetectionModeEnabled {
		self.Allow = true
		self.Verified = false
		self.AllowByDetectionMode = true
		self.Message = common.ReasonCodeMap[common.REASON_DETECTION].Message
		self.ReasonCode = common.REASON_DETECTION
	} else if !self.Allow && self.UnverifiedModeEnabled {
		self.Allow = true
		self.Verified = false
		self.AllowByUnverifiedMode = true
		self.Message = common.ReasonCodeMap[common.REASON_UNVERIFIED].Message
		self.ReasonCode = common.REASON_UNVERIFIED
	}

	if evalReason == common.REASON_UNEXPECTED {
		self.ReasonCode = evalReason
	}

	//create admission response
	admissionResponse := self.createAdmissionResponse()

	if !admissionResponse.Allowed {
		if self.MatchedRPP != nil {
			// TODO: implement update()

			// self.protectRule.Update(self.ReqC.Map(), self.MatchedRPP)
			// self.updateProtectRule()
		}
	}

	//log context
	self.logContext()

	//log exit
	self.logExit()

	return admissionResponse

}

func (self *CheckContext) logEntry() {
	if self.ConsoleLogEnabled {
		sLogger := logger.GetSessionLogger()
		sLogger.Trace("New Admission Request Received")
	}
}

func (self *CheckContext) logContext() {
	if self.ContextLogEnabled {
		cLogger := logger.GetContextLogger()
		logBytes := self.convertToLogBytes()
		cLogger.SendLog(logBytes)
	}
}

func (self *CheckContext) logExit() {
	if self.ConsoleLogEnabled {
		sLogger := logger.GetSessionLogger()
		sLogger.WithFields(log.Fields{
			"allowed": self.Allow,
			"aborted": self.Aborted,
		}).Trace("New Admission Request Sent")
	}
}

func (self *CheckContext) createAdmissionResponse() *v1beta1.AdmissionResponse {

	if self.DryRun {
		return &v1beta1.AdmissionResponse{
			Allowed: true,
			Result: &metav1.Status{
				Message: "request is dry run",
			}}
	}

	if self.Ignored {
		return &v1beta1.AdmissionResponse{
			Allowed: true,
			Result: &metav1.Status{
				Message: "request ignored",
			}}
	}

	allowed := self.Allow
	msg := self.Message

	labels := map[string]string{}
	deleteKeys := []string{}
	if allowed {

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
	}

	var patch []byte
	if allowed {
		name := self.ReqC.Name
		reqJson := self.ReqC.RequestJsonStr
		if self.config.PatchEnabled() {
			patch = createPatch(name, reqJson, labels, deleteKeys)
		}
	}

	admissionResponse := &v1beta1.AdmissionResponse{
		Allowed: allowed,
		Result: &metav1.Status{
			Message: msg,
		}}

	if !self.ReqC.IsDeleteRequest() && len(patch) > 0 {
		admissionResponse.Patch = patch
		admissionResponse.PatchType = func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}()
	}
	return admissionResponse
}

func (self *CheckContext) evalSignPolicy(pol *policy.PolicyList) (*common.SignPolicyEvalResult, error) {
	reqc := self.ReqC
	if signPolicy, err := sign.NewSignPolicy(self.config.Namespace, self.config.PolicyNamespace, pol); err != nil {
		return nil, err
	} else {
		return signPolicy.Eval(reqc)
	}
}

func (self *CheckContext) evalMutation(pol *policy.PolicyList) (*common.MutationEvalResult, error) {
	reqc := self.ReqC
	owners := []*common.Owner{}
	if checker, err := NewMutationChecker(owners); err != nil {
		return nil, err
	} else {
		return checker.Eval(reqc, pol)
	}
}

func (self *CheckContext) abort(reason string, err error) {
	self.Aborted = true
	self.AbortReason = reason
	self.Error = err
}

func (self *CheckContext) convertToLogBytes() []byte {

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
		"enfored":     self.Enforced,
		"ignored":     self.Ignored,
		"allowed":     self.Allow,
		"verified":    self.Verified,
		"aborted":     self.Aborted,
		"abortReason": self.AbortReason,
		"msg":         self.Message,
		"policy":      self.MatchedPolicy,
		// TODO: implement matched RPP/CRPP logging
		// "rule":        self.MatchedRPP.String(),
		"mode": self.Mode,

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

func (self *CheckContext) updateRPP() error {
	// TODO: implement
	return nil
}

func (self *CheckContext) isProtectedByProfile() (bool, *rppapi.VResourceProtectionProfile) {
	// if pRule == nil {
	// 	return false, nil
	// }
	// reqFields := reqc.Map()
	// return pRule.Match(reqFields)

	// TODO: implement
	return false, nil
}
