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

	prapi "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/protectrule/v1alpha1"
	"github.com/IBM/integrity-enforcer/enforcer/pkg/cache"
	prclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/protectrule/clientset/versioned/typed/protectrule/v1alpha1"
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
	"k8s.io/client-go/rest"
)

/**********************************************

				CheckContext

***********************************************/

type CheckContext struct {
	// request context
	config                *config.EnforcerConfig
	policy                *ctlconfig.PolicyLoader
	ReqC                  *common.ReqContext `json:"-"`
	ServiceAccount        *v1.ServiceAccount `json:"serviceAccount"`
	DryRun                bool               `json:"dryRun"`
	DetectionModeEnabled  bool               `json:"detectionModeEnabled"`
	UnverifiedModeEnabled bool               `json:"unverifiedModeEnabled"`

	Result *CheckResult `json:"result"`

	Enforced      bool   `json:"enforced"`
	Ignored       bool   `json:"ignored"`
	Allow         bool   `json:"allow"`
	Verified      bool   `json:"verified"`
	Aborted       bool   `json:"aborted"`
	AbortReason   string `json:"abortReason"`
	Error         error  `json:"error"`
	Message       string `json:"msg"`
	MatchedPolicy string `json:"matchedPolicy"`

	ConsoleLogEnabled bool `json:"-"`
	ContextLogEnabled bool `json:"-"`

	ReasonCode int `json:"reasonCode"`

	AllowByUnverifiedMode bool `json:"allowByUnverifiedMode"`
	AllowByDetectionMode  bool `json:"allowByDetectionMode"`

	detectionMatchedPolicy  string `json:"-"`
	unverifiedMatchedPolicy string `json:"-"`
	ignoreMatchedPolicy     string `json:"-"`
	allowMatchedPolicy      string `json:"-"`
	mutationMatchedPolicy   string `json:"-"`
	signerMatchedPolicy     string `json:"-"`
}

type CheckResult struct {
	InternalRequest      bool                         `json:"internal"`
	SignPolicyEvalResult *common.SignPolicyEvalResult `json:"signpolicy"`
	ResolveOwnerResult   *common.ResolveOwnerResult   `json:"owner"`
	MutationEvalResult   *common.MutationEvalResult   `json:"mutation"`
}

func NewCheckContext(config *config.EnforcerConfig, policy *ctlconfig.PolicyLoader) *CheckContext {
	cc := &CheckContext{
		config:   config,
		policy:   policy,
		Enforced: true,
		Ignored:  false,
		Aborted:  false,
		Allow:    false,
		Verified: false,
		Result: &CheckResult{
			InternalRequest: false,
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

func (self *CheckContext) ProcessRequest(req *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {

	self.DryRun = *(req.DryRun)
	if self.DryRun {
		return self.createAdmissionResponse()
	}

	//init annotation store (singleton)
	annotationStoreInstance = &ConcreteAnnotationStore{}

	//init sign store (singleton)
	sign.InitSignStore(self.config.SignStore)

	//load req context
	reqc := common.NewReqContext(req)
	logger.InitSessionLogger(reqc.Namespace, reqc.Name, reqc.ResourceRef().ApiVersion, reqc.Kind, reqc.Operation)
	self.ReqC = reqc

	// Check if the resource is protected or not
	pRule := self.loadProtectRule(self.ReqC.Namespace)
	isProtected := self.isProtected(pRule, reqc)

	if !isProtected {
		self.Ignored = true
		return self.createAdmissionResponse()
	}

	self.policy.Load(self.ReqC.Namespace)
	policyChecker := policy.NewPolicyChecker(self.policy.Policy, self.ReqC)
	self.DetectionModeEnabled, self.detectionMatchedPolicy = policyChecker.IsDetectionModeEnabled()
	self.UnverifiedModeEnabled, self.unverifiedMatchedPolicy = policyChecker.IsTrustStateEnforcementDisabled()

	if !self.Ignored && self.config.Log.ConsoleLog.IsInScope(self.ReqC) {
		self.ConsoleLogEnabled = true
	}

	if !self.Ignored && self.config.Log.ContextLog.IsInScope(self.ReqC) {
		self.ContextLogEnabled = true
	}
	//log entry
	self.logEntry()

	allowed := false
	evalReason := common.REASON_UNEXPECTED
	matchedPolicy := ""
	var errMsg string

	//evaluate sign policy
	if !self.Aborted && !allowed {
		if r, err := self.evalSignPolicy(); err != nil {
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
		if r, err := self.evalMutation(); err != nil {
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
		self.MatchedPolicy = self.detectionMatchedPolicy
	} else if !self.Allow && self.UnverifiedModeEnabled {
		self.Allow = true
		self.Verified = false
		self.AllowByUnverifiedMode = true
		self.Message = common.ReasonCodeMap[common.REASON_UNVERIFIED].Message
		self.ReasonCode = common.REASON_UNVERIFIED
		self.MatchedPolicy = self.unverifiedMatchedPolicy
	}

	if evalReason == common.REASON_UNEXPECTED {
		self.ReasonCode = evalReason
	}

	//create admission response
	admissionResponse := self.createAdmissionResponse()

	if !admissionResponse.Allowed {
		pRule.Update(reqc.Map())
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

func (self *CheckContext) evalSignPolicy() (*common.SignPolicyEvalResult, error) {
	reqc := self.ReqC
	if signPolicy, err := sign.NewSignPolicy(self.config.Namespace, self.config.PolicyNamespace, self.policy.Policy); err != nil {
		return nil, err
	} else {
		return signPolicy.Eval(reqc)
	}
}

func (self *CheckContext) evalMutation() (*common.MutationEvalResult, error) {
	reqc := self.ReqC
	owners := []*common.Owner{}
	if checker, err := NewMutationChecker(owners); err != nil {
		return nil, err
	} else {
		return checker.Eval(reqc, self.policy.Policy)
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

	if self.Result != nil {
		logRecord["internal"] = self.Result.InternalRequest
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

func (self *CheckContext) loadProtectRule(namespace string) *prapi.ProtectRule {
	name := "ie-protect-rule"
	prLoadInterval := time.Second * 5
	config, _ := rest.InClusterConfig()
	var pr *prapi.ProtectRule
	var err error
	var keyName string
	prClient, _ := prclient.NewForConfig(config)
	keyName = fmt.Sprintf("protectRule/%s", namespace)
	if cached := cache.GetString(keyName); cached == "" {
		pr, err = prClient.ProtectRules(namespace).Get(name, metav1.GetOptions{})
		if err != nil {
			logger.Debug("failed to get ProtectRule:", err)
			return nil
		}
		logger.Debug("ProtectRule reloaded.")
		if !pr.IsEmpty() {
			tmp, _ := json.Marshal(pr)
			cache.SetString(keyName, string(tmp), &(prLoadInterval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &pr)
		if err != nil {
			logger.Debug("failed to Unmarshal cached IntegrityEnforcerPolicy:", err)
			return nil
		}
	}
	return pr
}

func (self *CheckContext) isProtected(pRule *prapi.ProtectRule, reqc *common.ReqContext) bool {
	if pRule == nil {
		return false
	}
	reqFields := reqc.Map()
	return pRule.Match(reqFields)
	//return reqc.Namespace == "secure-ns" && reqc.Kind == "ConfigMap" && reqc.Name == "test-cm"
}
