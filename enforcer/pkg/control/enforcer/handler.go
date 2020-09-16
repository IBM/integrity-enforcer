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
	"strings"

	"github.com/IBM/integrity-enforcer/enforcer/pkg/config"
	common "github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/logger"
	v1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

/**********************************************

				VCheckContext

***********************************************/

type RequestHandler struct {
	config *config.EnforcerConfig
}

func NewRequestHandler(config *config.EnforcerConfig) *RequestHandler {
	return &RequestHandler{config: config}
}

func (self *RequestHandler) InitCheckContext() *VCheckContext {
	cc := &VCheckContext{
		config: self.config,
		Loader: &Loader{Config: self.config},

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

func (self *RequestHandler) Run(cc *VCheckContext, req *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {

	// init
	reqc := common.NewReqContext(req)
	cc.ReqC = reqc
	if reqc.Namespace == "" {
		cc.ResourceScope = "Cluster"
	} else {
		cc.ResourceScope = "Namespaced"
	}

	cc.DryRun = cc.checkIfDryRunAdmission()

	if cc.DryRun {
		return createAdmissionResponse(true, "request is dry run")
	}

	cc.Unprocessed = cc.checkIfUnprocessedInIE()
	if cc.Unprocessed {
		return createAdmissionResponse(true, "request is not processed by IE")
	}

	if cc.checkIfIEResource() {
		return cc.processRequestForIEResource()
	}

	// Start IE world from here ...

	//init loader
	cc.initLoader()

	//init logger
	logger.InitSessionLogger(cc.ReqC.Namespace,
		cc.ReqC.Name,
		cc.ReqC.ResourceRef().ApiVersion,
		cc.ReqC.Kind,
		cc.ReqC.Operation)

	if !cc.config.Log.ConsoleLog.IsInScope(cc.ReqC) {
		cc.ConsoleLogEnabled = true
	}

	if !cc.config.Log.ContextLog.IsInScope(cc.ReqC) {
		cc.ContextLogEnabled = true
	}

	cc.logEntry()

	requireChk := true

	if ignoredSA, err := cc.checkIfIgnoredSA(); err != nil {
		cc.abort("Error when checking if ignored service accounts", err)
	} else if ignoredSA {
		cc.IgnoredSA = ignoredSA
		requireChk = false
	}

	if !cc.Aborted && requireChk {
		if protected, err := cc.checkIfProtected(); err != nil {
			cc.abort("Error when check if the resource is protected", err)
		} else {
			cc.Protected = protected
		}
	}

	allowed := true
	evalReason := common.REASON_UNEXPECTED
	var errMsg string
	if !cc.Aborted && cc.Protected {
		allowed = false

		//init annotation store (singleton)
		annotationStoreInstance = &ConcreteAnnotationStore{}

		//evaluate sign policy
		if !cc.Aborted && !allowed {
			if r, err := cc.evalSignPolicy(); err != nil {
				cc.abort("Error when evaluating sign policy", err)
			} else {
				cc.Result.SignPolicyEvalResult = r
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
		if !cc.Aborted && !allowed && cc.ReqC.IsUpdateRequest() {
			if r, err := cc.evalMutation(); err != nil {
				cc.abort("Error when evaluating mutation", err)
			} else {
				cc.Result.MutationEvalResult = r
				if r.Checked && !r.IsMutated {
					allowed = true
					evalReason = common.REASON_NO_MUTATION
				}
			}
		}
	}

	cc.BreakGlassModeEnabled = cc.CheckIfBreakGlassEnabled()
	cc.DetectOnlyModeEnabled = cc.CheckIfDetectOnly()

	/********************************************
				Decision Step [3/3]

		input: allowed, evalReason, errMsg (&matchedPolicy)
		output: AdmissionResponse
	********************************************/

	if cc.ReqC.IsDeleteRequest() {
		cc.Allow = true
		cc.Verified = true
		cc.ReasonCode = common.REASON_SKIP_DELETE
		cc.Message = common.ReasonCodeMap[common.REASON_SKIP_DELETE].Message
	} else if cc.Aborted {
		cc.Allow = false
		cc.Verified = false
		cc.Message = cc.AbortReason
		cc.ReasonCode = common.REASON_ABORTED
	} else if allowed {
		cc.Allow = true
		cc.Verified = true
		cc.ReasonCode = evalReason
		cc.Message = common.ReasonCodeMap[evalReason].Message
	} else {
		cc.Allow = false
		cc.Verified = false
		cc.Message = errMsg
		cc.ReasonCode = evalReason
	}

	if !cc.Allow && cc.DetectOnlyModeEnabled {
		cc.Allow = true
		cc.Verified = false
		cc.AllowByDetectOnlyMode = true
		cc.Message = common.ReasonCodeMap[common.REASON_DETECTION].Message
		cc.ReasonCode = common.REASON_DETECTION
	} else if !cc.Allow && cc.BreakGlassModeEnabled {
		cc.Allow = true
		cc.Verified = false
		cc.AllowByBreakGlassMode = true
		cc.Message = common.ReasonCodeMap[common.REASON_UNVERIFIED].Message
		cc.ReasonCode = common.REASON_UNVERIFIED
	}

	if evalReason == common.REASON_UNEXPECTED {
		cc.ReasonCode = evalReason
	}

	//create admission response
	admissionResponse := createAdmissionResponse(cc.Allow, cc.Message)

	patch := cc.createPatch()

	if !cc.ReqC.IsDeleteRequest() && len(patch) > 0 {
		admissionResponse.Patch = patch
		admissionResponse.PatchType = func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}()
	}

	if !cc.Allow {
		cc.updateRPP()
	}

	//log context
	cc.logContext()

	//log exit
	cc.logExit()

	return admissionResponse

}

func createAdmissionResponse(allowed bool, msg string) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Allowed: allowed,
		Result: &metav1.Status{
			Message: msg,
		}}
}
