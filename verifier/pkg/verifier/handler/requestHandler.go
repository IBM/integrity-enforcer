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
	rspapi "github.com/IBM/integrity-enforcer/verifier/pkg/apis/resourcesigningprofile/v1alpha1"
	common "github.com/IBM/integrity-enforcer/verifier/pkg/common/common"
	logger "github.com/IBM/integrity-enforcer/verifier/pkg/util/logger"
	handlerutil "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/handlerutil"
	v1beta1 "k8s.io/api/admission/v1beta1"
)

/**********************************************

				RequestHandler

***********************************************/

type RequestHandler struct {
	*commonHandler
}

func (self *RequestHandler) Run(req *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {

	if resp := self.inScopeCheck(req); resp != nil {
		if self.config.Log.LogAllResponse {
			self.logResponse(req, resp)
		}
		return resp
	}

	// Start IV world from here ...

	//init logger
	logger.InitSessionLogger(self.reqc.Namespace,
		self.reqc.Name,
		self.reqc.ResourceRef().ApiVersion,
		self.reqc.Kind,
		self.reqc.Operation)

	self.logEntry()

	allowed := false
	evalReason := common.REASON_UNEXPECTED

	if ok, msg := handlerutil.ValidateResource(self.reqc, self.config.Namespace); !ok {
		return createAdmissionResponse(false, msg)
	}

	protected := false
	matchedProfiles := []rspapi.ResourceSigningProfile{}
	if !self.ctx.Aborted && !allowed {
		protected, matchedProfiles = self.checkIfProtected()
	}
	if !protected {
		allowed = true
		evalReason = common.REASON_NOT_PROTECTED
	} else {
		self.ctx.Protected = true
	}

	var errMsg string
	var denyingProfile *rspapi.ResourceSigningProfile
	var sigEvalResult *common.SignatureEvalResult
	var mutEvalResult *common.MutationEvalResult
	if !self.ctx.Aborted && self.ctx.Protected && !allowed {
		for _, prof := range matchedProfiles {
			profChecker := &profileChecker{commonHandler: self.commonHandler, profile: prof}
			allowed, evalReason, errMsg, sigEvalResult, mutEvalResult = profChecker.run()
			if !allowed {
				denyingProfile = &prof
				break
			}
		}
	}
	if sigEvalResult != nil {
		self.ctx.SignatureEvalResult = sigEvalResult
	}
	if mutEvalResult != nil {
		self.ctx.MutationEvalResult = mutEvalResult
	}

	self.ctx.BreakGlassModeEnabled = self.CheckIfBreakGlassEnabled()
	self.ctx.DetectOnlyModeEnabled = self.CheckIfDetectOnly()

	var dr *DecisionResult
	dr = self.evalFinalDecision(allowed, evalReason, errMsg)

	self.ctx.Allow = dr.Allow
	self.ctx.Verified = dr.Verified
	self.ctx.ReasonCode = dr.ReasonCode
	self.ctx.Message = dr.Message

	//create admission response
	admissionResponse := createAdmissionResponse(self.ctx.Allow, self.ctx.Message)
	if self.config.Log.LogAllResponse {
		self.logResponse(req, admissionResponse)
	}

	patch := self.createPatch()

	if !self.reqc.IsDeleteRequest() && len(patch) > 0 {
		admissionResponse.Patch = patch
		admissionResponse.PatchType = func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}()
	}

	if !self.ctx.Allow && denyingProfile != nil {
		err := self.loader.UpdateProfileStatus(denyingProfile, self.reqc, errMsg)
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
