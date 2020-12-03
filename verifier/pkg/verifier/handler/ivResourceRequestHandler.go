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
	common "github.com/IBM/integrity-enforcer/verifier/pkg/common/common"
	logger "github.com/IBM/integrity-enforcer/verifier/pkg/util/logger"
	handlerutil "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/handlerutil"
	v1beta1 "k8s.io/api/admission/v1beta1"
)

/**********************************************

				IVResourceRequestHandler

***********************************************/

type IVResourceRequestHandler struct {
	*commonHandler
	isOperatorResource bool
	isServerResource   bool
}

func (self *IVResourceRequestHandler) Run(req *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {

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

	self.ctx.IVResource = true
	if (self.isOperatorResource && self.checkIfIVAdminRequest()) || (self.isServerResource && (self.checkIfIVOperatorRequest() || self.checkIfIVServerRequest())) {
		allowed = true
		evalReason = common.REASON_IV_ADMIN
	} else {
		evalReason = common.REASON_BLOCK_IV_RESOURCE_OPERATION
		self.ctx.Protected = true
	}

	var errMsg string

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

	// Reload RuleTable only when RSP/namespace request is allowed.
	// however, RSP request by IV server is exception because it is just updating only `status` about denied request.
	if self.ctx.Allow && (self.checkIfProfileResource() && !self.checkIfIVServerRequest() || self.checkIfNamespaceRequest()) {
		err := self.loader.ReloadRuleTable(self.reqc)
		if err != nil {
			logger.Error("Failed to reload RuleTable; ", err)
		}
	}

	// event
	err := self.createOrUpdateEvent()
	if err != nil {
		logger.Error("Failed to create an event; ", err)
	}

	// avoid to log events for IV to update RuleTables
	if !(self.isServerResource && self.checkIfIVServerRequest()) {
		//log context
		self.logContext()
	}

	//log exit
	self.logExit()

	return admissionResponse

}

func (self *IVResourceRequestHandler) evalFinalDecision(allowed bool, evalReason int, errMsg string) *DecisionResult {

	dr := &DecisionResult{}

	if self.ctx.Aborted {
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
		dr.Message = common.ReasonCodeMap[evalReason].Message
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
