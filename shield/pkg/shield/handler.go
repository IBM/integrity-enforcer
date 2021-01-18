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

package shield

import (
	"encoding/json"
	"fmt"

	rspapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	logger "github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	log "github.com/sirupsen/logrus"

	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	config "github.com/IBM/integrity-enforcer/shield/pkg/shield/config"
	v1beta1 "k8s.io/api/admission/v1beta1"
)

/**********************************************

				Handler

***********************************************/

type Handler struct {
	config     *config.ShieldConfig
	ctx        *CheckContext
	reqc       *common.ReqContext
	data       *RunData
	logInScope bool
}

func NewHandler(config *config.ShieldConfig) *Handler {
	return &Handler{config: config, data: &RunData{}}
}

func (self *Handler) Run(req *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {

	// init ctx, reqc and data & init logger
	self.initialize(req)

	// make DecisionResult based on reqc, config and data
	dr := self.Check()

	// overwrite DecisionResult if needed (DetectMode & BreakGlass)
	dr = self.overwriteDecision(dr)

	// make AdmissionResponse based on DecisionResult
	resp := &v1beta1.AdmissionResponse{}
	if dr.isUndetermined() {
		resp = createAdmissionResponse(false, "IntegrityShield failed to decide the response for this request", self.reqc)
	} else if dr.isErrorOccurred() {
		resp = createAdmissionResponse(false, dr.Message, self.reqc)
	} else {
		resp = createAdmissionResponse(dr.isAllowed(), dr.Message, self.reqc)
	}

	// log results
	self.logResponse(req, resp)
	self.logContext()

	// create Event & update RSP status
	_ = self.Report(dr.denyRSP)

	// clear some cache if needed
	self.finalize(resp)

	return resp
}

func (self *Handler) Check() *DecisionResult {
	var dr *DecisionResult
	dr = undeterminedDescision()

	dr = inScopeCheck(self.reqc, self.config, self.data, self.ctx)
	if !dr.isUndetermined() {
		return dr
	}
	self.logInScope = true

	dr = formatCheck(self.reqc, self.config, self.data, self.ctx)
	if !dr.isUndetermined() {

		return dr
	}

	dr = iShieldResourceCheck(self.reqc, self.config, self.data, self.ctx)
	if !dr.isUndetermined() {
		return dr
	}

	dr = deleteCheck(self.reqc, self.config, self.data, self.ctx)
	if !dr.isUndetermined() {
		return dr
	}

	var matchedProfiles []rspapi.ResourceSigningProfile
	dr, matchedProfiles = protectedCheck(self.reqc, self.config, self.data, self.ctx)
	if !dr.isUndetermined() {
		return dr
	}

	for _, prof := range matchedProfiles {
		dr = resourceSigningProfileCheck(prof, self.reqc, self.config, self.data, self.ctx)
		if dr.isAllowed() {
			// this RSP allowed the request. will check next RSP.
		} else {
			// this RSP denied the request. return the result and will make AdmissionResponse.
			return dr
		}
	}

	if dr.isUndetermined() {
		dr = &DecisionResult{
			Type:       common.DecisionUndetermined,
			ReasonCode: common.REASON_UNEXPECTED,
			Message:    "IntegrityShield failed to decide a response for this request.",
		}
	}
	return dr
}

func (self *Handler) Report(denyRSP *rspapi.ResourceSigningProfile) error {
	// report only for denying request or for IShield resource request by IShield Admin
	shouldReport := false
	if !self.ctx.Allow {
		shouldReport = true
	}
	iShieldAdmin := checkIfIShieldAdminRequest(self.reqc, self.config)
	if self.ctx.IShieldResource && iShieldAdmin {
		shouldReport = true
	}

	if !shouldReport {
		return nil
	}

	var err error
	// create/update Event
	err = createOrUpdateEvent(self.reqc, self.ctx, self.config)
	if err != nil {
		logger.Error("Failed to create event; ", err)
		return err
	}

	// update RSP status
	err = updateRSPStatus(denyRSP, self.reqc, self.ctx.Message)
	if err != nil {
		logger.Error("Failed to update status; ", err)
	}

	return nil
}

// load resoruces / set default values
func (self *Handler) initialize(req *v1beta1.AdmissionRequest) *DecisionResult {

	self.ctx = InitCheckContext(self.config)

	reqNamespace := getRequestNamespace(req)

	// init ReqContext
	self.reqc = common.NewReqContext(req)

	// set request UID in logger special field
	logger.AddValueToListField("ongoingReqUIDs", string(req.UID))
	// init session logger
	logger.InitSessionLogger(self.reqc.Namespace, self.reqc.Name, self.reqc.ResourceRef().ApiVersion, self.reqc.Kind, self.reqc.Operation)
	// Note: logEntry() calls ShieldConfig.ConsoleLogEnabled() internally, and this requires SessionLogger and ReqContext.
	self.logEntry()

	runDataLoader := NewLoader(self.config, reqNamespace)
	self.data.loader = runDataLoader
	self.data.Init(self.reqc, self.config.Namespace)

	return &DecisionResult{Type: common.DecisionUndetermined}
}

func (self *Handler) overwriteDecision(dr *DecisionResult) *DecisionResult {
	sigConf := self.data.GetSignerConfig()
	isBreakGlass := checkIfBreakGlassEnabled(self.reqc, sigConf)
	isDetectMode := checkIfDetectOnly(self.config)

	if !isBreakGlass && !isDetectMode {
		return dr
	}

	if !dr.isAllowed() && isDetectMode {
		self.ctx.Allow = true
		self.ctx.DetectOnlyModeEnabled = true
		self.ctx.ReasonCode = common.REASON_DETECTION
		self.ctx.Message = common.ReasonCodeMap[common.REASON_DETECTION].Message
		dr.Type = common.DecisionAllow
		dr.Verified = false
		dr.Message = common.ReasonCodeMap[common.REASON_DETECTION].Message
		dr.ReasonCode = common.REASON_DETECTION
	} else if !dr.isAllowed() && isBreakGlass {
		self.ctx.Allow = true
		self.ctx.BreakGlassModeEnabled = true
		self.ctx.ReasonCode = common.REASON_BREAK_GLASS
		self.ctx.Message = common.ReasonCodeMap[common.REASON_BREAK_GLASS].Message
		dr.Type = common.DecisionAllow
		dr.Verified = false
		dr.Message = common.ReasonCodeMap[common.REASON_BREAK_GLASS].Message
		dr.ReasonCode = common.REASON_BREAK_GLASS
	}
	return dr
}

func (self *Handler) finalize(resp *v1beta1.AdmissionResponse) {
	if resp.Allowed {
		resetRuleTableCache := false
		iShieldServer := checkIfIShieldServerRequest(self.reqc, self.config)
		iShieldOperator := checkIfIShieldOperatorRequest(self.reqc, self.config)
		if self.reqc.Kind == "Namespace" {
			if self.reqc.IsUpdateRequest() {
				mtResult, _ := MutationCheck(self.reqc)
				if mtResult != nil && mtResult.IsMutated {
					logger.Debug("[DEBUG] namespace mutation: ", mtResult.Diff)
					resetRuleTableCache = true
				}
			} else {
				resetRuleTableCache = true
			}
		} else if self.reqc.Kind == common.ProfileCustomResourceKind && !iShieldServer && !iShieldOperator {
			resetRuleTableCache = true
		}
		if resetRuleTableCache {
			// if namespace/RSP request is allowed, then reset cache for RuleTable (RSP list & NS list).
			self.data.resetRuleTableCache()
		}
	}
	self.logExit()
	logger.RemoveValueFromListField("ongoingReqUIDs", self.reqc.RequestUid)
	return
}

func (self *Handler) logEntry() {
	if ok, level := self.config.ConsoleLogEnabled(self.reqc); ok {
		logger.SetLogLevel(level) // set custom log level for this request
		sLogger := logger.GetSessionLogger()
		sLogger.WithFields(log.Fields{
			"requestUID": self.reqc.RequestUid,
		}).Trace("New Admission Request Received")
	}
}

func (self *Handler) logContext() {
	if self.config.ContextLogEnabled(self.reqc) && self.logInScope {
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

func (self *Handler) logExit() {
	if ok, _ := self.config.ConsoleLogEnabled(self.reqc); ok {
		sLogger := logger.GetSessionLogger()
		sLogger.WithFields(log.Fields{
			"allowed":    self.ctx.Allow,
			"aborted":    self.ctx.Aborted,
			"requestUID": self.reqc.RequestUid,
		}).Trace("New Admission Request Sent")
		logger.SetLogLevel(self.config.Log.LogLevel) // set default log level again
	}
}

func (self *Handler) logResponse(req *v1beta1.AdmissionRequest, resp *v1beta1.AdmissionResponse) {
	if self.config.Log.LogAllResponse {
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
	}
	return
}
