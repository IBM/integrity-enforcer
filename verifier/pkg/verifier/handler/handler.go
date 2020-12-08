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
	"encoding/json"
	"fmt"

	rspapi "github.com/IBM/integrity-enforcer/verifier/pkg/apis/resourcesigningprofile/v1alpha1"
	logger "github.com/IBM/integrity-enforcer/verifier/pkg/util/logger"
	log "github.com/sirupsen/logrus"

	common "github.com/IBM/integrity-enforcer/verifier/pkg/common/common"
	config "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/config"
	loader "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/loader"
	v1beta1 "k8s.io/api/admission/v1beta1"
)

/**********************************************

				Handler

***********************************************/

type Handler struct {
	config     *config.VerifierConfig
	ctx        *CheckContext
	reqc       *common.ReqContext
	data       *RunData
	logInScope bool
}

func NewHandler(config *config.VerifierConfig) *Handler {
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
		resp = createAdmissionResponse(false, "IntegrityVerifeir failed to decide the response for this request")
	} else if dr.isErrorOccurred() {
		resp = createAdmissionResponse(false, dr.Message)
	} else {
		resp = createAdmissionResponse(dr.isAllowed(), dr.Message)
	}

	// log results
	self.logResponse(req, resp)
	self.logContext()

	// create Event & update RSP status
	self.Report(dr.denyRSP)

	return resp
}

func (self *Handler) Check() *DecisionResult {
	var dr *DecisionResult
	dr = undeterminedDescision()

	dr = inScopeCheck(self.reqc, self.config, self.data, self.ctx)
	if !dr.isUndetermined() {
		return dr
	}

	self.logEntry()
	self.logInScope = true

	dr = formatCheck(self.reqc, self.config, self.data, self.ctx)
	if !dr.isUndetermined() {
		self.logExit()
		return dr
	}

	dr = ivResourceCheck(self.reqc, self.config, self.data, self.ctx)
	if !dr.isUndetermined() {
		self.logExit()
		return dr
	}

	dr = deleteCheck(self.reqc, self.config, self.data, self.ctx)
	if !dr.isUndetermined() {
		self.logExit()
		return dr
	}

	var matchedProfiles []rspapi.ResourceSigningProfile
	dr, matchedProfiles = protectedCheck(self.reqc, self.config, self.data, self.ctx)
	if !dr.isUndetermined() {
		self.logExit()
		return dr
	}

	for _, prof := range matchedProfiles {
		dr = resourceSigningProfileCheck(prof, self.reqc, self.config, self.data, self.ctx)
		if dr.isAllowed() {
			// this RSP allowed the request. will check next RSP.
		} else {
			// this RSP denied the request. return the result and will make AdmissionResponse.
			self.logExit()
			return dr
		}
	}

	if dr.isUndetermined() {
		dr = &DecisionResult{
			Type:       common.DecisionUndetermined,
			ReasonCode: common.REASON_UNEXPECTED,
			Message:    "IntegrityVerifier failed to decide a response for this request.",
		}
	}
	self.logExit()
	return dr
}

func (self *Handler) Report(denyRSP *rspapi.ResourceSigningProfile) error {
	// report only for denying request or for IV resource request
	if self.ctx.Allow && !self.ctx.IVResource {
		return nil
	}

	var err error
	// create/update Event
	err = createOrUpdateEvent(self.reqc, self.ctx, self.config.Namespace)
	if err != nil {
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

	runDataLoader := loader.NewLoader(self.config, reqNamespace)
	self.data.loader = runDataLoader
	self.data.Init(self.reqc, self.config.Namespace)

	// init session logger
	logger.InitSessionLogger(self.reqc.Namespace, self.reqc.Name, self.reqc.ResourceRef().ApiVersion, self.reqc.Kind, self.reqc.Operation)

	return &DecisionResult{Type: common.DecisionUndetermined}
}

func (self *Handler) overwriteDecision(dr *DecisionResult) *DecisionResult {
	signPolicy := self.data.GetSignPolicy()
	isBreakGlass := checkIfBreakGlassEnabled(self.reqc, signPolicy)
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

func (self *Handler) logEntry() {
	if self.config.ConsoleLogEnabled(self.reqc) {
		sLogger := logger.GetSessionLogger()
		sLogger.Trace("New Admission Request Received")
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
	if self.config.ConsoleLogEnabled(self.reqc) {
		sLogger := logger.GetSessionLogger()
		sLogger.WithFields(log.Fields{
			"allowed": self.ctx.Allow,
			"aborted": self.ctx.Aborted,
		}).Trace("New Admission Request Sent")
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
