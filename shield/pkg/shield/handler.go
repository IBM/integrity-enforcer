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
	config "github.com/IBM/integrity-enforcer/shield/pkg/config"
	admv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

/**********************************************

				Handler

***********************************************/

type Handler struct {
	config        *config.ShieldConfig
	ctx           *CheckContext
	reqc          *common.RequestContext
	reqobj        *common.RequestObject
	resc          *common.ResourceContext
	data          *RunData
	serverLogger  *log.Logger
	requestLog    *log.Entry
	contextLogger *logger.ContextLogger
	logInScope    bool

	resHandler *ResourceCheckHandler
}

func NewHandler(config *config.ShieldConfig, metaLogger *log.Logger, reqLog *log.Entry) *Handler {
	return &Handler{config: config, data: &RunData{}, serverLogger: metaLogger, requestLog: reqLog}
}

func (self *Handler) Run(req *admv1.AdmissionRequest) *admv1.AdmissionResponse {

	// init ctx, reqc and data & init logger
	self.initialize(req)

	// make DecisionResult based on reqc, config and data
	dr := self.Check()

	// overwrite DecisionResult if needed (DetectMode & BreakGlass)
	dr = self.overwriteDecision(dr)

	// make AdmissionResponse based on DecisionResult
	resp := &admv1.AdmissionResponse{}

	if dr.IsUndetermined() {
		resp = createAdmissionResponse(false, "IntegrityShield failed to decide the response for this request", self.reqc, self.reqobj, self.ctx, self.config)
	} else if dr.IsErrorOccurred() {
		resp = createAdmissionResponse(false, dr.Message, self.reqc, self.reqobj, self.ctx, self.config)
	} else {
		resp = createAdmissionResponse(dr.IsAllowed(), dr.Message, self.reqc, self.reqobj, self.ctx, self.config)
	}

	// log results
	self.logResponse(req, dr)
	self.logContext()

	// create Event & update RSP status
	_ = self.Report(dr.denyRSP)

	// clear some cache if needed
	self.finalize(dr)

	return resp
}

func (self *Handler) Check() *DecisionResult {
	var dr *DecisionResult
	dr = undeterminedDescision()

	dr = inScopeCheck(self.reqc, self.config, self.data, self.ctx)
	if !dr.IsUndetermined() {
		return dr
	}
	self.logInScope = true

	dr = formatCheck(self.reqc, self.reqobj, self.config, self.data, self.ctx)
	if !dr.IsUndetermined() {

		return dr
	}

	dr = iShieldResourceCheck(self.reqc, self.config, self.data, self.ctx)
	if !dr.IsUndetermined() {
		return dr
	}

	dr = deleteCheck(self.reqc, self.config, self.data, self.ctx)
	if !dr.IsUndetermined() {
		return dr
	}

	var matchedProfiles []rspapi.ResourceSigningProfile
	dr, matchedProfiles = protectedCheck(self.reqc, self.config, self.data, self.ctx)
	if !dr.IsUndetermined() {
		return dr
	}

	dr = mutationCheck(matchedProfiles, self.reqc, self.reqobj, self.config, self.data, self.ctx)
	if !dr.IsUndetermined() {
		return dr
	}

	var obj *unstructured.Unstructured
	_ = json.Unmarshal(self.reqobj.RawObject, &obj)
	// For the case that RawObject does not have metadata.namespace
	obj.SetNamespace(self.reqc.Namespace)

	dr = self.resHandler.Run(obj)

	if dr.IsUndetermined() {
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
	if !self.ctx.Allow && self.config.SideEffect.CreateDenyEventEnabled() {
		shouldReport = true
	}
	iShieldAdmin := checkIfIShieldAdminRequest(self.reqc, self.config)
	if self.ctx.IShieldResource && !iShieldAdmin && self.config.SideEffect.CreateIShieldResourceEventEnabled() {
		shouldReport = true
	}

	if !shouldReport {
		return nil
	}

	var err error
	// create/update Event
	if self.config.SideEffect.CreateEventEnabled() {
		err = createOrUpdateEvent(self.reqc, self.ctx, self.config, denyRSP)
		if err != nil {
			self.requestLog.Error("Failed to create event; ", err)
			return err
		}
	}

	// update RSP status
	if self.config.SideEffect.UpdateRSPStatusEnabled() {
		err = updateRSPStatus(denyRSP, self.reqc, self.ctx.Message)
		if err != nil {
			self.requestLog.Error("Failed to update status; ", err)
		}
	}

	return nil
}

// load resoruces / set default values
func (self *Handler) initialize(req *admv1.AdmissionRequest) *DecisionResult {

	// init CheckContext
	self.ctx = InitCheckContext(self.config)

	// init resource handler with shared CheckContext
	self.resHandler = NewResourceCheckHandlerWithContext(self.config, self.serverLogger, self.requestLog, self.ctx, self.data)

	reqNamespace := getRequestNamespace(req)

	// init RequestContext & RequestObject
	self.reqc, self.reqobj = common.NewRequestContext(req)

	// init ResourceContext
	self.resc = common.AdmissionRequestToResourceContext(req)

	// Note: logEntry() calls ShieldConfig.ConsoleLogEnabled() internally, and this requires ResourceContext.
	self.logEntry()

	runDataLoader := NewLoader(self.config, reqNamespace)
	self.data.loader = runDataLoader
	self.data.Init(self.config)

	return &DecisionResult{Type: common.DecisionUndetermined}
}

func (self *Handler) overwriteDecision(dr *DecisionResult) *DecisionResult {
	sigConf := self.data.GetSignerConfig()
	isBreakGlass := checkIfBreakGlassEnabled(self.reqc, sigConf)
	isDetectMode := checkIfDetectOnly(self.config)

	if !isBreakGlass && !isDetectMode {
		return dr
	}

	if !dr.IsAllowed() && isDetectMode {
		self.ctx.Allow = true
		self.ctx.DetectOnlyModeEnabled = true
		self.ctx.ReasonCode = common.REASON_DETECTION
		self.ctx.Message = common.ReasonCodeMap[common.REASON_DETECTION].Message
		dr.Type = common.DecisionAllow
		dr.Verified = false
		dr.Message = common.ReasonCodeMap[common.REASON_DETECTION].Message
		dr.ReasonCode = common.REASON_DETECTION
	} else if !dr.IsAllowed() && isBreakGlass {
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

func (self *Handler) finalize(dr *DecisionResult) {
	if dr.IsAllowed() {
		resetRuleTableCache := false
		iShieldServer := checkIfIShieldServerRequest(self.reqc, self.config)
		iShieldOperator := checkIfIShieldOperatorRequest(self.reqc, self.config)
		if self.reqc.Kind == "Namespace" {
			if self.reqc.IsUpdateRequest() {
				mtResult, _ := MutationCheck(self.reqc, self.reqobj)
				if mtResult != nil && mtResult.IsMutated {
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
	return
}

func (self *Handler) logEntry() {
	if ok, levelStr := self.config.ConsoleLogEnabled(self.resc); ok {
		logger.SetSingletonLoggerLevel(levelStr) // change singleton logger level; this might be overwritten by parallel handler instance
		lvl, _ := log.ParseLevel(levelStr)
		self.serverLogger.SetLevel(lvl) // set custom log level for this request
		self.requestLog.Trace("New Admission Request Received")
	}
}

func (self *Handler) logContext() {
	if self.config.ContextLogEnabled(self.resc) && self.logInScope {
		self.contextLogger = logger.InitContextLogger(self.config.ContextLoggerConfig())
		logRecord := self.ctx.convertToLogRecord(self.reqc)
		if self.config.Log.IncludeRequest && !self.reqc.IsSecret() {
			logRecord["request.dump"] = self.reqc.RequestJsonStr
		}
		logBytes, err := json.Marshal(logRecord)
		if err != nil {
			self.requestLog.Error(err)
			logBytes = []byte("")
		}
		if self.reqc.ResourceScope == "Namespaced" || (self.reqc.ResourceScope == "Cluster" && self.ctx.Protected) {
			self.contextLogger.SendLog(logBytes)
		}
	}
}

func (self *Handler) logExit() {
	if ok, _ := self.config.ConsoleLogEnabled(self.resc); ok {
		logger.SetSingletonLoggerLevel(self.config.Log.LogLevel)
		self.requestLog.WithFields(log.Fields{
			"allowed":    self.ctx.Allow,
			"aborted":    self.ctx.Aborted,
			"requestUID": self.reqc.RequestUid,
		}).Trace("New Admission Request Sent")
	}
}

func (self *Handler) logResponse(req *admv1.AdmissionRequest, dr *DecisionResult) {
	if self.config.Log.LogAllResponse {
		respData := map[string]interface{}{}
		respData["allowed"] = dr.IsAllowed()
		respData["operation"] = req.Operation
		respData["kind"] = req.Kind
		respData["namespace"] = req.Namespace
		respData["name"] = req.Name
		respData["message"] = dr.Message
		// respData["patch"] = resp.Patch
		respDataBytes, err := json.Marshal(respData)
		if err != nil {
			self.requestLog.Error(err.Error())
			return
		}
		self.requestLog.Trace(fmt.Sprintf("[AdmissionResponse] %s", string(respDataBytes)))
	}
	return
}
