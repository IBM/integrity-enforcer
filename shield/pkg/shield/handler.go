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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

/**********************************************

				Handler

***********************************************/

type Handler struct {
	config        *config.ShieldConfig
	ctx           *common.CheckContext
	reqc          *common.RequestContext
	reqobj        *common.RequestObject
	resc          *common.ResourceContext
	data          *RunData
	serverLogger  *logger.Logger
	requestLog    *log.Entry
	contextLogger *logger.ContextLogger
	logInScope    bool

	profileParameters rspapi.Parameters

	resHandler *ResourceCheckHandler
}

func NewHandler(config *config.ShieldConfig, metaLogger *logger.Logger, profileParameters rspapi.Parameters) *Handler {
	return &Handler{config: config, data: &RunData{}, serverLogger: metaLogger, profileParameters: profileParameters}
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

	// just logExit
	self.finalize(dr)

	return resp
}

func (self *Handler) Decide(req *admv1.AdmissionRequest) *common.DecisionResult {

	// init ctx, reqc and data & init logger
	self.initialize(req)

	// make DecisionResult based on reqc, config and data
	dr := self.Check()

	// overwrite DecisionResult if needed (DetectMode & BreakGlass)
	dr = self.overwriteDecision(dr)

	// log results
	self.logResponse(req, dr)
	self.logContext()

	// just logExit
	self.finalize(dr)

	return dr
}

func (self *Handler) Check() *common.DecisionResult {
	var dr *common.DecisionResult
	dr = common.UndeterminedDecision()

	// TODO: need to implement protection check based on RSP.Spec.Parameters
	// it would use `additionalProtectRules` and `manifestRef.image`

	// when this func is called, it implies that the requested resource is protected.
	// but need to check if the user of this request is ignored or not.
	dr = ignoredCheck(self.reqc, self.config, self.profileParameters, self.ctx)
	if !dr.IsUndetermined() {
		return dr
	}

	dr = mutationCheckWithSingleProfile(self.profileParameters, self.reqc, self.reqobj, self.config, self.data, self.ctx)
	if !dr.IsUndetermined() {
		return dr
	}

	var obj *unstructured.Unstructured
	_ = json.Unmarshal(self.reqobj.RawObject, &obj)
	// For the case that RawObject does not have metadata.namespace
	obj.SetNamespace(self.reqc.Namespace)

	dr = self.resHandler.Run(obj)

	if dr.IsUndetermined() {
		dr = &common.DecisionResult{
			Type:       common.DecisionUndetermined,
			ReasonCode: common.REASON_UNEXPECTED,
			Message:    "IntegrityShield failed to decide a response for this request.",
		}
	}
	return dr
}

func (self *Handler) GetCheckContext() *common.CheckContext {
	return self.ctx
}

// load resoruces / set default values
func (self *Handler) initialize(req *admv1.AdmissionRequest) *common.DecisionResult {
	gv := metav1.GroupVersion{Group: req.Kind.Group, Version: req.Kind.Version}
	self.requestLog = self.serverLogger.WithFields(
		log.Fields{
			"namespace":  req.Namespace,
			"name":       req.Name,
			"apiVersion": gv.String(),
			"kind":       req.Kind,
			"operation":  req.Operation,
			"requestUID": string(req.UID),
		},
	)

	// init CheckContext
	self.ctx = common.InitCheckContext()

	// init resource handler with shared CheckContext
	self.resHandler = NewResourceCheckHandlerWithContext(self.config, self.serverLogger, self.profileParameters, self.ctx, self.data)

	reqNamespace := ""
	if req.Kind.Kind != "Namespace" && req.Namespace != "" {
		reqNamespace = req.Namespace
	}

	// init RequestContext & RequestObject
	self.reqc, self.reqobj = common.NewRequestContext(req)

	// init ResourceContext
	self.resc = common.AdmissionRequestToResourceContext(req)

	// Note: logEntry() calls ShieldConfig.ConsoleLogEnabled() internally, and this requires ResourceContext.
	self.logEntry()
	// Note: self.logInScope is used for checking whether a log of this request should be output in context log or not
	self.logInScope = true

	runDataLoader := NewLoader(self.config, reqNamespace)
	self.data.loader = runDataLoader

	return &common.DecisionResult{Type: common.DecisionUndetermined}
}

func (self *Handler) overwriteDecision(dr *common.DecisionResult) *common.DecisionResult {
	sigConf := self.profileParameters.SignerConfig
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

func (self *Handler) finalize(dr *common.DecisionResult) {
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
		logRecord := self.ctx.ConvertToLogRecord(self.reqc, self.serverLogger)
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

func (self *Handler) logResponse(req *admv1.AdmissionRequest, dr *common.DecisionResult) {
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
