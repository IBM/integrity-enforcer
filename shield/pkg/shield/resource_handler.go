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

type ResourceHandler struct {
	config        *config.ShieldConfig
	ctx           *CheckContext
	v2resc        *common.V2ResourceContext
	data          *RunData
	serverLogger  *log.Logger
	requestLog    *log.Entry
	contextLogger *logger.ContextLogger
	logInScope    bool
}

func NewResourceHandler(config *config.ShieldConfig, metaLogger *log.Logger, reqLog *log.Entry) *ResourceHandler {
	data := &RunData{}
	data.EnableForceInitialize() // Resource Handler will load profiles on every run
	return &ResourceHandler{config: config, data: data, serverLogger: metaLogger, requestLog: reqLog}
}

func (self *ResourceHandler) Run(res *unstructured.Unstructured) *DecisionResult {

	// init ctx, reqc and data & init logger
	self.initialize(res)

	// make DecisionResult based on reqc, config and data
	dr := self.Check()

	// log results
	self.logContext()

	// reset logger
	self.finalize()

	return dr
}

func (self *ResourceHandler) Check() *DecisionResult {
	var dr *DecisionResult
	dr = undeterminedDescision()

	var matchedProfiles []rspapi.ResourceSigningProfile
	dr, matchedProfiles = protectedCheckByResource(self.v2resc, self.config, self.data, self.ctx)
	if !dr.isUndetermined() {
		return dr
	}

	for _, prof := range matchedProfiles {
		dr = resourceSigningProfileSignatureCheck(prof, self.v2resc, self.config, self.data, self.ctx)
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

// load resoruces / set default values
func (self *ResourceHandler) initialize(res *unstructured.Unstructured) *DecisionResult {

	self.ctx = InitCheckContext(self.config)

	reqNamespace := res.GetNamespace()

	// init RequestContext
	self.v2resc = common.NewV2ResourceContext(res)

	// init ResourceContext
	self.v2resc = common.NewV2ResourceContext(res)

	// Note: logEntry() calls ShieldConfig.ConsoleLogEnabled() internally, and this requires ReqContext.
	self.logEntry()

	runDataLoader := NewLoader(self.config, reqNamespace)
	self.data.loader = runDataLoader
	self.data.Init(self.config)

	return &DecisionResult{Type: common.DecisionUndetermined}
}

// reset logger context
func (self *ResourceHandler) finalize() {
	self.logExit()
}

func (self *ResourceHandler) logEntry() {
	if ok, levelStr := self.config.ConsoleLogEnabled(self.v2resc); ok {
		logger.SetSingletonLoggerLevel(levelStr) // change singleton logger level; this might be overwritten by parallel handler instance
		lvl, _ := log.ParseLevel(levelStr)
		self.serverLogger.SetLevel(lvl) // set custom log level for this request
		self.requestLog.Trace("New Admission Request Received")
	}
}

func (self *ResourceHandler) logContext() {
	if self.config.ContextLogEnabled(self.v2resc) && self.logInScope {
		self.contextLogger = logger.InitContextLogger(self.config.ContextLoggerConfig())
		logRecord := self.ctx.convertToLogRecordByResource(self.v2resc)
		logBytes, err := json.Marshal(logRecord)
		if err != nil {
			self.requestLog.Error(err)
			logBytes = []byte("")
		}
		if self.v2resc.ResourceScope == "Namespaced" || (self.v2resc.ResourceScope == "Cluster" && self.ctx.Protected) {
			self.contextLogger.SendLog(logBytes)
		}
	}
}

func (self *ResourceHandler) logExit() {
	if ok, _ := self.config.ConsoleLogEnabled(self.v2resc); ok {
		logger.SetSingletonLoggerLevel(self.config.Log.LogLevel)
		self.requestLog.WithFields(log.Fields{
			"allowed": self.ctx.Allow,
			"aborted": self.ctx.Aborted,
		}).Trace("New Admission Request Sent")
	}
}

func (self *ResourceHandler) logResponse(req *admv1.AdmissionRequest, resp *admv1.AdmissionResponse) {
	if self.config.Log.LogAllResponse {
		respData := map[string]interface{}{}
		respData["allowed"] = resp.Allowed
		respData["operation"] = req.Operation
		respData["kind"] = req.Kind
		respData["namespace"] = req.Namespace
		respData["name"] = req.Name
		respData["message"] = resp.Result.Message
		respData["patch"] = resp.Patch
		respDataBytes, err := json.Marshal(respData)
		if err != nil {
			self.requestLog.Error(err.Error())
			return
		}
		self.requestLog.Trace(fmt.Sprintf("[AdmissionResponse] %s", string(respDataBytes)))
	}
	return
}
