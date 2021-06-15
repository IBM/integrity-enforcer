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
	rspapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	logger "github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	log "github.com/sirupsen/logrus"

	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	config "github.com/IBM/integrity-enforcer/shield/pkg/config"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

/**********************************************

				Handler

***********************************************/

type ResourceCheckHandler struct {
	config            *config.ShieldConfig
	ctx               *common.CheckContext
	resc              *common.ResourceContext
	data              *RunData
	serverLogger      *logger.Logger
	resourceLog       *log.Entry
	contextLogger     *logger.ContextLogger
	logInScope        bool
	profileParameters rspapi.Parameters
}

func NewResourceCheckHandler(config *config.ShieldConfig, metaLogger *logger.Logger, profileParameters rspapi.Parameters) *ResourceCheckHandler {
	data := &RunData{}
	// if common profile is not embedded in profile parameters yet, then do it
	if !profileParameters.IsCommonProfilesEmbedded() {
		commonProfileParameters := rspapi.Parameters{
			IgnoreRules: config.CommonProfile.IgnoreRules,
			IgnoreAttrs: config.CommonProfile.IgnoreAttrs,
		}
		profileParameters = profileParameters.EmbedCommonProfiles(commonProfileParameters)
	}
	return &ResourceCheckHandler{config: config, data: data, serverLogger: metaLogger, profileParameters: profileParameters}
}

func NewResourceCheckHandlerWithContext(config *config.ShieldConfig, metaLogger *logger.Logger, profileParameters rspapi.Parameters, ctx *common.CheckContext, data *RunData) *ResourceCheckHandler {
	resHandler := NewResourceCheckHandler(config, metaLogger, profileParameters)
	resHandler.ctx = ctx
	resHandler.data = data
	return resHandler
}

func (self *ResourceCheckHandler) Run(res *unstructured.Unstructured) *common.DecisionResult {

	// init ctx, resc and data & init logger
	self.initialize(res)

	// make DecisionResult based on reqc, config and data
	dr := self.Check()

	// reset logger
	self.finalize()

	return dr
}

func (self *ResourceCheckHandler) GetCheckContext() *common.CheckContext {
	return self.ctx
}

func (self *ResourceCheckHandler) Check() *common.DecisionResult {
	var dr *common.DecisionResult
	dr = common.UndeterminedDecision()

	// TODO: implement imageRef protect matching
	// check if this resource is protected by additionalProtectRules or imageRef manifest in profileParameters
	dr = protectCheckWithResource(self.resc, self.config, self.profileParameters, self.ctx)
	if !dr.IsUndetermined() {
		return dr
	}

	// check if this resource is ignored by ignore rules in profileParameters
	dr = ignoredCheckWithResource(self.resc, self.config, self.profileParameters, self.ctx)
	if !dr.IsUndetermined() {
		return dr
	}

	dr = signatureCheckWithSingleProfile(self.profileParameters, self.resc, self.config, self.data, self.ctx)
	if dr.IsAllowed() {
		// this RSP allowed the resource. will check next RSP.
	} else {
		// this RSP denied the resource. return the result.
		return dr
	}

	resourceDecisionResult := dr
	resourceSigOk := resourceDecisionResult.IsAllowed()

	// if image verification is enabled, check the image siganture here if needed.
	// At the end of this verification, override the result only when resource is ok & image is ng.
	if self.config.ImageVerificationEnabled() {
		// TODO: support pgp/x509 image signature
		if self.config.SigStoreEnabled() {
			self.resourceLog.Trace("ImageVerificationEnabled")
			imageDecisionResult := self.ImageCheck()
			self.resourceLog.Trace("image check result: ", imageDecisionResult)
			imageDenied := imageDecisionResult.IsDenied() || imageDecisionResult.IsErrorOccurred()

			// overwride existing DecisionResult only when resource siganature is allowed & image is denied
			if resourceSigOk && imageDenied {
				dr = imageDecisionResult
			}
		}
	}

	if dr.IsUndetermined() {
		dr = &common.DecisionResult{
			Type:       common.DecisionUndetermined,
			ReasonCode: common.REASON_UNEXPECTED,
			Message:    "IntegrityShield failed to decide a response for this resource.",
		}
	}
	return dr
}

// image
func (self *ResourceCheckHandler) ImageCheck() *common.DecisionResult {
	idr := common.UndeterminedDecision()
	needSigCheck, imageToVerify, _ := requestCheckForImageCheck(self.resc)
	if !needSigCheck {
		return idr
	}
	imageToVerify.imageSignatureCheck()
	imageToVerify.imageVerifiedResultCheckByProfile()
	idr = makeImageCheckResult(imageToVerify)
	return idr
}

// load resoruces / set default values
func (self *ResourceCheckHandler) initialize(res *unstructured.Unstructured) *common.DecisionResult {
	self.resourceLog = self.serverLogger.WithFields(
		log.Fields{
			"namespace":  res.GetNamespace(),
			"name":       res.GetName(),
			"apiVersion": res.GetAPIVersion(),
			"kind":       res.GetKind(),
		},
	)

	if self.ctx == nil {
		self.ctx = common.InitCheckContext()
	}

	reqNamespace := res.GetNamespace()

	// init ResourceContext
	self.resc = common.NewResourceContext(res)

	// Note: logEntry() calls ShieldConfig.ConsoleLogEnabled() internally, and this requires ResourceContext.
	self.logEntry()

	if self.data.loader == nil {
		runDataLoader := NewLoader(self.config, reqNamespace)
		self.data.loader = runDataLoader
	}

	return &common.DecisionResult{Type: common.DecisionUndetermined}
}

// reset logger context
func (self *ResourceCheckHandler) finalize() {
	self.logExit()
}

func (self *ResourceCheckHandler) logEntry() {
	if ok, levelStr := self.config.ConsoleLogEnabled(self.resc); ok {
		logger.SetSingletonLoggerLevel(levelStr) // change singleton logger level; this might be overwritten by parallel handler instance
		lvl, _ := log.ParseLevel(levelStr)
		self.serverLogger.SetLevel(lvl) // set custom log level for this resource
		self.resourceLog.Trace("New Resource Check Request Received")
	}
}

// func (self *ResourceCheckHandler) logContext() {
// 	if self.config.ContextLogEnabled(self.resc) && self.logInScope {
// 		self.contextLogger = logger.InitContextLogger(self.config.ContextLoggerConfig())
// 		logRecord := self.ctx.convertToLogRecordByResource(self.resc, self.resourceLog)
// 		logBytes, err := json.Marshal(logRecord)
// 		if err != nil {
// 			self.resourceLog.Error(err)
// 			logBytes = []byte("")
// 		}
// 		if self.resc.ResourceScope == "Namespaced" || (self.resc.ResourceScope == "Cluster" && self.ctx.Protected) {
// 			self.contextLogger.SendLog(logBytes)
// 		}
// 	}
// }

func (self *ResourceCheckHandler) logExit() {
	if ok, _ := self.config.ConsoleLogEnabled(self.resc); ok {
		logger.SetSingletonLoggerLevel(self.config.Log.LogLevel)
		self.resourceLog.WithFields(log.Fields{
			"allowed": self.ctx.Allow,
			"aborted": self.ctx.Aborted,
		}).Trace("New Resource Check Request Sent")
	}
}
