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
	"strconv"
	"time"

	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	config "github.com/IBM/integrity-enforcer/shield/pkg/config"
)

/**********************************************

				CheckContext

***********************************************/

type CheckContext struct {
	DetectOnlyModeEnabled bool   `json:"detectOnly"`
	BreakGlassModeEnabled bool   `json:"breakGlass"`
	IgnoredSA             bool   `json:"ignoredSA"`
	Protected             bool   `json:"protected"`
	IShieldResource       bool   `json:"iShieldResource"`
	Allow                 bool   `json:"allow"`
	Verified              bool   `json:"verified"`
	Aborted               bool   `json:"aborted"`
	AbortReason           string `json:"abortReason"`
	Error                 error  `json:"error"`
	Message               string `json:"msg"`

	SignatureEvalResult *common.SignatureEvalResult `json:"signature"`
	MutationEvalResult  *common.MutationEvalResult  `json:"mutation"`

	ReasonCode int `json:"reasonCode"`
}

func InitCheckContext(config *config.ShieldConfig) *CheckContext {
	cc := &CheckContext{
		IgnoredSA: false,
		Protected: false,
		Aborted:   false,
		Allow:     false,
		Verified:  false,
		SignatureEvalResult: &common.SignatureEvalResult{
			Allow:   false,
			Checked: false,
		},
		MutationEvalResult: &common.MutationEvalResult{
			IsMutated: false,
			Checked:   false,
		},
	}
	return cc
}

func (self *CheckContext) convertToLogRecord(vreqc *common.VRequestContext) map[string]interface{} {

	// cc := self
	logRecord := map[string]interface{}{
		// request context
		"namespace":  vreqc.Namespace,
		"name":       vreqc.Name,
		"apiGroup":   vreqc.ApiGroup,
		"apiVersion": vreqc.ApiVersion,
		"kind":       vreqc.Kind,
		"operation":  vreqc.Operation,
		"userInfo":   vreqc.UserInfo,
		// "objLabels":    vreqc.ObjLabels,
		// "objMetaName":  vreqc.ObjMetaName,
		"userName":     vreqc.UserName,
		"request.uid":  vreqc.RequestUid,
		"type":         vreqc.Type,
		"request.dump": "",
		"requestScope": vreqc.ResourceScope,

		//context
		"ignoreSA":        self.IgnoredSA,
		"protected":       self.Protected,
		"iShieldResource": self.IShieldResource,
		"allowed":         self.Allow,
		"verified":        self.Verified,
		"aborted":         self.Aborted,
		"abortReason":     self.AbortReason,
		"msg":             self.Message,
		"breakglass":      self.BreakGlassModeEnabled,
		"detectOnly":      self.DetectOnlyModeEnabled,

		//reason code
		"reasonCode": common.ReasonCodeMap[self.ReasonCode].Code,
	}

	if self.Error != nil {
		logRecord["error"] = self.Error.Error()
	}

	//context from sign policy eval
	if self.SignatureEvalResult != nil {
		r := self.SignatureEvalResult
		if r.Signer != nil {
			logRecord["sig.signer.email"] = r.Signer.Email
			logRecord["sig.signer.name"] = r.Signer.Name
			logRecord["sig.signer.comment"] = r.Signer.Comment
			logRecord["sig.signer.fingerprint"] = r.Signer.Fingerprint
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

	//context from mutation eval
	if self.MutationEvalResult != nil {
		r := self.MutationEvalResult
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

	// logRecord["request.objectHashType"] = vreqc.ObjectHashType
	// logRecord["request.objectHash"] = vreqc.ObjectHash

	// logRecord["sessionTrace"] = logger.GetSessionTraceString()

	currentTime := time.Now()
	ts := currentTime.Format("2006-01-02T15:04:05.000Z")

	logRecord["timestamp"] = ts

	return logRecord

}

func (self *CheckContext) convertToLogRecordByResource(v2resc *common.V2ResourceContext) map[string]interface{} {

	// cc := self
	logRecord := map[string]interface{}{
		// request context
		"namespace":    v2resc.Namespace,
		"name":         v2resc.Name,
		"apiGroup":     v2resc.ApiGroup,
		"apiVersion":   v2resc.ApiVersion,
		"kind":         v2resc.Kind,
		"objLabels":    v2resc.ObjLabels,
		"objMetaName":  v2resc.ObjMetaName,
		"request.dump": "",
		"requestScope": v2resc.ResourceScope,

		//context
		"ignoreSA":        self.IgnoredSA,
		"protected":       self.Protected,
		"iShieldResource": self.IShieldResource,
		"allowed":         self.Allow,
		"verified":        self.Verified,
		"aborted":         self.Aborted,
		"abortReason":     self.AbortReason,
		"msg":             self.Message,
		"breakglass":      self.BreakGlassModeEnabled,
		"detectOnly":      self.DetectOnlyModeEnabled,

		//reason code
		"reasonCode": common.ReasonCodeMap[self.ReasonCode].Code,
	}

	if self.Error != nil {
		logRecord["error"] = self.Error.Error()
	}

	//context from sign policy eval
	if self.SignatureEvalResult != nil {
		r := self.SignatureEvalResult
		if r.Signer != nil {
			logRecord["sig.signer.email"] = r.Signer.Email
			logRecord["sig.signer.name"] = r.Signer.Name
			logRecord["sig.signer.comment"] = r.Signer.Comment
			logRecord["sig.signer.fingerprint"] = r.Signer.Fingerprint
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

	//context from mutation eval
	if self.MutationEvalResult != nil {
		r := self.MutationEvalResult
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

	// logRecord["sessionTrace"] = logger.GetSessionTraceString()

	currentTime := time.Now()
	ts := currentTime.Format("2006-01-02T15:04:05.000Z")

	logRecord["timestamp"] = ts

	return logRecord

}
