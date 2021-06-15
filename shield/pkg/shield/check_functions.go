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
	"strings"

	rspapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"

	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	config "github.com/IBM/integrity-enforcer/shield/pkg/config"
)

func protectCheck(reqc *common.RequestContext, config *config.ShieldConfig, profileParameters rspapi.Parameters, ctx *common.CheckContext) *common.DecisionResult {
	reqFields := reqc.Map()
	protectMatched, _ := profileParameters.ProtectMatch(reqFields)

	if !protectMatched {
		ctx.Allow = true
		ctx.Verified = true
		ctx.Protected = false
		ctx.ReasonCode = common.REASON_NOT_PROTECTED
		ctx.Message = common.ReasonCodeMap[common.REASON_NOT_PROTECTED].Message
		return &common.DecisionResult{
			Type:       common.DecisionAllow,
			ReasonCode: common.REASON_NOT_PROTECTED,
			Message:    common.ReasonCodeMap[common.REASON_NOT_PROTECTED].Message,
		}
	} else {
		ctx.Protected = true
	}
	return common.UndeterminedDecision()
}

func protectCheckWithResource(resc *common.ResourceContext, config *config.ShieldConfig, profileParameters rspapi.Parameters, ctx *common.CheckContext) *common.DecisionResult {
	reqFields := resc.Map()
	protectMatched, _ := profileParameters.ProtectMatch(reqFields)

	if !protectMatched {
		ctx.Allow = true
		ctx.Verified = true
		ctx.Protected = false
		ctx.ReasonCode = common.REASON_NOT_PROTECTED
		ctx.Message = common.ReasonCodeMap[common.REASON_NOT_PROTECTED].Message
		return &common.DecisionResult{
			Type:       common.DecisionAllow,
			ReasonCode: common.REASON_NOT_PROTECTED,
			Message:    common.ReasonCodeMap[common.REASON_NOT_PROTECTED].Message,
		}
	} else {
		ctx.Protected = true
	}
	return common.UndeterminedDecision()
}

func ignoredCheck(reqc *common.RequestContext, config *config.ShieldConfig, profileParameters rspapi.Parameters, ctx *common.CheckContext) *common.DecisionResult {
	reqFields := reqc.Map()
	ignoreMatched, _ := profileParameters.IgnoreMatch(reqFields)

	if ignoreMatched {
		ctx.Allow = true
		ctx.Verified = true
		ctx.Protected = false
		ctx.ReasonCode = common.REASON_IGNORE_RULE_MATCHED
		ctx.Message = common.ReasonCodeMap[common.REASON_IGNORE_RULE_MATCHED].Message
		return &common.DecisionResult{
			Type:       common.DecisionAllow,
			ReasonCode: common.REASON_IGNORE_RULE_MATCHED,
			Message:    common.ReasonCodeMap[common.REASON_IGNORE_RULE_MATCHED].Message,
		}
	} else {
		ctx.Protected = true
	}
	return common.UndeterminedDecision()
}

func ignoredCheckWithResource(resc *common.ResourceContext, config *config.ShieldConfig, profileParameters rspapi.Parameters, ctx *common.CheckContext) *common.DecisionResult {
	reqFields := resc.Map()
	ignoreMatched, _ := profileParameters.IgnoreMatch(reqFields)

	if ignoreMatched {
		ctx.Allow = true
		ctx.Verified = true
		ctx.Protected = false
		ctx.ReasonCode = common.REASON_IGNORE_RULE_MATCHED
		ctx.Message = common.ReasonCodeMap[common.REASON_IGNORE_RULE_MATCHED].Message
		return &common.DecisionResult{
			Type:       common.DecisionAllow,
			ReasonCode: common.REASON_IGNORE_RULE_MATCHED,
			Message:    common.ReasonCodeMap[common.REASON_IGNORE_RULE_MATCHED].Message,
		}
	} else {
		ctx.Protected = true
	}
	return common.UndeterminedDecision()
}

func mutationCheckWithSingleProfile(profileParameters rspapi.Parameters, reqc *common.RequestContext, reqobj *common.RequestObject, config *config.ShieldConfig, data *RunData, ctx *common.CheckContext) *common.DecisionResult {
	var allowed bool
	var evalMessage string
	var evalReason int
	var mutResult *common.MutationEvalResult
	var err error

	if reqc.IsUpdateRequest() {
		mutResult, err = NewMutationChecker().Eval(reqc, reqobj, profileParameters)
		if err != nil {
			allowed = false
			evalMessage = err.Error()
			evalReason = common.REASON_ERROR
		}
		if mutResult.Checked && !mutResult.IsMutated {
			allowed = true
			evalMessage = common.ReasonCodeMap[common.REASON_NO_MUTATION].Message
			evalReason = common.REASON_NO_MUTATION
		}
	}

	ctx.Allow = allowed
	ctx.ReasonCode = evalReason
	ctx.Message = evalMessage
	if mutResult != nil {
		ctx.MutationEvalResult = mutResult
	}

	if allowed {
		ctx.Verified = true
		return &common.DecisionResult{
			Type:       common.DecisionAllow,
			Verified:   true,
			ReasonCode: evalReason,
			Message:    evalMessage,
		}
	} else {
		// return undetermined DecisionResult to trigger resource checker
		return common.UndeterminedDecision()
	}
}

func signatureCheckWithSingleProfile(profileParameters rspapi.Parameters, resc *common.ResourceContext, config *config.ShieldConfig, data *RunData, ctx *common.CheckContext) *common.DecisionResult {
	var allowed bool
	var evalMessage string
	var evalReason int
	var sigResult *common.SignatureEvalResult

	rsigList := data.GetResSigList(resc)

	var err error

	plugins := config.GetEnabledPlugins()
	evaluator, err := NewSignatureEvaluator(config, profileParameters, plugins)
	if err != nil {
		allowed = false
		evalMessage = err.Error()
		evalReason = common.REASON_ERROR
	} else {
		sigResult, err = evaluator.Eval(resc, rsigList)
		if err != nil {
			allowed = false
			evalMessage = err.Error()
			evalReason = common.REASON_ERROR
		} else if sigResult.Checked && sigResult.Allow {
			allowed = true
			evalMessage = common.ReasonCodeMap[common.REASON_VALID_SIG].Message
			evalReason = common.REASON_VALID_SIG
		} else if sigResult.Error != nil {
			var reasonCode int
			var message string
			message = sigResult.Error.MakeMessage()
			if strings.HasPrefix(message, common.ReasonCodeMap[common.REASON_INVALID_SIG].Message) {
				reasonCode = common.REASON_INVALID_SIG
			} else if strings.HasPrefix(message, common.ReasonCodeMap[common.REASON_NO_VALID_KEYRING].Message) {
				reasonCode = common.REASON_NO_VALID_KEYRING
			} else if strings.HasPrefix(message, common.ReasonCodeMap[common.REASON_NO_MATCH_SIGNER_CONFIG].Message) {
				reasonCode = common.REASON_NO_MATCH_SIGNER_CONFIG
			} else if message == common.ReasonCodeMap[common.REASON_NO_SIG].Message {
				reasonCode = common.REASON_NO_SIG
			} else {
				reasonCode = common.REASON_ERROR
			}
			allowed = false
			evalMessage = message
			evalReason = reasonCode
		}
	}

	ctx.Allow = allowed
	ctx.ReasonCode = evalReason
	ctx.Message = evalMessage
	if sigResult != nil {
		ctx.SignatureEvalResult = sigResult
	}

	if allowed {
		ctx.Verified = true
		return &common.DecisionResult{
			Type:       common.DecisionAllow,
			Verified:   true,
			ReasonCode: evalReason,
			Message:    evalMessage,
		}
	} else {
		return &common.DecisionResult{
			Type:       common.DecisionDeny,
			ReasonCode: evalReason,
			Message:    evalMessage,
		}
	}
}
