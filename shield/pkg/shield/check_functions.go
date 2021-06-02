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

// check if request is ishieldScope or not
func ishieldScopeCheck(reqc *common.RequestContext, config *config.ShieldConfig, data *RunData, ctx *CheckContext) *common.DecisionResult {
	reqNamespace := getRequestNamespaceFromRequestContext(reqc)

	// check if reqNamespace matches ShieldConfig.MonitoringNamespace and check if any RSP is targeting the namespace
	// this check is done only for Namespaced request, and skip this for Cluster-scope request
	if reqNamespace != "" && !checkIfIshieldScopeNamespace(reqNamespace, config) && !checkIfProfileTargetNamespace(reqNamespace, config.Namespace, data) {
		msg := "this namespace is not monitored"
		ctx.Allow = true
		ctx.ReasonCode = common.REASON_INTERNAL
		ctx.Message = msg
		return &common.DecisionResult{
			Type:       common.DecisionAllow,
			ReasonCode: common.REASON_INTERNAL,
			Message:    msg,
		}
	}

	if checkIfDryRunAdmission(reqc) {
		msg := "request is dry run"
		ctx.Allow = true
		ctx.ReasonCode = common.REASON_INTERNAL
		ctx.Message = msg
		return &common.DecisionResult{
			Type:       common.DecisionAllow,
			ReasonCode: common.REASON_INTERNAL,
			Message:    msg,
		}
	}

	if checkIfUnprocessedInIShield(reqc.Map(), config) {
		msg := "request is not processed by IShield"
		ctx.Allow = true
		ctx.ReasonCode = common.REASON_INTERNAL
		ctx.Message = msg
		return &common.DecisionResult{
			Type:       common.DecisionAllow,
			ReasonCode: common.REASON_INTERNAL,
			Message:    msg,
		}
	}

	return common.UndeterminedDecision()
}

// check if resource is ishieldScope or not
func ishieldScopeCheckByResource(resc *common.ResourceContext, config *config.ShieldConfig, data *RunData, ctx *CheckContext) *common.DecisionResult {
	resNamespace := getRequestNamespaceFromResourceContext(resc)

	// check if resNamespace matches ShieldConfig.MonitoringNamespace and check if any RSP is targeting the namespace
	// this check is done only for Namespaced request, and skip this for Cluster-scope request
	if resNamespace != "" && !checkIfIshieldScopeNamespace(resNamespace, config) && !checkIfProfileTargetNamespace(resNamespace, config.Namespace, data) {
		msg := "this namespace is not monitored"
		ctx.Allow = true
		ctx.ReasonCode = common.REASON_INTERNAL
		ctx.Message = msg
		return &common.DecisionResult{
			Type:       common.DecisionAllow,
			ReasonCode: common.REASON_INTERNAL,
			Message:    msg,
		}
	}

	if checkIfUnprocessedInIShield(resc.Map(), config) {
		msg := "request is not processed by IShield"
		ctx.Allow = true
		ctx.ReasonCode = common.REASON_INTERNAL
		ctx.Message = msg
		return &common.DecisionResult{
			Type:       common.DecisionAllow,
			ReasonCode: common.REASON_INTERNAL,
			Message:    msg,
		}
	}

	return common.UndeterminedDecision()
}

func formatCheck(reqc *common.RequestContext, reqobj *common.RequestObject, config *config.ShieldConfig, data *RunData, ctx *CheckContext) *common.DecisionResult {
	if ok, msg := ValidateResource(reqc, reqobj, config.Namespace); !ok {
		ctx.Allow = false
		ctx.ReasonCode = common.REASON_VALIDATION_FAIL
		ctx.Message = msg
		return &common.DecisionResult{
			Type:       common.DecisionDeny,
			ReasonCode: common.REASON_VALIDATION_FAIL,
			Message:    msg,
		}
	}
	return common.UndeterminedDecision()
}

func iShieldResourceCheck(reqc *common.RequestContext, config *config.ShieldConfig, data *RunData, ctx *CheckContext) *common.DecisionResult {
	reqRef := reqc.ResourceRef()
	iShieldOperatorResource := config.IShieldResourceCondition.IsOperatorResource(reqRef)
	iShieldServerResource := config.IShieldResourceCondition.IsServerResource(reqRef)

	if !iShieldOperatorResource && !iShieldServerResource {
		return common.UndeterminedDecision()
	} else {
		ctx.IShieldResource = true
	}

	adminReq := checkIfIShieldAdminRequest(reqc, config)
	serverReq := checkIfIShieldServerRequest(reqc, config)
	operatorReq := checkIfIShieldOperatorRequest(reqc, config)
	gcReq := checkIfGarbageCollectorRequest(reqc)
	spSAReq := checkIfSpecialServiceAccountRequest(reqc) && (reqc.Kind != "ClusterServiceVersion")

	if (iShieldOperatorResource && (adminReq || operatorReq || gcReq || spSAReq)) || (iShieldServerResource && (operatorReq || serverReq || gcReq || spSAReq)) {
		ctx.Allow = true
		ctx.Verified = true
		ctx.ReasonCode = common.REASON_ISHIELD_ADMIN
		ctx.Message = common.ReasonCodeMap[common.REASON_ISHIELD_ADMIN].Message
		return &common.DecisionResult{
			Type:       common.DecisionAllow,
			Verified:   true,
			ReasonCode: common.REASON_ISHIELD_ADMIN,
			Message:    common.ReasonCodeMap[common.REASON_ISHIELD_ADMIN].Message,
		}
	} else {
		ctx.Allow = false
		ctx.Verified = false
		ctx.ReasonCode = common.REASON_BLOCK_ISHIELD_RESOURCE_OPERATION
		ctx.Message = common.ReasonCodeMap[common.REASON_BLOCK_ISHIELD_RESOURCE_OPERATION].Message
		return &common.DecisionResult{
			Type:       common.DecisionDeny,
			Verified:   false,
			ReasonCode: common.REASON_BLOCK_ISHIELD_RESOURCE_OPERATION,
			Message:    common.ReasonCodeMap[common.REASON_BLOCK_ISHIELD_RESOURCE_OPERATION].Message,
		}
	}
}

func deleteCheck(reqc *common.RequestContext, config *config.ShieldConfig, data *RunData, ctx *CheckContext) *common.DecisionResult {
	if reqc.IsDeleteRequest() {
		ctx.Allow = true
		ctx.Verified = true
		ctx.ReasonCode = common.REASON_SKIP_DELETE
		ctx.Message = common.ReasonCodeMap[common.REASON_SKIP_DELETE].Message
		return &common.DecisionResult{
			Type:       common.DecisionAllow,
			Verified:   true,
			ReasonCode: common.REASON_SKIP_DELETE,
			Message:    common.ReasonCodeMap[common.REASON_SKIP_DELETE].Message,
		}
	}
	return common.UndeterminedDecision()
}

func protectedCheck(reqc *common.RequestContext, config *config.ShieldConfig, profile rspapi.ResourceSigningProfile, ctx *CheckContext) *common.DecisionResult {
	reqFields := reqc.Map()
	protected, matchedRule := profile.Match(reqFields, config.Namespace)
	ignoreMatched := false
	if !protected && matchedRule != nil {
		ignoreMatched = true
	}

	if !protected {
		ctx.Allow = true
		ctx.Verified = true
		ctx.Protected = false
		if ignoreMatched {
			ctx.ReasonCode = common.REASON_IGNORE_RULE_MATCHED
			ctx.Message = common.ReasonCodeMap[common.REASON_IGNORE_RULE_MATCHED].Message
			return &common.DecisionResult{
				Type:       common.DecisionAllow,
				ReasonCode: common.REASON_IGNORE_RULE_MATCHED,
				Message:    common.ReasonCodeMap[common.REASON_IGNORE_RULE_MATCHED].Message,
			}
		} else {
			ctx.ReasonCode = common.REASON_NOT_PROTECTED
			ctx.Message = common.ReasonCodeMap[common.REASON_NOT_PROTECTED].Message
			return &common.DecisionResult{
				Type:       common.DecisionAllow,
				ReasonCode: common.REASON_NOT_PROTECTED,
				Message:    common.ReasonCodeMap[common.REASON_NOT_PROTECTED].Message,
			}
		}
	} else {
		ctx.Protected = true
	}
	return common.UndeterminedDecision()
}

func protectedCheckByResource(resc *common.ResourceContext, config *config.ShieldConfig, data *RunData, ctx *CheckContext) (*common.DecisionResult, []rspapi.ResourceSigningProfile) {
	reqFields := resc.Map()

	ruleTable := data.GetRuleTable(config.Namespace)
	if ruleTable == nil {
		ctx.Allow = true
		ctx.Verified = true
		ctx.Protected = false
		ctx.ReasonCode = common.REASON_NOT_PROTECTED
		ctx.Message = common.ReasonCodeMap[common.REASON_NOT_PROTECTED].Message
		return &common.DecisionResult{
			Type:       common.DecisionAllow,
			ReasonCode: common.REASON_NOT_PROTECTED,
			Message:    common.ReasonCodeMap[common.REASON_NOT_PROTECTED].Message,
		}, nil
	}
	protected, ignoreMatched, matchedProfiles := ruleTable.CheckIfProtected(reqFields)
	if !protected {
		ctx.Allow = true
		ctx.Verified = true
		ctx.Protected = false
		if ignoreMatched {
			ctx.ReasonCode = common.REASON_IGNORE_RULE_MATCHED
			ctx.Message = common.ReasonCodeMap[common.REASON_IGNORE_RULE_MATCHED].Message
			return &common.DecisionResult{
				Type:       common.DecisionAllow,
				ReasonCode: common.REASON_IGNORE_RULE_MATCHED,
				Message:    common.ReasonCodeMap[common.REASON_IGNORE_RULE_MATCHED].Message,
			}, nil
		} else {
			ctx.ReasonCode = common.REASON_NOT_PROTECTED
			ctx.Message = common.ReasonCodeMap[common.REASON_NOT_PROTECTED].Message
			return &common.DecisionResult{
				Type:       common.DecisionAllow,
				ReasonCode: common.REASON_NOT_PROTECTED,
				Message:    common.ReasonCodeMap[common.REASON_NOT_PROTECTED].Message,
			}, nil
		}
	} else {
		ctx.Protected = true
	}
	return common.UndeterminedDecision(), matchedProfiles
}

func mutationCheck(matchedProfiles []rspapi.ResourceSigningProfile, reqc *common.RequestContext, reqobj *common.RequestObject, config *config.ShieldConfig, data *RunData, ctx *CheckContext) *common.DecisionResult {
	mutationCheckPassedCount := 0
	var dr *common.DecisionResult
	for _, prof := range matchedProfiles {
		tmpdr := mutationCheckWithSingleProfile(prof, reqc, reqobj, config, data, ctx)
		if tmpdr.IsAllowed() {
			// no mutations are found
			dr = tmpdr
			mutationCheckPassedCount += 1
		} else {
			// mutation is found.
			break
		}
	}
	mutationCheckPassed := false
	if len(matchedProfiles) == mutationCheckPassedCount {
		mutationCheckPassed = true
	}
	if mutationCheckPassed {
		return dr
	}
	return common.UndeterminedDecision()
}

func mutationCheckWithSingleProfile(singleProfile rspapi.ResourceSigningProfile, reqc *common.RequestContext, reqobj *common.RequestObject, config *config.ShieldConfig, data *RunData, ctx *CheckContext) *common.DecisionResult {
	var allowed bool
	var evalMessage string
	var evalReason int
	var mutResult *common.MutationEvalResult
	var err error

	if reqc.IsUpdateRequest() {
		mutResult, err = NewMutationChecker().Eval(reqc, reqobj, singleProfile)
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

func signatureCheckWithSingleProfile(singleProfile rspapi.ResourceSigningProfile, resc *common.ResourceContext, config *config.ShieldConfig, data *RunData, ctx *CheckContext) *common.DecisionResult {
	var allowed bool
	var evalMessage string
	var evalReason int
	var sigResult *common.SignatureEvalResult

	rsigList := data.GetResSigList(resc)

	var err error

	signerConfig := singleProfile.Spec.Parameters.SignerConfig
	plugins := config.GetEnabledPlugins()
	evaluator, err := NewSignatureEvaluator(config, signerConfig, plugins)
	if err != nil {
		allowed = false
		evalMessage = err.Error()
		evalReason = common.REASON_ERROR
	} else {
		sigResult, err = evaluator.Eval(resc, rsigList, singleProfile)
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
			DenyRSP:    &singleProfile,
		}
	}
}
