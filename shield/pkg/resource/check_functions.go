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

	rsigapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesignature/v1alpha1"
	rspapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	sigconfapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/signerconfig/v1alpha1"

	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	config "github.com/IBM/integrity-enforcer/shield/pkg/config"
)

func singleProfileCheck(singleProfile rspapi.ResourceSigningProfile, reqc *common.ReqContext, config *config.ShieldConfig, sigConfRes *sigconfapi.SignerConfig, rsigList *rsigapi.ResourceSignatureList) (bool, int, string, *common.SignatureEvalResult) {
	var sigResult *common.SignatureEvalResult
	var err error

	signerConfig := sigConfRes.Spec.Config
	plugins := config.GetEnabledPlugins()
	evaluator, err := NewSignatureEvaluator(config, signerConfig, plugins)
	if err != nil {
		return false, common.REASON_ERROR, err.Error(), nil
	}
	sigResult, err = evaluator.Eval(reqc, rsigList, singleProfile)
	if err != nil {
		return false, common.REASON_ERROR, err.Error(), sigResult
	}
	if sigResult.Checked && sigResult.Allow {
		return true, common.REASON_VALID_SIG, common.ReasonCodeMap[common.REASON_VALID_SIG].Message, sigResult
	}

	var reasonCode int
	var message string
	if sigResult.Error != nil {
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
	}
	return false, reasonCode, message, sigResult
}
