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
	"strings"

	rspapi "github.com/IBM/integrity-enforcer/verifier/pkg/apis/resourcesigningprofile/v1alpha1"
	common "github.com/IBM/integrity-enforcer/verifier/pkg/common/common"
	handlerutil "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/handlerutil"
	sign "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/sign"
)

/**********************************************

				profileChecker

***********************************************/

type profileChecker struct {
	*commonHandler
	profile                      rspapi.ResourceSigningProfile
	allowedForThisProfile        bool
	errMsgForThisProfile         string
	evalReasonForThisProfile     int
	signResultForThisProfile     *common.SignatureEvalResult
	mutationResultForThisProfile *common.MutationEvalResult
}

func (self *profileChecker) run() (bool, int, string, *common.SignatureEvalResult, *common.MutationEvalResult) {
	//check signature
	if !self.ctx.Aborted && !self.allowedForThisProfile {
		if r, err := self.evalSignature(self.profile); err != nil {
			self.abort("Error when evaluating sign policy", err)
		} else {
			self.signResultForThisProfile = r
			if r.Checked && r.Allow {
				self.allowedForThisProfile = true
				self.evalReasonForThisProfile = common.REASON_VALID_SIG
			}
			if r.Error != nil {
				self.errMsgForThisProfile = r.Error.MakeMessage()
				if strings.HasPrefix(self.errMsgForThisProfile, common.ReasonCodeMap[common.REASON_INVALID_SIG].Message) {
					self.evalReasonForThisProfile = common.REASON_INVALID_SIG
				} else if strings.HasPrefix(self.errMsgForThisProfile, common.ReasonCodeMap[common.REASON_NO_POLICY].Message) {
					self.evalReasonForThisProfile = common.REASON_NO_POLICY
				} else if self.errMsgForThisProfile == common.ReasonCodeMap[common.REASON_NO_SIG].Message {
					self.evalReasonForThisProfile = common.REASON_NO_SIG
				} else {
					self.evalReasonForThisProfile = common.REASON_ERROR
				}
			}
		}
	}

	//check mutation
	if !self.ctx.Aborted && !self.allowedForThisProfile && self.reqc.IsUpdateRequest() {
		if r, err := self.evalMutation(self.profile); err != nil {
			self.abort("Error when evaluating mutation", err)
		} else {
			self.mutationResultForThisProfile = r
			if r.Checked && !r.IsMutated {
				self.allowedForThisProfile = true
				self.evalReasonForThisProfile = common.REASON_NO_MUTATION
			}
		}
	}

	return self.allowedForThisProfile, self.evalReasonForThisProfile, self.errMsgForThisProfile, self.signResultForThisProfile, self.mutationResultForThisProfile
}

func (self *profileChecker) evalSignature(signingProfile rspapi.ResourceSigningProfile) (*common.SignatureEvalResult, error) {
	signPolicy := self.loader.GetSignPolicy()
	plugins := self.GetEnabledPlugins()
	if evaluator, err := sign.NewSignatureEvaluator(self.config, signPolicy, plugins); err != nil {
		return nil, err
	} else {
		reqc := self.reqc
		resSigList := self.loader.ResSigList(reqc)
		return evaluator.Eval(reqc, resSigList, signingProfile)
	}
}

func (self *profileChecker) evalMutation(signingProfile rspapi.ResourceSigningProfile) (*common.MutationEvalResult, error) {
	reqc := self.reqc
	checker := handlerutil.NewMutationChecker()
	return checker.Eval(reqc, signingProfile)
}
