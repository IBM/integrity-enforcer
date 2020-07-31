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

package policy

import (
	"strings"

	"github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
)

/**********************************************

				PolicyChecker

***********************************************/

type PolicyChecker interface {
	IsTrustStateEnforcementDisabled() (bool, *Policy)
	IsDetectionModeEnabled() (bool, *Policy)
	IsIgnoreRequest() (bool, *Policy)
	IsAllowRequest() (bool, *Policy)
}

func NewPolicyChecker(policy *PolicyList, reqc *common.ReqContext) PolicyChecker {
	return &concretePolicyChecker{
		policy: policy,
		reqc:   reqc,
	}
}

type concretePolicyChecker struct {
	policy *PolicyList
	reqc   *common.ReqContext
}

func (self *concretePolicyChecker) check(patterns []RequestMatchPattern) bool {

	reqc := self.reqc

	isInScope := false
	for _, v := range patterns {
		if v.Match(reqc) {
			isInScope = true
			break
		}
	}
	return isInScope
}

func (self *concretePolicyChecker) IsDetectionModeEnabled() (bool, *Policy) {

	if self.policy != nil {
		ieMode, pol := self.policy.GetMode()
		if ieMode == DetectionMode {
			return true, pol
		} else {
			return false, nil
		}
	} else {
		return false, nil
	}

}

func (self *concretePolicyChecker) IsTrustStateEnforcementDisabled() (bool, *Policy) {

	signerPolicyList := self.policy.Get([]PolicyType{SignerPolicy})
	for _, signerPolicy := range signerPolicyList.Items {
		for _, pattern := range signerPolicy.AllowUnverified {
			if pattern.Match(self.reqc) {
				return true, signerPolicy
			}
		}
	}
	return false, nil
}

func (self *concretePolicyChecker) IsIgnoreRequest() (bool, *Policy) {
	policyList := self.policy.Get([]PolicyType{IEPolicy})
	for _, pol := range policyList.Items {
		if self.check(pol.Ignore) {
			return true, pol
		}
	}
	return false, nil
}

func (self *concretePolicyChecker) IsAllowRequest() (bool, *Policy) {
	policyList := self.policy.Get([]PolicyType{IEPolicy, DefaultPolicy, CustomPolicy})
	for _, pol := range policyList.Items {
		if self.check(pol.Allow.Request) {
			return true, pol
		}
	}
	return false, nil
}

/**********************************************

				Common Functions

***********************************************/

func MatchPattern(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return true
	} else if pattern == "*" {
		return true
	} else if pattern == "-" && value == "" {
		return true
	} else if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, strings.TrimRight(pattern, "*"))
	} else if pattern == value {
		return true
	} else if strings.Contains(pattern, ",") {
		patterns := SplitRule(pattern)
		return MatchWithPatternArray(value, patterns)
	} else {
		return false
	}
}

func MatchPatternWithArray(pattern string, valueArray []string) bool {
	for _, value := range valueArray {
		if MatchPattern(pattern, value) {
			return true
		}
	}
	return false
}

func MatchWithPatternArray(value string, patternArray []string) bool {
	for _, pattern := range patternArray {
		if MatchPattern(pattern, value) {
			return true
		}
	}
	return false
}

func SplitRule(rules string) []string {
	result := []string{}
	slice := strings.Split(rules, ",")
	for _, s := range slice {
		rule := strings.TrimSpace(s)
		result = append(result, rule)
	}
	return result
}
