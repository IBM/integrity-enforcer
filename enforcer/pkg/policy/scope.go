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
	"math/big"
	"strconv"
	"strings"

	"github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
)

/**********************************************

				PolicyChecker

***********************************************/

type PolicyChecker interface {
	IsTrustStateEnforcementDisabled() (bool, string)
	IsDetectionModeEnabled() (bool, string)
	IsIgnoreRequest() (bool, string)
	IsAllowRequest() (bool, string)
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

func (self *concretePolicyChecker) IsDetectionModeEnabled() (bool, string) {

	if self.policy != nil {
		ieMode, pol := self.policy.GetMode()
		if ieMode == DetectMode {
			return true, pol.String()
		} else {
			return false, ""
		}
	} else {
		return false, ""
	}

}

func (self *concretePolicyChecker) IsTrustStateEnforcementDisabled() (bool, string) {

	signerPolicyList := self.policy.Get([]PolicyType{SignerPolicy})
	for _, signerPolicy := range signerPolicyList.Items {
		for _, pattern := range signerPolicy.AllowUnverified {
			if pattern.Match(self.reqc) {
				return true, signerPolicy.String()
			}
		}
	}
	return false, ""
}

func (self *concretePolicyChecker) IsIgnoreRequest() (bool, string) {
	policyList := self.policy.Get([]PolicyType{IEPolicy})
	for _, pol := range policyList.Items {
		if self.check(pol.Ignore) {
			return true, pol.String()
		}
	}
	return false, ""
}

func (self *concretePolicyChecker) IsAllowRequest() (bool, string) {
	policyList := self.policy.Get([]PolicyType{IEPolicy, DefaultPolicy, CustomPolicy})
	for _, pol := range policyList.Items {
		if self.check(pol.Allow.Request) {
			return true, pol.String()
		}
	}
	return false, ""
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

func MatchBigInt(pattern string, value *big.Int) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return true
	} else if pattern == "*" {
		return true
	} else if pattern == "-" && value == nil {
		return true
	} else if strings.Contains(pattern, ":") {
		return pattern2BigInt(pattern).Cmp(value) == 0
	} else if i, err := strconv.Atoi(pattern); err == nil {
		return i == int(value.Int64())
	} else {
		return false
	}
}

func pattern2BigInt(pattern string) *big.Int {
	a := strings.ReplaceAll(pattern, ":", "")
	i := new(big.Int)
	i.SetString(a, 16)
	return i
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
