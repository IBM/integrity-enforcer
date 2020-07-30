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
	IsTrustStateEnforcementDisabled() bool
	IsDetectionModeEnabled() bool
	IsEnforceResult() bool
	IsIgnoreRequest() bool
	IsAllowedForInternalRequest() bool
	IsAllowedByRule() bool
	PermitIfVerifiedOwner() bool
	PermitIfVerifiedServiceAccount() bool
}

func NewPolicyChecker(policy *Policy, reqc *common.ReqContext) PolicyChecker {
	return &concretePolicyChecker{
		policy: policy,
		reqc:   reqc,
	}
}

type concretePolicyChecker struct {
	policy *Policy
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

func (self *concretePolicyChecker) IsDetectionModeEnabled() bool {

	if self.policy != nil {
		ieMode := self.policy.Mode
		if ieMode == UnknownMode {
			ieMode = defaultIntegrityEnforcerMode
		}
		if ieMode == DetectionMode {
			return true
		} else {
			return false
		}
	} else {
		return false
	}

}

func (self *concretePolicyChecker) IsTrustStateEnforcementDisabled() bool {

	if self.policy != nil && self.policy.AllowUnverified != nil {
		for _, pattern := range self.policy.AllowUnverified {
			if pattern.Match(self.reqc) {
				return true
			}
		}
		return false
	} else {
		return false
	}

}

func (self *concretePolicyChecker) IsIgnoreRequest() bool {
	if self.policy != nil && self.policy.IgnoreRequest != nil {
		return self.check(self.policy.IgnoreRequest)
	} else {
		return false
	}
}

func (self *concretePolicyChecker) IsEnforceResult() bool {
	if self.IsIgnoreRequest() {
		return false
	} else if self.policy != nil && self.policy.Enforce != nil {
		return self.check(self.policy.Enforce)
	} else {
		return false
	}
}

func (self *concretePolicyChecker) IsAllowedForInternalRequest() bool {
	if self.policy != nil && self.policy.AllowedForInternalRequest != nil {
		return self.check(self.policy.AllowedForInternalRequest)
	} else {
		return false
	}
}

func (self *concretePolicyChecker) IsAllowedByRule() bool {
	if self.policy != nil && self.policy.AllowedByRule != nil {
		return self.check(self.policy.AllowedByRule)
	} else {
		return false
	}
}

func (self *concretePolicyChecker) PermitIfVerifiedOwner() bool {
	if self.policy != nil && self.policy.PermitIfVerifiedOwner != nil {
		patterns := self.policy.PermitIfVerifiedOwner

		for _, p := range patterns {
			request := p.Request.Match(self.reqc)
			if !request {
				continue
			}

			//check if sa is included in the list.
			if len(p.AuthorizedServiceAccount) != 0 {
				for _, au := range p.AuthorizedServiceAccount {
					userName := self.reqc.UserName
					if strings.Contains(userName, ":") {
						name := strings.Split(userName, ":")
						userName = name[len(name)-1]
					}
					result := MatchPattern(au, userName)
					if result {
						return result
					}
				}
			}
		}
		return false
	} else {
		return false
	}
}

func (self *concretePolicyChecker) PermitIfVerifiedServiceAccount() bool {

	if self.policy != nil && self.policy.PermitIfVerifiedOwner != nil {
		patterns := self.policy.PermitIfVerifiedOwner

		for _, p := range patterns {
			request := p.Request.Match(self.reqc)
			if !request {
				continue
			}
			//check if sa is verified.
			if p.AllowChangesBySignedServiceAccount {
				return true
			}
		}
		return false

	} else {
		return false
	}

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
