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

package enforcer

import (
	"encoding/json"
	"fmt"

	epolpkg "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/enforcepolicy/v1alpha1"
	common "github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/policy"
)

type PolicyValidator struct {
	Namespace         string
	Operation         string
	Policy            *policy.Policy
	EnforcerNamespace string
	PolicyNamespace   string
}

func isPolicyReq(reqc *common.ReqContext) bool {
	return (reqc.GroupVersion() == epolpkg.SchemeGroupVersion.String() && reqc.Kind == epolpkg.KindName)
}

func NewPolicyValidator(reqc *common.ReqContext, ieNs, policyNs string) *PolicyValidator {
	emptyValidator := &PolicyValidator{}
	var epolObj *epolpkg.EnforcePolicy
	err := json.Unmarshal(reqc.RawObject, &epolObj)
	if err != nil {
		return emptyValidator
	}
	if epolObj == nil {
		return emptyValidator
	}
	if epolObj.Spec.Policy == nil {
		return emptyValidator
	}
	validator := &PolicyValidator{
		Namespace:         reqc.Namespace,
		Operation:         reqc.Operation,
		Policy:            epolObj.Spec.Policy,
		EnforcerNamespace: ieNs,
		PolicyNamespace:   policyNs,
	}
	return validator
}

func (self *PolicyValidator) Validate() (bool, string) {
	if self.Policy == nil {
		return false, "Failed to create PolicyValidator"
	}
	ok, errMsg := self.Policy.CheckFormat()
	if !ok {
		return false, fmt.Sprintf("Policy in invalid format; %s", errMsg)
	}
	ns := self.Namespace
	ieNs := self.EnforcerNamespace
	polNs := self.PolicyNamespace
	pType := self.Policy.PolicyType
	if ns != ieNs && ns != polNs {
		return false, fmt.Sprintf("Policy must be created in namespace \"%s\" or \"%s\", but requested in \"%s\"", ieNs, polNs, ns)
	}
	if (pType == policy.DefaultPolicy || pType == policy.IEPolicy || pType == policy.SignerPolicy) && ns != ieNs {
		return false, fmt.Sprintf("%s must be created in namespace \"%s\", but requested in \"%s\"", pType, ieNs, ns)
	}
	if pType == policy.CustomPolicy && ns != polNs {
		return false, fmt.Sprintf("%s must be created in namespace \"%s\", but requested in \"%s\"", pType, polNs, ns)
	}
	// op := self.Operation
	// if op == "UPDATE" && (pType == policy.DefaultPolicy || pType == policy.IEPolicy) {
	// 	return false, fmt.Sprintf("%s cannot be updated", pType)
	// }
	return true, ""
}
