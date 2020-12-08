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
	rsigapi "github.com/IBM/integrity-enforcer/verifier/pkg/apis/resourcesignature/v1alpha1"
	rspapi "github.com/IBM/integrity-enforcer/verifier/pkg/apis/resourcesigningprofile/v1alpha1"
	spolapi "github.com/IBM/integrity-enforcer/verifier/pkg/apis/signpolicy/v1alpha1"

	common "github.com/IBM/integrity-enforcer/verifier/pkg/common/common"
	loader "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/loader"
	v1 "k8s.io/api/core/v1"
)

/**********************************************

				RunData

***********************************************/

type RunData struct {
	RSPList []rspapi.ResourceSigningProfile `json:"rspList,omitempty"`
	NSList  []v1.Namespace                  `json:"nsList,omitempty"`

	// for test
	SignPolicy *spolapi.SignPolicy            `json:"signPolicy,omitempty"`
	ResSigList *rsigapi.ResourceSignatureList `json:"resSigList,omitempty"`

	loader    *loader.Loader     `json:"-"`
	ruleTable *loader.RuleTable2 `json:"-"`
}

func (self *RunData) GetSignPolicy() *spolapi.SignPolicy {
	if self.SignPolicy == nil && self.loader != nil {
		self.SignPolicy = self.loader.SignPolicy.GetData(true)
	}
	return self.SignPolicy
}

func (self *RunData) GetResSigList(reqc *common.ReqContext) *rsigapi.ResourceSignatureList {
	if self.ResSigList == nil && self.loader != nil {
		self.ResSigList = self.loader.ResourceSignature.GetData(reqc, true)
	}
	return self.ResSigList
}

func (self *RunData) GetRSPList() []rspapi.ResourceSigningProfile {
	if self.RSPList == nil && self.loader != nil {
		self.RSPList = self.loader.RSP.GetData(true)
	}
	return self.RSPList
}

func (self *RunData) GetNSList() []v1.Namespace {
	if self.NSList == nil && self.loader != nil {
		self.NSList = self.loader.Namespace.GetData(true)
	}
	return self.NSList
}

func (self *RunData) setRuleTable(verifierNamespace string) {
	ruleTable := loader.NewRuleTable2(self.RSPList, self.NSList, verifierNamespace)
	if ruleTable != nil && !ruleTable.IsEmpty() {
		self.ruleTable = ruleTable
	}
}

func (self *RunData) GetRuleTable(verifierNamespace string) *loader.RuleTable2 {
	if self.ruleTable == nil || self.ruleTable.IsEmpty() {
		if self.loader != nil {
			self.RSPList = self.loader.RSP.GetData(true)
			self.NSList = self.loader.Namespace.GetData(true)
		}
		self.setRuleTable(verifierNamespace)
	}
	return self.ruleTable
}

func (self *RunData) Init(reqc *common.ReqContext, verifierNamespace string) {
	// self.GetSignPolicy()
	// self.GetResSigList(reqc)
	self.RSPList = self.loader.RSP.GetData(false)
	self.NSList = self.loader.Namespace.GetData(false)
	self.setRuleTable(verifierNamespace)
	return
}
