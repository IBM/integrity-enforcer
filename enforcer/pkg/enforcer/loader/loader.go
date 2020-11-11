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

package loader

import (
	rsig "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourcesignature/v1alpha1"
	common "github.com/IBM/integrity-enforcer/enforcer/pkg/common/common"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/common/policy"
	profile "github.com/IBM/integrity-enforcer/enforcer/pkg/common/profile"
	config "github.com/IBM/integrity-enforcer/enforcer/pkg/enforcer/config"
	v1 "k8s.io/api/core/v1"
)

/**********************************************

				Loader

***********************************************/

type Loader struct {
	SignPolicy        *SignPolicyLoader
	RuleTable         *RuleTableLoader
	RSP               *RSPLoader
	ResourceSignature *ResSigLoader
}

func NewLoader(cfg *config.EnforcerConfig, reqc *common.ReqContext) *Loader {
	enforcerNamespace := cfg.Namespace
	requestNamespace := reqc.Namespace
	signatureNamespace := cfg.SignatureNamespace // for non-existing namespace / cluster scope
	profileNamespace := cfg.ProfileNamespace     // for non-existing namespace / cluster scope
	reqApiVersion := reqc.GroupVersion()
	reqKind := reqc.Kind
	loader := &Loader{
		SignPolicy:        NewSignPolicyLoader(enforcerNamespace),
		RSP:               NewRSPLoader(enforcerNamespace, profileNamespace, requestNamespace, cfg.CommonProfile),
		RuleTable:         NewRuleTableLoader(enforcerNamespace),
		ResourceSignature: NewResSigLoader(signatureNamespace, requestNamespace, reqApiVersion, reqKind),
	}
	return loader
}

func (self *Loader) ProtectRules() *RuleTable {
	table := self.RuleTable.GetData()
	return table
}

func (self *Loader) IgnoreRules() *RuleTable {
	table := self.RuleTable.GetIgnoreData()
	return table
}

func (self *Loader) ForceCheckRules() *RuleTable {
	table := self.RuleTable.GetForceCheckData()
	return table
}

func (self *Loader) SigningProfile(profileReferences []*v1.ObjectReference) []profile.SigningProfile {
	signingProfiles := []profile.SigningProfile{}

	rsps := self.RSP.GetByReferences(profileReferences)
	for _, d := range rsps {
		if !d.Spec.Disabled {
			signingProfiles = append(signingProfiles, d)
		}
	}

	return signingProfiles

}

func (self *Loader) UpdateRuleTable(reqc *common.ReqContext) error {
	err := self.RuleTable.Update(reqc)
	if err != nil {
		return err
	}
	return nil
}

func (self *Loader) UpdateProfileStatus(profile profile.SigningProfile, reqc *common.ReqContext, errMsg string) error {
	err := self.RSP.UpdateStatus(profile, reqc, errMsg)
	if err != nil {
		return err
	}
	return nil
}

func (self *Loader) RefreshRuleTable() error {
	err := self.RuleTable.Refresh()
	if err != nil {
		return err
	}
	return nil
}

func (self *Loader) BreakGlassConditions() []policy.BreakGlassCondition {
	sp := self.SignPolicy.GetData()
	conditions := []policy.BreakGlassCondition{}
	if sp != nil {
		conditions = append(conditions, sp.Spec.SignPolicy.BreakGlass...)
	}
	return conditions
}

func (self *Loader) GetSignPolicy() *policy.SignPolicy {
	spol := self.SignPolicy.GetData()
	return spol.Spec.SignPolicy
}

func (self *Loader) ResSigList(reqc *common.ReqContext) *rsig.ResourceSignatureList {
	items := self.ResourceSignature.GetData()

	return &rsig.ResourceSignatureList{Items: items}
}
