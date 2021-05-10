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
	"encoding/json"

	rsigapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesignature/v1alpha1"
	rspapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	sigconfapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/signerconfig/v1alpha1"
	config "github.com/IBM/integrity-enforcer/shield/pkg/config"
	logger "github.com/IBM/integrity-enforcer/shield/pkg/util/logger"

	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	v1 "k8s.io/api/core/v1"
)

/**********************************************

				RunData

***********************************************/

type RunData struct {
	RSPList      []rspapi.ResourceSigningProfile `json:"rspList,omitempty"`
	NSList       []v1.Namespace                  `json:"nsList,omitempty"`
	SignerConfig *sigconfapi.SignerConfig        `json:"signerConfig,omitempty"`
	ResSigList   *rsigapi.ResourceSignatureList  `json:"resSigList,omitempty"`

	loader          *Loader               `json:"-"`
	commonProfile   *common.CommonProfile `json:"-"`
	ruleTable       *RuleTable            `json:"-"`
	forceInitialize bool                  `json:"-"`
}

func (self *RunData) EnableForceInitialize() {
	self.forceInitialize = true
	return
}

func (self *RunData) DisableForceInitialize() {
	self.forceInitialize = false
	return
}

func (self *RunData) GetSignerConfig() *sigconfapi.SignerConfig {
	if self.SignerConfig == nil && self.loader != nil {
		self.SignerConfig = self.loader.SignerConfig.GetData(true)
	}
	return self.SignerConfig
}

func (self *RunData) GetResSigList(v2resc *common.V2ResourceContext) *rsigapi.ResourceSignatureList {
	if self.ResSigList == nil && self.loader != nil {
		self.ResSigList = self.loader.ResourceSignature.GetData(v2resc, true)
	}
	return self.ResSigList
}

func (self *RunData) setRuleTable(shieldNamespace string) bool {
	updated := false
	ruleTable := NewRuleTable(self.RSPList, self.NSList, self.commonProfile, shieldNamespace)
	if ruleTable != nil && !ruleTable.IsEmpty() && !ruleTable.IsTargetEmpty() {
		self.ruleTable = ruleTable
		updated = true
	}
	return updated
}

func (self *RunData) GetRuleTable(shieldNamespace string) *RuleTable {
	rspReloaded := false
	nsReloaded := false
	var tmpRSPList []rspapi.ResourceSigningProfile
	var tmpNSList []v1.Namespace
	if self.loader != nil {
		tmpRSPList, rspReloaded = self.loader.RSP.GetData(true)
		tmpNSList, nsReloaded = self.loader.Namespace.GetData(true)
		if rspReloaded || len(tmpRSPList) > 0 {
			self.RSPList = tmpRSPList
		}
		if nsReloaded || len(tmpNSList) > 0 {
			self.NSList = tmpNSList
		}
	}
	if self.ruleTable == nil || self.ruleTable.IsEmpty() || self.ruleTable.IsTargetEmpty() || rspReloaded || nsReloaded {
		rtInited := self.setRuleTable(shieldNamespace)
		if rtInited {
			// logger.Trace("RuleTable is updated.")
		}
	}

	if self.ruleTable == nil || self.ruleTable.IsEmpty() || self.ruleTable.IsTargetEmpty() {
		rspBytes, _ := json.Marshal(self.RSPList)
		tmpRSPBytes, _ := json.Marshal(tmpRSPList)
		nsBytes, _ := json.Marshal(self.NSList)
		tmpNSBytes, _ := json.Marshal(tmpNSList)
		logger.Trace("RuleTable is nil; RunData.RSPList: ", string(rspBytes), "RunData.NSList: ", string(nsBytes), "rspReloaded: ", rspReloaded, "nsReloaded: ", nsReloaded, "tmpRSPList: ", string(tmpRSPBytes), "tmpNSList: ", string(tmpNSBytes))
	}
	return self.ruleTable
}

func (self *RunData) Init(conf *config.ShieldConfig) {
	force := false
	if self.forceInitialize {
		force = false
	}

	self.RSPList, _ = self.loader.RSP.GetData(force)
	self.NSList, _ = self.loader.Namespace.GetData(force)
	self.commonProfile = conf.CommonProfile
	rtInited := self.setRuleTable(conf.Namespace)
	rtB, err := json.Marshal(self.ruleTable)
	if err != nil {
		logger.Info("[DEBUG] RuleTable marshaling err: ", err.Error())
	} else {
		logger.Info("[DEBUG] RuleTable:", string(rtB))
		rlB, _ := json.Marshal(self.RSPList)
		logger.Info("[DEBUG] RSPList:", string(rlB))
	}
	if rtInited {
		// logger.Trace("RuleTable is initialized.")
	}
	return
}

func (self *RunData) resetRuleTableCache() {
	self.loader.RSP.ClearCache()
	self.loader.Namespace.ClearCache()
	logger.Debug("RuleTable cache has been cleared")
	return
}
