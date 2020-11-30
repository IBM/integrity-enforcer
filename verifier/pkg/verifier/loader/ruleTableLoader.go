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
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/IBM/integrity-enforcer/verifier/pkg/apis/resourcesigningprofile/v1alpha1"
	rspclient "github.com/IBM/integrity-enforcer/verifier/pkg/client/resourcesigningprofile/clientset/versioned/typed/resourcesigningprofile/v1alpha1"
	common "github.com/IBM/integrity-enforcer/verifier/pkg/common/common"
	cache "github.com/IBM/integrity-enforcer/verifier/pkg/util/cache"
	logger "github.com/IBM/integrity-enforcer/verifier/pkg/util/logger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/rest"
)

const DefaultRuleTableLockCMName = "iv-rule-table-lock"
const DefaultIgnoreTableLockCMName = "iv-ignore-table-lock"
const DefaultForceCheckTableLockCMName = "iv-force-check-table-lock"

// RuleTable

type RuleTableLoader struct {
	RSPClient *rspclient.ApisV1alpha1Client
	// ConfigMapClient xxxxxx
	Rule       *RuleTable
	Ignore     *RuleTable
	ForceCheck *RuleTable

	interval          time.Duration
	verifierNamespace string
	loaded            bool
}

func NewRuleTableLoader(verifierNamespace string) *RuleTableLoader {
	config, _ := rest.InClusterConfig()
	rspClient, _ := rspclient.NewForConfig(config)

	return &RuleTableLoader{
		RSPClient:         rspClient,
		Rule:              NewRuleTable(),
		Ignore:            NewRuleTable(),
		ForceCheck:        NewRuleTable(),
		verifierNamespace: verifierNamespace,
		interval:          time.Second * 30,
		loaded:            false,
	}
}

func InitAllRuleTables(namespace string) error {
	_, err1 := InitRuleTable(namespace, DefaultRuleTableLockCMName, RuleTableTypeProtect, nil)
	_, err2 := InitRuleTable(namespace, DefaultIgnoreTableLockCMName, RuleTableTypeIgnore, nil)
	_, err3 := InitRuleTable(namespace, DefaultForceCheckTableLockCMName, RuleTableTypeForce, nil)
	if err1 != nil || err2 != nil || err3 != nil {
		return fmt.Errorf("RuleTableErr: %s, IgnoreRuleTableError: %s, ForceCheckRuleTableError: %s", err1.Error(), err2.Error(), err3.Error())
	}
	return nil
}

func InitRuleTable(namespace, name string, tableType RuleTableType, reqc *common.ReqContext) (*RuleTable, error) {
	emptyTable := RuleTable([]RuleItem{})
	config, _ := rest.InClusterConfig()
	rspClient, _ := rspclient.NewForConfig(config)
	// list RSP in all namespaces
	list1, err := rspClient.ResourceSigningProfiles("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return &emptyTable, err
	}
	if reqc != nil {
		if reqc.Kind == common.ProfileCustomResourceKind {
			if reqc.IsDeleteRequest() {
				tmpItems := []v1alpha1.ResourceSigningProfile{}
				for _, item := range list1.Items {
					if item.GetNamespace() == reqc.Namespace && item.GetName() == reqc.Name {
						continue
					}
					tmpItems = append(tmpItems, item)
				}
				list1.Items = tmpItems
			} else {
				var newRSP *v1alpha1.ResourceSigningProfile
				_ = json.Unmarshal(reqc.RawObject, &newRSP)
				if newRSP != nil {
					list1.Items = append(list1.Items, *newRSP)
				}
			}
		}
	}

	table := NewRuleTable()
	for _, rsp := range list1.Items {
		singleTable := NewRuleTableFromProfile(rsp, tableType, namespace, reqc)
		if !rsp.Spec.Disabled {
			table = table.Merge(singleTable)
		}
	}
	err = table.Update(namespace, name)
	if err != nil {
		logger.Warn("Failed to update RuleTable: ", name, ", err: ", err.Error())
	}
	return table, nil
}

func (self *RuleTableLoader) GetData() *RuleTable {
	if !self.loaded {
		self.Load(nil)
	}
	return self.Rule
}

func (self *RuleTableLoader) GetIgnoreData() *RuleTable {
	if !self.loaded {
		self.Load(nil)
	}
	return self.Ignore
}

func (self *RuleTableLoader) GetForceCheckData() *RuleTable {
	if !self.loaded {
		self.Load(nil)
	}
	return self.ForceCheck
}

func (self *RuleTableLoader) Load(reqc *common.ReqContext) {
	var tmpData1, tmpData2, tmpData3 *RuleTable
	var keyName string
	var keyExists bool
	var cached string
	var err error

	keyName = fmt.Sprintf("RuleTableLoader/%s/get/%s", self.verifierNamespace, DefaultRuleTableLockCMName)
	keyExists = cache.KeyExists(keyName)
	cached = cache.GetString(keyName)
	if !keyExists && cached == "" {
		tmpData1, err = InitRuleTable(self.verifierNamespace, DefaultRuleTableLockCMName, RuleTableTypeProtect, reqc)
		if err != nil {
			logger.Error("failed to reload RuleTable:", err)
		}
		tmp, _ := json.Marshal(tmpData1)
		cache.SetString(keyName, string(tmp), &(self.interval))
		logger.Trace("RuleTable reloaded. ", string(tmp))
	} else {
		err = json.Unmarshal([]byte(cached), &tmpData1)
		if err != nil {
			logger.Error("failed to Unmarshal cached RuleTable:", err)
			return
		}
	}

	keyName = fmt.Sprintf("RuleTableLoader/%s/get/%s", self.verifierNamespace, DefaultIgnoreTableLockCMName)
	keyExists = cache.KeyExists(keyName)
	cached = cache.GetString(keyName)
	if !keyExists && cached == "" {
		tmpData2, err = InitRuleTable(self.verifierNamespace, DefaultIgnoreTableLockCMName, RuleTableTypeIgnore, reqc)
		if err != nil {
			logger.Error("failed to reload RuleTable:", err)
		}
		tmp, _ := json.Marshal(tmpData2)
		cache.SetString(keyName, string(tmp), &(self.interval))
		logger.Trace("IgnoreRuleTable reloaded. ", string(tmp))
	} else {
		err = json.Unmarshal([]byte(cached), &tmpData2)
		if err != nil {
			logger.Error("failed to Unmarshal cached IgnoreRuleTable:", err)
			return
		}
	}

	keyName = fmt.Sprintf("RuleTableLoader/%s/get/%s", self.verifierNamespace, DefaultForceCheckTableLockCMName)
	keyExists = cache.KeyExists(keyName)
	cached = cache.GetString(keyName)
	if !keyExists && cached == "" {
		tmpData3, err = InitRuleTable(self.verifierNamespace, DefaultForceCheckTableLockCMName, RuleTableTypeForce, reqc)
		if err != nil {
			logger.Error("failed to reload RuleTable:", err)
		}
		tmp, _ := json.Marshal(tmpData3)
		cache.SetString(keyName, string(tmp), &(self.interval))
		logger.Trace("ForceCheckRuleTable reloaded. ", string(tmp))
	} else {
		err = json.Unmarshal([]byte(cached), &tmpData3)
		if err != nil {
			logger.Error("failed to Unmarshal cached ForceCheckRuleTable:", err)
			return
		}
	}

	self.Rule = tmpData1
	self.Ignore = tmpData2
	self.ForceCheck = tmpData3
	self.loaded = true
	return
}

func (self *RuleTableLoader) ResetCache() error {
	cache.Unset(fmt.Sprintf("RuleTableLoader/%s/get/%s", self.verifierNamespace, DefaultRuleTableLockCMName))
	cache.Unset(fmt.Sprintf("RuleTableLoader/%s/get/%s", self.verifierNamespace, DefaultIgnoreTableLockCMName))
	cache.Unset(fmt.Sprintf("RuleTableLoader/%s/get/%s", self.verifierNamespace, DefaultForceCheckTableLockCMName))
	return nil
}

func (self *RuleTableLoader) Reload(reqc *common.ReqContext) error {
	_ = self.ResetCache()
	self.Load(reqc)
	return nil
}

func (self *RuleTableLoader) GetTargetNamespaces() []string {
	if !self.loaded {
		self.Load(nil)
	}
	list1 := self.Rule.NamespaceList(self.verifierNamespace)
	list2 := self.Ignore.NamespaceList(self.verifierNamespace)
	list3 := self.ForceCheck.NamespaceList(self.verifierNamespace)
	listUnion := []string{}
	listUnion = common.GetUnionOfArrays(listUnion, list1)
	listUnion = common.GetUnionOfArrays(listUnion, list2)
	listUnion = common.GetUnionOfArrays(listUnion, list3)
	return listUnion
}
