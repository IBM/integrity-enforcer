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

	rspclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/resourcesigningprofile/clientset/versioned/typed/resourcesigningprofile/v1alpha1"
	common "github.com/IBM/integrity-enforcer/enforcer/pkg/common/common"
	cache "github.com/IBM/integrity-enforcer/enforcer/pkg/util/cache"
	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/util/logger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/rest"
)

const DefaultRuleTableLockCMName = "ie-rule-table-lock"
const DefaultIgnoreTableLockCMName = "ie-ignore-table-lock"
const DefaultForceCheckTableLockCMName = "ie-force-check-table-lock"

// RuleTable

type RuleTableLoader struct {
	RSPClient *rspclient.ApisV1alpha1Client
	// ConfigMapClient xxxxxx
	Rule       *RuleTable
	Ignore     *RuleTable
	ForceCheck *RuleTable

	interval          time.Duration
	enforcerNamespace string
}

func NewRuleTableLoader(enforcerNamespace string) *RuleTableLoader {
	config, _ := rest.InClusterConfig()
	rspClient, _ := rspclient.NewForConfig(config)

	return &RuleTableLoader{
		RSPClient:         rspClient,
		Rule:              NewRuleTable(),
		Ignore:            NewRuleTable(),
		ForceCheck:        NewRuleTable(),
		enforcerNamespace: enforcerNamespace,
		interval:          time.Second * 30,
	}
}

func InitAllRuleTables(namespace string) error {
	err1 := InitRuleTable(namespace, DefaultRuleTableLockCMName)
	err2 := InitIgnoreRuleTable(namespace, DefaultIgnoreTableLockCMName)
	err3 := InitForceCheckRuleTable(namespace, DefaultForceCheckTableLockCMName)
	if err1 != nil || err2 != nil || err3 != nil {
		return fmt.Errorf("RuleTableErr: %s, IgnoreRuleTableError: %s, ForceCheckRuleTableError: %s", err1.Error(), err2.Error(), err3.Error())
	}
	return nil
}

func InitRuleTable(namespace, name string) error {
	config, _ := rest.InClusterConfig()
	rspClient, _ := rspclient.NewForConfig(config)
	// list RSP in all namespaces
	list1, err := rspClient.ResourceSigningProfiles("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	table := NewRuleTable()
	for _, rsp := range list1.Items {
		singleTable := NewRuleTableFromProfile(rsp, RuleTableTypeProtect)
		if !rsp.Spec.Disabled {
			table = table.Merge(singleTable)
		}
	}
	table.Update(namespace, name)
	return nil
}

func InitIgnoreRuleTable(namespace, name string) error {
	config, _ := rest.InClusterConfig()
	rspClient, _ := rspclient.NewForConfig(config)
	// list RSP in all namespaces
	list1, err := rspClient.ResourceSigningProfiles("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	table := NewRuleTable()
	for _, rsp := range list1.Items {
		singleTable := NewRuleTableFromProfile(rsp, RuleTableTypeIgnore)
		if !rsp.Spec.Disabled {
			table = table.Merge(singleTable)
		}
	}
	table.Update(namespace, name)
	return nil
}

func InitForceCheckRuleTable(namespace, name string) error {
	config, _ := rest.InClusterConfig()
	rspClient, _ := rspclient.NewForConfig(config)
	// list RSP in all namespaces
	list1, err := rspClient.ResourceSigningProfiles("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	table := NewRuleTable()
	for _, rsp := range list1.Items {
		singleTable := NewRuleTableFromProfile(rsp, RuleTableTypeForce)
		if !rsp.Spec.Disabled {
			table = table.Merge(singleTable)
		}
	}
	table.Update(namespace, name)
	return nil
}

func (self *RuleTableLoader) GetData() *RuleTable {
	self.Load()
	return self.Rule
}

func (self *RuleTableLoader) GetIgnoreData() *RuleTable {
	self.Load()
	return self.Ignore
}

func (self *RuleTableLoader) GetForceCheckData() *RuleTable {
	self.Load()
	return self.ForceCheck
}

func (self *RuleTableLoader) Load() {
	var tmpData1, tmpData2, tmpData3 *RuleTable
	var keyName string
	var err error
	keyName = fmt.Sprintf("RuleTableLoader/%s/get/%s", self.enforcerNamespace, DefaultRuleTableLockCMName)
	if cached := cache.GetString(keyName); cached == "" {
		err = InitRuleTable(self.enforcerNamespace, DefaultRuleTableLockCMName)
		if err != nil {
			logger.Error("failed to reload RuleTable:", err)
		}
		tmpData1, err = GetRuleTable(self.enforcerNamespace, DefaultRuleTableLockCMName)
		if err != nil {
			logger.Error("failed to get RuleTable:", err)
		}

		logger.Trace("RuleTable reloaded.")
		tmp, _ := json.Marshal(tmpData1)
		cache.SetString(keyName, string(tmp), &(self.interval))
	} else {
		err = json.Unmarshal([]byte(cached), &tmpData1)
		if err != nil {
			logger.Error("failed to Unmarshal cached RuleTable:", err)
			return
		}
	}

	keyName = fmt.Sprintf("RuleTableLoader/%s/get/%s", self.enforcerNamespace, DefaultIgnoreTableLockCMName)
	if cached := cache.GetString(keyName); cached == "" {
		err = InitIgnoreRuleTable(self.enforcerNamespace, DefaultIgnoreTableLockCMName)
		if err != nil {
			logger.Error("failed to reload RuleTable:", err)
		}
		tmpData2, err = GetRuleTable(self.enforcerNamespace, DefaultIgnoreTableLockCMName)
		if err != nil {
			logger.Error("failed to get IgnoreRuleTable:", err)
		}

		logger.Trace("IgnoreRuleTable reloaded.")
		tmp, _ := json.Marshal(tmpData2)
		cache.SetString(keyName, string(tmp), &(self.interval))
	} else {
		err = json.Unmarshal([]byte(cached), &tmpData2)
		if err != nil {
			logger.Error("failed to Unmarshal cached IgnoreRuleTable:", err)
			return
		}
	}

	keyName = fmt.Sprintf("RuleTableLoader/%s/get/%s", self.enforcerNamespace, DefaultForceCheckTableLockCMName)
	if cached := cache.GetString(keyName); cached == "" {
		err = InitForceCheckRuleTable(self.enforcerNamespace, DefaultForceCheckTableLockCMName)
		if err != nil {
			logger.Error("failed to reload RuleTable:", err)
		}
		tmpData3, err = GetRuleTable(self.enforcerNamespace, DefaultForceCheckTableLockCMName)
		if err != nil {
			logger.Error("failed to get ForceCheckRuleTable:", err)
		}

		logger.Trace("ForceCheckRuleTable reloaded.")
		tmp, _ := json.Marshal(tmpData3)
		cache.SetString(keyName, string(tmp), &(self.interval))
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
	return
}

func (self *RuleTableLoader) ResetCache() error {
	cache.Unset(fmt.Sprintf("RuleTableLoader/%s/get/%s", self.enforcerNamespace, DefaultRuleTableLockCMName))
	cache.Unset(fmt.Sprintf("RuleTableLoader/%s/get/%s", self.enforcerNamespace, DefaultIgnoreTableLockCMName))
	cache.Unset(fmt.Sprintf("RuleTableLoader/%s/get/%s", self.enforcerNamespace, DefaultForceCheckTableLockCMName))
	return nil
}

func (self *RuleTableLoader) GetTargetNamespaces() []string {
	self.Load()
	list1 := self.Rule.NamespaceList(self.enforcerNamespace)
	list2 := self.Ignore.NamespaceList(self.enforcerNamespace)
	list3 := self.ForceCheck.NamespaceList(self.enforcerNamespace)
	listUnion := []string{}
	listUnion = common.GetUnionOfArrays(listUnion, list1)
	listUnion = common.GetUnionOfArrays(listUnion, list2)
	listUnion = common.GetUnionOfArrays(listUnion, list3)
	return listUnion
}
