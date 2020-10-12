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

package config

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	cache "github.com/IBM/integrity-enforcer/enforcer/pkg/cache"
	"github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
	"github.com/IBM/integrity-enforcer/enforcer/pkg/protect"

	rppapi "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourceprotectionprofile/v1alpha1"
	rsigapi "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourcesignature/v1alpha1"
	spolapi "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/signpolicy/v1alpha1"
	rppclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/resourceprotectionprofile/clientset/versioned/typed/resourceprotectionprofile/v1alpha1"
	rsigclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/resourcesignature/clientset/versioned/typed/resourcesignature/v1alpha1"
	spolclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/signpolicy/clientset/versioned/typed/signpolicy/v1alpha1"
	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/logger"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ecfgclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/enforcerconfig/clientset/versioned/typed/enforcerconfig/v1alpha1"
	cfg "github.com/IBM/integrity-enforcer/enforcer/pkg/config"

	log "github.com/sirupsen/logrus"

	"k8s.io/client-go/rest"
)

const DefaultRuleTableLockCMName = "ie-rule-table-lock"
const DefaultIgnoreSATableLockCMName = "ie-ignore-sa-table-lock"
const DefaultForceCheckSATableLockCMName = "ie-force-check-sa-table-lock"

// RuleTable

type RuleTableLoader struct {
	RPPClient *rppclient.ResearchV1alpha1Client
	// ConfigMapClient xxxxxx
	Rule         *protect.RuleTable
	IgnoreSA     *protect.SARuleTable
	ForceCheckSA *protect.SARuleTable

	enforcerNamespace string
}

func NewRuleTableLoader(enforcerNamespace string) *RuleTableLoader {
	config, _ := rest.InClusterConfig()
	rppClient, _ := rppclient.NewForConfig(config)

	return &RuleTableLoader{
		RPPClient:         rppClient,
		Rule:              protect.NewRuleTable(),
		IgnoreSA:          protect.NewSARuleTable(),
		ForceCheckSA:      protect.NewSARuleTable(),
		enforcerNamespace: enforcerNamespace,
	}
}

func InitRuleTable(namespace, name string) error {
	config, _ := rest.InClusterConfig()
	rppClient, _ := rppclient.NewForConfig(config)
	// list RPP in all namespaces
	list1, err := rppClient.ResourceProtectionProfiles("").List(metav1.ListOptions{})
	if err != nil {
		return err
	}

	table := protect.NewRuleTable()
	for _, rpp := range list1.Items {
		singleTable := rpp.ToRuleTable()
		stb, _ := json.Marshal(singleTable)
		logger.Debug("[SingleTable]", string(stb))
		if !rpp.Spec.Disabled {
			table = table.Merge(singleTable)
		}
	}
	table.Update(namespace, name)
	return nil
}

func InitIgnoreSARuleTable(namespace, name string) error {
	config, _ := rest.InClusterConfig()
	rppClient, _ := rppclient.NewForConfig(config)
	// list RPP in all namespaces
	list1, err := rppClient.ResourceProtectionProfiles("").List(metav1.ListOptions{})
	if err != nil {
		return err
	}

	table := protect.NewSARuleTable()
	for _, rpp := range list1.Items {
		singleTable := rpp.ToIgnoreSARuleTable()
		stb, _ := json.Marshal(singleTable)
		logger.Debug("[SingleIgnoreSATable]", string(stb))
		if !rpp.Spec.Disabled {
			table = table.Merge(singleTable)
		}
	}
	table.Update(namespace, name)
	return nil
}

func InitForceCheckSARuleTable(namespace, name string) error {
	config, _ := rest.InClusterConfig()
	rppClient, _ := rppclient.NewForConfig(config)
	// list RPP in all namespaces
	list1, err := rppClient.ResourceProtectionProfiles("").List(metav1.ListOptions{})
	if err != nil {
		return err
	}

	table := protect.NewSARuleTable()
	for _, rpp := range list1.Items {
		singleTable := rpp.ToForceCheckSARuleTable()
		stb, _ := json.Marshal(singleTable)
		logger.Debug("[SingleForceCheckSATable]", string(stb))
		if !rpp.Spec.Disabled {
			table = table.Merge(singleTable)
		}
	}
	table.Update(namespace, name)
	return nil
}

func (self *RuleTableLoader) GetData() *protect.RuleTable {
	self.Load()
	return self.Rule
}

func (self *RuleTableLoader) GetIgnoreSAData() *protect.SARuleTable {
	self.Load()
	return self.IgnoreSA
}

func (self *RuleTableLoader) GetForceCheckSAData() *protect.SARuleTable {
	self.Load()
	return self.ForceCheckSA
}

func (self *RuleTableLoader) Load() {
	tmpData, err := protect.GetRuleTable(self.enforcerNamespace, DefaultRuleTableLockCMName)
	if err != nil {
		logger.Error(err)
	}
	self.Rule = tmpData
	tmpSAData, err := protect.GetSARuleTable(self.enforcerNamespace, DefaultIgnoreSATableLockCMName)
	if err != nil {
		logger.Error(err)
	}
	self.IgnoreSA = tmpSAData
	tmpSAData2, err := protect.GetSARuleTable(self.enforcerNamespace, DefaultForceCheckSATableLockCMName)
	if err != nil {
		logger.Error(err)
	}
	self.ForceCheckSA = tmpSAData2
	return
}

func (self *RuleTableLoader) Update(reqc *common.ReqContext) error {
	ref := &v1.ObjectReference{
		APIVersion: reqc.GroupVersion(),
		Kind:       reqc.Kind,
		Name:       reqc.Name,
		Namespace:  reqc.Namespace,
	}
	tmpData, err := protect.GetRuleTable(self.enforcerNamespace, DefaultRuleTableLockCMName)
	if err != nil {
		logger.Error(err)
	}
	tmpData = tmpData.Remove(ref)

	tmpSAData, err := protect.GetSARuleTable(self.enforcerNamespace, DefaultIgnoreSATableLockCMName)
	if err != nil {
		logger.Error(err)
	}
	tmpSAData = tmpSAData.Remove(ref)

	tmpSAData2, err := protect.GetSARuleTable(self.enforcerNamespace, DefaultForceCheckSATableLockCMName)
	if err != nil {
		logger.Error(err)
	}
	tmpSAData2 = tmpSAData2.Remove(ref)

	if reqc.IsCreateRequest() || reqc.IsUpdateRequest() {
		var newProfile rppapi.ResourceProtectionProfile
		err = json.Unmarshal(reqc.RawObject, &newProfile)
		if err != nil {
			logger.Error(err)
		}
		tmpData = tmpData.Add(newProfile.Spec.Rules, ref)
		tmpSAData = tmpSAData.Add(newProfile.Spec.IgnoreServiceAccounts, ref)
		tmpSAData2 = tmpSAData2.Add(newProfile.Spec.ForceCheckServiceAccounts, ref)
	}

	self.Rule = tmpData
	self.Rule.Update(self.enforcerNamespace, DefaultRuleTableLockCMName)

	self.IgnoreSA = tmpSAData
	self.IgnoreSA.Update(self.enforcerNamespace, DefaultIgnoreSATableLockCMName)

	self.ForceCheckSA = tmpSAData2
	self.ForceCheckSA.Update(self.enforcerNamespace, DefaultForceCheckSATableLockCMName)
	return nil
}

// ResourceProtectionProfile

type RPPLoader struct {
	enforcerNamespace      string
	profileNamespace       string
	requestNamespace       string
	defaultProfileName     string
	defaultProfileInterval time.Duration

	Client *rppclient.ResearchV1alpha1Client
	Data   []rppapi.ResourceProtectionProfile
}

func NewRPPLoader(enforcerNamespace, profileNamespace, requestNamespace string) *RPPLoader {
	defaultProfileInterval := time.Second * 60
	config, _ := rest.InClusterConfig()
	client, _ := rppclient.NewForConfig(config)

	return &RPPLoader{
		enforcerNamespace:      enforcerNamespace,
		profileNamespace:       profileNamespace,
		requestNamespace:       requestNamespace,
		defaultProfileName:     "default-rpp",
		defaultProfileInterval: defaultProfileInterval,
		Client:                 client,
	}
}

func (self *RPPLoader) GetData() []rppapi.ResourceProtectionProfile {
	if len(self.Data) == 0 {
		self.Load()
	}
	return self.Data
}

func (self *RPPLoader) Load() {
	var err error
	var list1, list2, list3 *rppapi.ResourceProtectionProfileList
	var keyName string

	keyName = fmt.Sprintf("RPPLoader/%s/list", self.enforcerNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		list1, err = self.Client.ResourceProtectionProfiles(self.enforcerNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Error("failed to get ResourceProtectionProfile:", err)
			return
		}
		logger.Debug("ResourceProtectionProfile reloaded.")
		if len(list1.Items) > 0 {
			tmp, _ := json.Marshal(list1)
			cache.SetString(keyName, string(tmp), &(self.defaultProfileInterval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list1)
		if err != nil {
			logger.Error("failed to Unmarshal cached ResourceProtectionProfile:", err)
			return
		}
	}

	keyName = fmt.Sprintf("RPPLoader/%s/list", self.profileNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		list2, err = self.Client.ResourceProtectionProfiles(self.profileNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Error("failed to get ResourceProtectionProfile:", err)
			return
		}
		logger.Debug("ResourceProtectionProfile reloaded.")
		if len(list2.Items) > 0 {
			tmp, _ := json.Marshal(list2)
			cache.SetString(keyName, string(tmp), &(self.defaultProfileInterval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list2)
		if err != nil {
			logger.Error("failed to Unmarshal cached ResourceProtectionProfile:", err)
			return
		}
	}

	keyName = fmt.Sprintf("RPPLoader/%s/list", self.requestNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		list3, err = self.Client.ResourceProtectionProfiles(self.requestNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Error("failed to get ResourceProtectionProfile:", err)
			return
		}
		logger.Debug("ResourceProtectionProfile reloaded.")
		if len(list3.Items) > 0 {
			tmp, _ := json.Marshal(list3)
			cache.SetString(keyName, string(tmp), &(self.defaultProfileInterval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list3)
		if err != nil {
			logger.Error("failed to Unmarshal cached ResourceProtectionProfile:", err)
			return
		}
	}
	data := []rppapi.ResourceProtectionProfile{}
	for _, d := range list1.Items {
		data = append(data, d)
	}
	for _, d := range list2.Items {
		data = append(data, d)
	}
	for _, d := range list3.Items {
		data = append(data, d)
	}
	self.Data = data
	return
}

func (self *RPPLoader) GetByReferences(refs []*v1.ObjectReference) []rppapi.ResourceProtectionProfile {
	data := []rppapi.ResourceProtectionProfile{}
	for _, ref := range refs {
		d, err := self.Client.ResourceProtectionProfiles(ref.Namespace).Get(ref.Name, metav1.GetOptions{})
		if err != nil {
			logger.Error(err)
		} else {
			data = append(data, *d)
		}
	}
	// add empty RPP if there is no matched reference, to enable default RPP even in the case
	if len(data) == 0 {
		emptyProfile := rppapi.ResourceProtectionProfile{}
		emptyProfile.SetNamespace(self.enforcerNamespace)
		emptyProfile.SetName("default-rpp")
		data = []rppapi.ResourceProtectionProfile{
			emptyProfile,
		}
	}
	data, err := self.MergeDefaultProfiles(data)
	if err != nil {
		logger.Error(err)
	}
	return data
}

func (self *RPPLoader) MergeDefaultProfiles(data []rppapi.ResourceProtectionProfile) ([]rppapi.ResourceProtectionProfile, error) {
	dp, err := self.GetDefaultProfile()
	if err != nil {
		logger.Error(err)
	} else {
		for i, d := range data {
			data[i] = d.Merge(*dp)
		}
	}
	return data, nil
}

func (self *RPPLoader) GetDefaultProfile() (*rppapi.ResourceProtectionProfile, error) {
	var rpp *rppapi.ResourceProtectionProfile
	var err error

	keyName := fmt.Sprintf("RPPLoader/%s/get/%s", self.enforcerNamespace, self.defaultProfileName)
	if cached := cache.GetString(keyName); cached == "" {
		rpp, err = self.Client.ResourceProtectionProfiles(self.enforcerNamespace).Get(self.defaultProfileName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get ResourceProtectionProfile: %s", err.Error())
		}
		logger.Debug("ResourceProtectionProfile reloaded.")
		if rpp != nil {
			tmp, _ := json.Marshal(rpp)
			cache.SetString(keyName, string(tmp), &(self.defaultProfileInterval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &rpp)
		if err != nil {
			return nil, fmt.Errorf("failed to Unmarshal cached ResourceProtectionProfile: %s", err.Error())
		}
	}
	return rpp, nil
}

func (self *RPPLoader) GetProfileInterface() []protect.ProtectionProfile {
	profiles := []protect.ProtectionProfile{}
	for _, d := range self.GetData() {
		profiles = append(profiles, d)
	}
	return profiles
}

type ProtectionProfileLoader interface {
	GetProfileInterface() []protect.ProtectionProfile
}

// SignPolicy

type SignPolicyLoader struct {
	interval          time.Duration
	enforcerNamespace string

	Client *spolclient.ResearchV1alpha1Client
	Data   *spolapi.SignPolicy
}

func NewSignPolicyLoader(enforcerNamespace string) *SignPolicyLoader {
	interval := time.Second * 10
	config, _ := rest.InClusterConfig()
	client, _ := spolclient.NewForConfig(config)

	return &SignPolicyLoader{
		interval:          interval,
		enforcerNamespace: enforcerNamespace,
		Client:            client,
	}
}

func (self *SignPolicyLoader) GetData() *spolapi.SignPolicy {
	if self.Data == nil {
		self.Load()
	}
	return self.Data
}

func (self *SignPolicyLoader) Load() {
	var err error
	var list1 *spolapi.SignPolicyList
	var keyName string

	keyName = fmt.Sprintf("SignPolicyLoader/%s/list", self.enforcerNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		list1, err = self.Client.SignPolicies(self.enforcerNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Error("failed to get SignPolicy:", err)
			return
		}
		logger.Debug("SignPolicy reloaded.")
		if len(list1.Items) > 0 {
			tmp, _ := json.Marshal(list1)
			cache.SetString(keyName, string(tmp), &(self.interval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list1)
		if err != nil {
			logger.Error("failed to Unmarshal cached SignPolicy:", err)
			return
		}
	}

	data := &spolapi.SignPolicy{}
	if len(list1.Items) > 0 {
		data = &(list1.Items[0])
	}
	self.Data = data
	return
}

// ResourceSignature

type ResSigLoader struct {
	interval           time.Duration
	signatureNamespace string
	requestNamespace   string

	Client *rsigclient.ResearchV1alpha1Client
	Data   []*rsigapi.ResourceSignature
}

func NewResSigLoader(signatureNamespace, requestNamespace string) *ResSigLoader {
	interval := time.Second * 0
	config, _ := rest.InClusterConfig()
	client, _ := rsigclient.NewForConfig(config)

	return &ResSigLoader{
		interval:           interval,
		signatureNamespace: signatureNamespace,
		requestNamespace:   requestNamespace,
		Client:             client,
	}
}

func (self *ResSigLoader) GetData() []*rsigapi.ResourceSignature {
	if len(self.Data) == 0 {
		self.Load()
	}
	return self.Data
}

func (self *ResSigLoader) Load() {
	var err error
	var list1, list2 *rsigapi.ResourceSignatureList
	var keyName string

	keyName = fmt.Sprintf("ResSigLoader/%s/list", self.signatureNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		list1, err = self.Client.ResourceSignatures(self.signatureNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Error("failed to get ResourceSignature:", err)
			return
		}
		logger.Debug("ResourceSignature reloaded.")
		if len(list1.Items) > 0 {
			tmp, _ := json.Marshal(list1)
			cache.SetString(keyName, string(tmp), &(self.interval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list1)
		if err != nil {
			logger.Error("failed to Unmarshal cached ResourceSignature:", err)
			return
		}
	}
	keyName = fmt.Sprintf("ResSigLoader/%s/list", self.requestNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		list2, err = self.Client.ResourceSignatures(self.requestNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Error("failed to get ResourceSignature:", err)
			return
		}
		logger.Debug("ResourceSignature reloaded.")
		if len(list2.Items) > 0 {
			tmp, _ := json.Marshal(list2)
			cache.SetString(keyName, string(tmp), &(self.interval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list2)
		if err != nil {
			logger.Error("failed to Unmarshal cached ResourceSignature:", err)
			return
		}
	}

	data := []*rsigapi.ResourceSignature{}
	for _, d := range list1.Items {
		data = append(data, d)
	}
	for _, d := range list2.Items {
		data = append(data, d)
	}
	sortedData := sortByCreationTimestamp(data)
	self.Data = sortedData
	return
}

func sortByCreationTimestamp(items []*rsigapi.ResourceSignature) []*rsigapi.ResourceSignature {
	items2 := make([]*rsigapi.ResourceSignature, len(items))
	copy(items2, items)
	sort.Slice(items2, func(i, j int) bool {
		ti := items2[i].GetCreationTimestamp()
		tj := items2[j].GetCreationTimestamp()
		return ti.Time.After(tj.Time)
	})
	return items2
}

func LoadEnforceConfig(namespace, cmname string) *cfg.EnforcerConfig {

	config, err := rest.InClusterConfig()
	if err != nil {
		return nil
	}
	clientset, err := ecfgclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return nil
	}
	ecres, err := clientset.EnforcerConfigs(namespace).Get(cmname, metav1.GetOptions{})
	if err != nil {
		log.Error("failed to get EnforcerConfig:", err.Error())
		return nil
	}

	ec := ecres.Spec.EnforcerConfig
	return ec
}
