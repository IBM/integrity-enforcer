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
	"github.com/IBM/integrity-enforcer/enforcer/pkg/protect"

	"log"

	crppapi "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/clusterresourceprotectionprofile/v1alpha1"
	rppapi "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourceprotectionprofile/v1alpha1"
	rsigapi "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourcesignature/v1alpha1"
	spolapi "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/signpolicy/v1alpha1"
	crppclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/clusterresourceprotectionprofile/clientset/versioned/typed/clusterresourceprotectionprofile/v1alpha1"
	rppclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/resourceprotectionprofile/clientset/versioned/typed/resourceprotectionprofile/v1alpha1"
	rsigclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/resourcesignature/clientset/versioned/typed/resourcesignature/v1alpha1"
	spolclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/signpolicy/clientset/versioned/typed/signpolicy/v1alpha1"
	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/logger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ecfgclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/enforcerconfig/clientset/versioned/typed/enforcerconfig/v1alpha1"
	cfg "github.com/IBM/integrity-enforcer/enforcer/pkg/config"

	"k8s.io/client-go/rest"
)

// ResourceProtectionProfile

type RPPLoader struct {
	enforcerNamespace string
	requestNamespace  string
	interval          time.Duration

	Client *rppclient.ResearchV1alpha1Client
	Data   []*rppapi.ResourceProtectionProfile
}

func NewRPPLoader(enforcerNamespace, requestNamespace string) *RPPLoader {
	interval := time.Second * 10
	config, _ := rest.InClusterConfig()
	client, _ := rppclient.NewForConfig(config)

	return &RPPLoader{
		enforcerNamespace: enforcerNamespace,
		requestNamespace:  requestNamespace,
		interval:          interval,
		Client:            client,
	}
}

func (self *RPPLoader) GetData() []*rppapi.ResourceProtectionProfile {
	if len(self.Data) == 0 {
		self.Load()
	}
	return self.Data
}

func (self *RPPLoader) Load() {
	var err error
	var list1, list2 *rppapi.ResourceProtectionProfileList
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
			cache.SetString(keyName, string(tmp), &(self.interval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list1)
		if err != nil {
			logger.Error("failed to Unmarshal cached ResourceProtectionProfile:", err)
			return
		}
	}

	keyName = fmt.Sprintf("RPPLoader/%s/list", self.requestNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		list2, err = self.Client.ResourceProtectionProfiles(self.requestNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Error("failed to get ResourceProtectionProfile:", err)
			return
		}
		logger.Debug("ResourceProtectionProfile reloaded.")
		if len(list1.Items) > 0 {
			tmp, _ := json.Marshal(list2)
			cache.SetString(keyName, string(tmp), &(self.interval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list2)
		if err != nil {
			logger.Error("failed to Unmarshal cached ResourceProtectionProfile:", err)
			return
		}
	}

	data := []*rppapi.ResourceProtectionProfile{}
	for _, d := range list1.Items {
		data = append(data, &d)
	}
	for _, d := range list2.Items {
		data = append(data, &d)
	}
	self.Data = data
	return
}

func (self *RPPLoader) GetProfileInterface() []protect.ProtectionProfile {
	profiles := []protect.ProtectionProfile{}
	for _, d := range self.GetData() {
		profiles = append(profiles, d)
	}
	return profiles
}

func (self *RPPLoader) Update(profiles []protect.ProtectionProfile) error {
	for _, profile := range profiles {
		rpp, ok := profile.(*rppapi.ResourceProtectionProfile)
		if !ok {
			continue
		}
		_, err := self.Client.ResourceProtectionProfiles(rpp.GetNamespace()).Update(rpp)
		if err != nil {
			return err
		}
	}
	return nil
}

// ClusterResourceProtectionProfile

type CRPPLoader struct {
	interval time.Duration

	Client *crppclient.ResearchV1alpha1Client
	Data   []*crppapi.ClusterResourceProtectionProfile
}

func NewCRPPLoader() *CRPPLoader {
	interval := time.Second * 10
	config, _ := rest.InClusterConfig()
	client, _ := crppclient.NewForConfig(config)

	return &CRPPLoader{
		interval: interval,
		Client:   client,
	}
}

func (self *CRPPLoader) GetData() []*crppapi.ClusterResourceProtectionProfile {
	if len(self.Data) == 0 {
		self.Load()
	}
	return self.Data
}

func (self *CRPPLoader) Load() {
	var err error
	var list1 *crppapi.ClusterResourceProtectionProfileList
	var keyName string

	keyName = "CRPPLoader/list"
	if cached := cache.GetString(keyName); cached == "" {
		list1, err = self.Client.ClusterResourceProtectionProfiles().List(metav1.ListOptions{})
		if err != nil {
			logger.Error("failed to get ClusterResourceProtectionProfile:", err)
			return
		}
		logger.Debug("ClusterResourceProtectionProfile reloaded.")
		if len(list1.Items) > 0 {
			tmp, _ := json.Marshal(list1)
			cache.SetString(keyName, string(tmp), &(self.interval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list1)
		if err != nil {
			logger.Error("failed to Unmarshal cached ClusterResourceProtectionProfile:", err)
			return
		}
	}

	data := []*crppapi.ClusterResourceProtectionProfile{}
	for _, d := range list1.Items {
		data = append(data, &d)
	}
	self.Data = data
	return
}

func (self *CRPPLoader) GetProfileInterface() []protect.ProtectionProfile {
	profiles := []protect.ProtectionProfile{}
	for _, d := range self.GetData() {
		profiles = append(profiles, d)
	}
	return profiles
}

func (self *CRPPLoader) Update(profiles []protect.ProtectionProfile) error {
	for _, profile := range profiles {
		crpp, ok := profile.(*crppapi.ClusterResourceProtectionProfile)
		if !ok {
			continue
		}
		_, err := self.Client.ClusterResourceProtectionProfiles().Update(crpp)
		if err != nil {
			return err
		}
	}
	return nil
}

type ProtectionProfileLoader interface {
	GetProfileInterface() []protect.ProtectionProfile
	Update(profiles []protect.ProtectionProfile) error
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
			tmpItems := sortByCreationTimestamp(list1.Items)
			list1.Items = tmpItems
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
	self.Data = data
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
		log.Fatal(err)
		return nil
	}
	ecres, err := clientset.EnforcerConfigs(namespace).Get(cmname, metav1.GetOptions{})
	if err != nil {
		log.Fatalln("failed to get EnforcerConfig:", err)
		return nil
	}

	ec := ecres.Spec.EnforcerConfig
	return ec
}
