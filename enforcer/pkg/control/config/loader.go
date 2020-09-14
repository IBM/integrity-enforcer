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
	"time"

	cache "github.com/IBM/integrity-enforcer/enforcer/pkg/cache"

	crppapi "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/vclusterresourceprotectionprofile/v1alpha1"
	rppapi "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/vresourceprotectionprofile/v1alpha1"
	rsigapi "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/vresourcesignature/v1alpha1"
	spolapi "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/vsignpolicy/v1alpha1"
	crppclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/vclusterresourceprotectionprofile/clientset/versioned/typed/vclusterresourceprotectionprofile/v1alpha1"
	rppclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/vresourceprotectionprofile/clientset/versioned/typed/vresourceprotectionprofile/v1alpha1"
	rsigclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/vresourcesignature/clientset/versioned/typed/vresourcesignature/v1alpha1"
	spolclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/vsignpolicy/clientset/versioned/typed/vsignpolicy/v1alpha1"
	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/logger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/rest"
)

// ResourceProtectionProfile

type RPPLoader struct {
	enforcerNamespace string
	requestNamespace  string
	interval          time.Duration

	Client *rppclient.ResearchV1alpha1Client
	Data   []*rppapi.VResourceProtectionProfile
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

func (self *RPPLoader) GetData() []*rppapi.VResourceProtectionProfile {
	if len(self.Data) == 0 {
		self.Load()
	}
	return self.Data
}

func (self *RPPLoader) Load() {
	var err error
	var list1, list2 *rppapi.VResourceProtectionProfileList
	var keyName string

	keyName = fmt.Sprintf("RPPLoader/%s/list", self.enforcerNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		list1, err = self.Client.VResourceProtectionProfiles(self.enforcerNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Fatal("failed to get VResourceProtectionProfile:", err)
			return
		}
		logger.Debug("VResourceProtectionProfile reloaded.")
		if len(list1.Items) > 0 {
			tmp, _ := json.Marshal(list1)
			cache.SetString(keyName, string(tmp), &(self.interval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list1)
		if err != nil {
			logger.Fatal("failed to Unmarshal cached VResourceProtectionProfile:", err)
			return
		}
	}

	keyName = fmt.Sprintf("RPPLoader/%s/list", self.requestNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		list2, err = self.Client.VResourceProtectionProfiles(self.requestNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Fatal("failed to get VResourceProtectionProfile:", err)
			return
		}
		logger.Debug("VResourceProtectionProfile reloaded.")
		if len(list1.Items) > 0 {
			tmp, _ := json.Marshal(list2)
			cache.SetString(keyName, string(tmp), &(self.interval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list2)
		if err != nil {
			logger.Fatal("failed to Unmarshal cached VResourceProtectionProfile:", err)
			return
		}
	}

	data := []*rppapi.VResourceProtectionProfile{}
	for _, d := range list1.Items {
		data = append(data, &d)
	}
	for _, d := range list2.Items {
		data = append(data, &d)
	}
	self.Data = data
	return
}

// ClusterResourceProtectionProfile

type CRPPLoader struct {
	interval time.Duration

	Client *crppclient.ResearchV1alpha1Client
	Data   []*crppapi.VClusterResourceProtectionProfile
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

func (self *CRPPLoader) Load() {
	var err error
	var list1 *crppapi.VClusterResourceProtectionProfileList
	var keyName string

	keyName = "CRPPLoader/list"
	if cached := cache.GetString(keyName); cached == "" {
		list1, err = self.Client.VClusterResourceProtectionProfiles().List(metav1.ListOptions{})
		if err != nil {
			logger.Fatal("failed to get VClusterResourceProtectionProfile:", err)
			return
		}
		logger.Debug("VClusterResourceProtectionProfile reloaded.")
		if len(list1.Items) > 0 {
			tmp, _ := json.Marshal(list1)
			cache.SetString(keyName, string(tmp), &(self.interval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list1)
		if err != nil {
			logger.Fatal("failed to Unmarshal cached VClusterResourceProtectionProfile:", err)
			return
		}
	}

	data := []*crppapi.VClusterResourceProtectionProfile{}
	for _, d := range list1.Items {
		data = append(data, &d)
	}
	self.Data = data
	return
}

// SignPolicy

type SignPolicyLoader struct {
	interval          time.Duration
	enforcerNamespace string

	Client *spolclient.ResearchV1alpha1Client
	Data   []*spolapi.VSignPolicy
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

func (self *SignPolicyLoader) Load() {
	var err error
	var list1 *spolapi.VSignPolicyList
	var keyName string

	keyName = fmt.Sprintf("SignPolicyLoader/%s/list", self.enforcerNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		list1, err = self.Client.VSignPolicies(self.enforcerNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Fatal("failed to get VSignPolicy:", err)
			return
		}
		logger.Debug("VSignPolicy reloaded.")
		if len(list1.Items) > 0 {
			tmp, _ := json.Marshal(list1)
			cache.SetString(keyName, string(tmp), &(self.interval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list1)
		if err != nil {
			logger.Fatal("failed to Unmarshal cached VSignPolicy:", err)
			return
		}
	}

	data := []*spolapi.VSignPolicy{}
	for _, d := range list1.Items {
		data = append(data, &d)
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
	Data   []*rsigapi.VResourceSignature
}

func NewResSigLoader(signatureNamespace, requestNamespace string) *ResSigLoader {
	interval := time.Second * 0
	config, _ := rest.InClusterConfig()
	client, _ := rsigclient.NewForConfig(config)

	return &ResSigLoader{
		interval:           interval,
		signatureNamespace: signatureNamespace,
		Client:             client,
	}
}

func (self *ResSigLoader) Load() {
	var err error
	var list1, list2 *rsigapi.VResourceSignatureList
	var keyName string

	keyName = fmt.Sprintf("ResSigLoader/%s/list", self.signatureNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		list1, err = self.Client.VResourceSignatures(self.signatureNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Fatal("failed to get VResourceSignature:", err)
			return
		}
		logger.Debug("VResourceSignature reloaded.")
		if len(list1.Items) > 0 {
			tmp, _ := json.Marshal(list1)
			cache.SetString(keyName, string(tmp), &(self.interval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list1)
		if err != nil {
			logger.Fatal("failed to Unmarshal cached VResourceSignature:", err)
			return
		}
	}
	keyName = fmt.Sprintf("ResSigLoader/%s/list", self.requestNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		list2, err = self.Client.VResourceSignatures(self.requestNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Fatal("failed to get VResourceSignature:", err)
			return
		}
		logger.Debug("VResourceSignature reloaded.")
		if len(list2.Items) > 0 {
			tmp, _ := json.Marshal(list2)
			cache.SetString(keyName, string(tmp), &(self.interval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list2)
		if err != nil {
			logger.Fatal("failed to Unmarshal cached VResourceSignature:", err)
			return
		}
	}

	data := []*rsigapi.VResourceSignature{}
	for _, d := range list1.Items {
		data = append(data, &d)
	}
	for _, d := range list2.Items {
		data = append(data, &d)
	}
	self.Data = data
	return
}
