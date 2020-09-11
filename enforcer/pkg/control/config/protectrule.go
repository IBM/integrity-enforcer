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

	rppapi "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/vresourceprotectionprofile/v1alpha1"
	crppclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/vclusterresourceprotectionprofile/clientset/versioned/typed/vclusterresourceprotectionprofile/v1alpha1"
	rppclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/vresourceprotectionprofile/clientset/versioned/typed/vresourceprotectionprofile/v1alpha1"

	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/logger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/rest"
)

type ProtectRuleLoader struct {
	enforcerNamespace string
	rppInterval       time.Duration
	crppInterval      time.Duration

	RPPClient  *rppclient.ResearchV1alpha1Client
	CRPPClient *crppclient.ResearchV1alpha1Client

	RPP         []*rppapi.VResourceProtectionProfile
	CRPP        []*rppapi.VClusterResourceProtectionProfile
	lastUpdated time.Time
}

func NewProtectRuleLoader(enforcerNamespace string) *ProtectRuleLoader {
	rppInterval := time.Second * 10
	crppInterval := time.Second * 10
	config, _ := rest.InClusterConfig()

	RPPClient, _ := rppclient.NewForConfig(config)
	CRPPClient, _ := crppclient.NewForConfig(config)

	return &ProtectRuleLoader{
		enforcerNamespace: enforcerNamespace,
		rppInterval:       rppInterval,
		crppInterval:      crppInterval,

		RPPClient:  rppClient,
		CRPPClient: crppClient,
	}
}

func (self *ProtectRuleLoader) Load(requestNamespace string) {
	reqNs := requestNamespace
	enforcerNs := self.enforcerNamespace
	self.loadProtectRule(reqNs, enforcerNs)
}

func (self *PolicyLoader) loadProtectRule(requestNamespace, enforcerNamespace string) {
	var err error
	var rppList1, rppList2 *rppapi.VResourceProtectionProfile
	var crppList *crppapi.VClusterResourceProtectionProfile
	var keyName string

	keyName = fmt.Sprintf("protectRuleLoader/rpp/%s", requestNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		rppList1, err = self.RPPClient.VResourceProtectionProfile(requestNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Fatal("failed to get VResourceProtectionProfile:", err)
			return nil
		}
		logger.Debug("VResourceProtectionProfile reloaded.")
		if len(rppList1.Items) > 0 {
			tmp, _ := json.Marshal(rppList)
			cache.SetString(keyName, string(tmp), &(self.rppInterval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &rppList1)
		if err != nil {
			logger.Fatal("failed to Unmarshal cached VResourceProtectionProfile:", err)
			return nil
		}
	}

	keyName = fmt.Sprintf("protectRuleLoader/rpp/%s", enforcerNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		rppList2, err = self.RPPClient.VResourceProtectionProfile(enforcerNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Fatal("failed to get VResourceProtectionProfile:", err)
			return nil
		}
		logger.Debug("VResourceProtectionProfile reloaded.")
		if len(rppList2.Items) > 0 {
			tmp, _ := json.Marshal(rppList2)
			cache.SetString(keyName, string(tmp), &(self.rppInterval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &rppList2)
		if err != nil {
			logger.Fatal("failed to Unmarshal cached VResourceProtectionProfile:", err)
			return nil
		}
	}

	keyName = "protectRuleLoader/crpp"
	if cached := cache.GetString(keyName); cached == "" {
		crppList, err = self.CRPPClient.VClusterResourceProtectionProfile().List(metav1.ListOptions{})
		if err != nil {
			logger.Fatal("failed to get VClusterResourceProtectionProfile:", err)
			return nil
		}
		logger.Debug("VClusterResourceProtectionProfile reloaded.")
		if len(crppList.Items) > 0 {
			tmp, _ := json.Marshal(crppList)
			cache.SetString(keyName, string(tmp), &(self.rppInterval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &crppList)
		if err != nil {
			logger.Fatal("failed to Unmarshal cached VClusterResourceProtectionProfile:", err)
			return nil
		}
	}

	self.RPP = []*rppapi.VResourceProtectionProfile{}
	self.CRPP = []*rppapi.VClusterResourceProtectionProfile{}

	self.RPP = append(self.RPP, rppList1...)
	self.RPP = append(self.RPP, rppList2...)
	self.CRPP = append(self.CRPP, crppList...)
	return
}
