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
	"reflect"
	"time"

	ecfg "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/enforcerconfig/v1alpha1"
	iespol "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/signpolicy/v1alpha1"
	cache "github.com/IBM/integrity-enforcer/enforcer/pkg/cache"

	ecfgclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/enforcerconfig/clientset/versioned/typed/enforcerconfig/v1alpha1"
	iespolclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/signpolicy/clientset/versioned/typed/signpolicy/v1alpha1"
	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/logger"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/policy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/rest"
)

type PolicyLoader struct {
	enforcerNamespace string
	policyNamespace   string
	iePolicyInterval  time.Duration
	appPolicyInterval time.Duration

	enforcerConfigClient *ecfgclient.ResearchV1alpha1Client
	signPolicyClient     *iespolclient.ResearchV1alpha1Client

	Policy      *policy.PolicyList
	lastUpdated time.Time
}

func NewPolicyLoader(enforcerNamespace, policyNamespace string) *PolicyLoader {
	iePolicyInterval := time.Second * 10
	appPolicyInterval := time.Second * 10
	config, _ := rest.InClusterConfig()

	enforcerConfigClient, _ := ecfgclient.NewForConfig(config)
	signPolicyClient, _ := iespolclient.NewForConfig(config)

	return &PolicyLoader{
		enforcerNamespace: enforcerNamespace,
		policyNamespace:   policyNamespace,
		iePolicyInterval:  iePolicyInterval,
		appPolicyInterval: appPolicyInterval,

		enforcerConfigClient: enforcerConfigClient,
		signPolicyClient:     signPolicyClient,
	}
}

func (self *PolicyLoader) Load(requestNamespace string) {

	renew := false
	t := time.Now()
	if self.Policy != nil {
		interval := self.appPolicyInterval
		duration := t.Sub(self.lastUpdated)
		if duration > interval {
			renew = true
		}
	} else {
		renew = true
	}

	if renew {
		reqNs := requestNamespace
		enforcerNs := self.enforcerNamespace
		policyNs := self.policyNamespace
		enforcePolicy := self.loadEnforcePolicy(reqNs, enforcerNs, policyNs)

		if enforcePolicy != nil {
			changed := reflect.DeepEqual(enforcePolicy, self.Policy)
			if changed {
				logger.Info("Enforce Policy update reloaded")
			}
			self.Policy = enforcePolicy
			self.lastUpdated = t
		}
	}
}

func (self *PolicyLoader) loadEnforcePolicy(requestNamespace, enforcerNamespace, policyNamespace string) *policy.PolicyList {
	var err error
	var eCfgList *ecfg.EnforcerConfigList
	var sigPolList *iespol.SignPolicyList
	var keyName string

	keyName = "policyLoader/eCfgList"
	if cached := cache.GetString(keyName); cached == "" {
		eCfgList, err = self.enforcerConfigClient.EnforcerConfigs(enforcerNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Fatal("failed to get IntegrityEnforcerPolicy:", err)
			return nil
		}
		logger.Debug("IntegrityEnforcerPolicy reloaded.")
		if len(eCfgList.Items) > 0 {
			tmp, _ := json.Marshal(eCfgList)
			cache.SetString(keyName, string(tmp), &(self.iePolicyInterval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &eCfgList)
		if err != nil {
			logger.Fatal("failed to Unmarshal cached IntegrityEnforcerPolicy:", err)
			return nil
		}
	}

	keyName = "policyLoader/sigPolList"
	if cached := cache.GetString(keyName); cached == "" {
		sigPolList, err = self.signPolicyClient.SignPolicies(enforcerNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Fatal("failed to get SignPolicy:", err)
			return nil
		}
		logger.Debug("SignPolicy reloaded.")
		if len(sigPolList.Items) > 0 {
			tmp, _ := json.Marshal(sigPolList)
			cache.SetString(keyName, string(tmp), &(self.iePolicyInterval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &sigPolList)
		if err != nil {
			logger.Fatal("failed to Unmarshal cached SignPolicy:", err)
			return nil
		}
	}

	policyList := &policy.PolicyList{}
	for _, econfig := range eCfgList.Items {
		pol := econfig.Spec.EnforcerConfig.Policy.Policy()
		policyList.Add(pol)
	}
	for _, epol := range sigPolList.Items {
		pol := epol.Spec.SignPolicy.Policy()
		policyList.Add(pol)
	}
	return policyList

}
