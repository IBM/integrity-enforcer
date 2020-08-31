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
	"reflect"
	"time"

	apppol "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/appenforcepolicy/v1alpha1"
	iedpol "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/iedefaultpolicy/v1alpha1"
	iespol "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/iesignerpolicy/v1alpha1"
	iepol "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/integrityenforcerpolicy/v1alpha1"
	cache "github.com/IBM/integrity-enforcer/enforcer/pkg/cache"
	apppolclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/appenforcepolicy/clientset/versioned/typed/appenforcepolicy/v1alpha1"
	iedpolclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/iedefaultpolicy/clientset/versioned/typed/iedefaultpolicy/v1alpha1"
	iespolclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/iesignerpolicy/clientset/versioned/typed/iesignerpolicy/v1alpha1"
	iepolclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/integrityenforcerpolicy/clientset/versioned/typed/integrityenforcerpolicy/v1alpha1"
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

	iePolicyClient         *iepolclient.ResearchV1alpha1Client
	ieDefaultPolicyClient  *iedpolclient.ResearchV1alpha1Client
	ieSignerPolicyClient   *iespolclient.ResearchV1alpha1Client
	appEnforcePolicyClient *apppolclient.ResearchV1alpha1Client

	Policy      *policy.PolicyList
	lastUpdated time.Time
}

func NewPolicyLoader(enforcerNamespace, policyNamespace string) *PolicyLoader {
	iePolicyInterval := time.Second * 10
	appPolicyInterval := time.Second * 10
	config, _ := rest.InClusterConfig()

	iePolicyClient, _ := iepolclient.NewForConfig(config)
	ieDefaultPolicyClient, _ := iedpolclient.NewForConfig(config)
	ieSignerPolicyClient, _ := iespolclient.NewForConfig(config)
	appEnforcePolicyClient, _ := apppolclient.NewForConfig(config)

	return &PolicyLoader{
		enforcerNamespace: enforcerNamespace,
		policyNamespace:   policyNamespace,
		iePolicyInterval:  iePolicyInterval,
		appPolicyInterval: appPolicyInterval,

		iePolicyClient:         iePolicyClient,
		ieDefaultPolicyClient:  ieDefaultPolicyClient,
		ieSignerPolicyClient:   ieSignerPolicyClient,
		appEnforcePolicyClient: appEnforcePolicyClient,
	}
}

func (self *PolicyLoader) Load(requestNamespace string) {

	renew := true
	t := time.Now()

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
	var iePolList *iepol.IntegrityEnforcerPolicyList
	var defPolList *iedpol.IEDefaultPolicyList
	var sigPolList *iespol.IESignerPolicyList
	var appPolList *apppol.AppEnforcePolicyList
	var appPolList2 *apppol.AppEnforcePolicyList
	var keyName string

	keyName = "policyLoader/iePolList"
	if cached := cache.GetString(keyName); cached == "" {
		iePolList, err = self.iePolicyClient.IntegrityEnforcerPolicies(enforcerNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Fatal("failed to get IntegrityEnforcerPolicy:", err)
			return nil
		}
		logger.Debug("IntegrityEnforcerPolicy reloaded.")
		if len(iePolList.Items) > 0 {
			tmp, _ := json.Marshal(iePolList)
			cache.SetString(keyName, string(tmp), &(self.iePolicyInterval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &iePolList)
		if err != nil {
			logger.Fatal("failed to Unmarshal cached IntegrityEnforcerPolicy:", err)
			return nil
		}
	}

	keyName = "policyLoader/defPolList"
	if cached := cache.GetString(keyName); cached == "" {
		defPolList, err = self.ieDefaultPolicyClient.IEDefaultPolicies(enforcerNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Fatal("failed to get IEDefaultPolicy:", err)
			return nil
		}
		logger.Debug("IEDefaultPolicy reloaded.")
		if len(defPolList.Items) > 0 {
			tmp, _ := json.Marshal(defPolList)
			cache.SetString(keyName, string(tmp), &(self.iePolicyInterval))
		}

	} else {
		err = json.Unmarshal([]byte(cached), &defPolList)
		if err != nil {
			logger.Fatal("failed to Unmarshal cached IEDefaultPolicy:", err)
			return nil
		}
	}

	keyName = "policyLoader/sigPolList"
	if cached := cache.GetString(keyName); cached == "" {
		sigPolList, err = self.ieSignerPolicyClient.IESignerPolicies(enforcerNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Fatal("failed to get IESignerPolicy:", err)
			return nil
		}
		logger.Debug("IESignerPolicy reloaded.")
		if len(sigPolList.Items) > 0 {
			tmp, _ := json.Marshal(sigPolList)
			cache.SetString(keyName, string(tmp), &(self.iePolicyInterval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &sigPolList)
		if err != nil {
			logger.Fatal("failed to Unmarshal cached IESignerPolicy:", err)
			return nil
		}
	}

	keyName = fmt.Sprintf("policyLoader/appPolList/%s", requestNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		appPolList, err = self.appEnforcePolicyClient.AppEnforcePolicies(requestNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Fatal("failed to get AppEnforcePolicy:", err)
			return nil
		}
		logger.Debug("AppEnforcePolicy reloaded. namespace: ", requestNamespace)
		tmp, _ := json.Marshal(appPolList)
		cache.SetString(keyName, string(tmp), &(self.appPolicyInterval))
	} else {
		err = json.Unmarshal([]byte(cached), &appPolList)
		if err != nil {
			logger.Fatal("failed to Unmarshal cached AppEnforcePolicy:", err)
			return nil
		}
	}

	keyName = fmt.Sprintf("policyLoader/appPolList2/%s", policyNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		appPolList2, err = self.appEnforcePolicyClient.AppEnforcePolicies(policyNamespace).List(metav1.ListOptions{})
		if err != nil {
			logger.Fatal("failed to get AppEnforcePolicy2:", err)
			return nil
		}
		logger.Debug("AppEnforcePolicy2 reloaded. namespace: ", policyNamespace)
		tmp, _ := json.Marshal(appPolList2)
		cache.SetString(keyName, string(tmp), &(self.appPolicyInterval))
	} else {
		err = json.Unmarshal([]byte(cached), &appPolList2)
		if err != nil {
			logger.Fatal("failed to Unmarshal cached AppEnforcePolicy2:", err)
			return nil
		}
	}

	policyList := &policy.PolicyList{}
	for _, epol := range iePolList.Items {
		pol := epol.Spec.IntegrityEnforcerPolicy.Policy()
		policyList.Add(pol)
	}
	for _, epol := range defPolList.Items {
		pol := epol.Spec.IEDefaultPolicy.Policy()
		policyList.Add(pol)
	}
	for _, epol := range sigPolList.Items {
		pol := epol.Spec.IESignerPolicy.Policy()
		policyList.Add(pol)
	}
	for _, epol := range appPolList.Items {
		pol := epol.Spec.AppEnforcePolicy.Policy()
		policyList.Add(pol)
	}
	for _, epol := range appPolList2.Items {
		pol := epol.Spec.AppEnforcePolicy.Policy()
		policyList.Add(pol)
	}
	return policyList

}
