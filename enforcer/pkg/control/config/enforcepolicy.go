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
	"log"

	epolclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/enforcepolicy/clientset/versioned/typed/enforcepolicy/v1alpha1"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/policy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/rest"
)

func LoadEnforcePolicy(requestNamespace, enforcerNamespace, policyNamespace string) *policy.Policy {

	config, err := rest.InClusterConfig()
	if err != nil {
		return nil
	}
	clientset, err := epolclient.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	epolList, err := clientset.EnforcePolicies(enforcerNamespace).List(metav1.ListOptions{})
	if err != nil {
		log.Fatalln("failed to get EnforcePolicy:", err)
		return nil
	}
	perNsEpolList, err := clientset.EnforcePolicies(requestNamespace).List(metav1.ListOptions{})
	if err != nil {
		log.Fatalln("failed to get EnforcePolicy:", err)
		return nil
	}
	polNsEpolList, err := clientset.EnforcePolicies(policyNamespace).List(metav1.ListOptions{})
	if err != nil {
		log.Fatalln("failed to get EnforcePolicy:", err)
		return nil
	}

	policyMap := map[policy.PolicyType]*policy.Policy{}
	policyMap[policy.IEPolicy] = &policy.Policy{}
	policyMap[policy.DefaultPolicy] = &policy.Policy{}
	policyMap[policy.SignerPolicy] = &policy.Policy{}
	policyMap[policy.CustomPolicy] = &policy.Policy{}

	for _, epol := range epolList.Items {
		pType := epol.Spec.Policy.PolicyType
		policyMap[pType] = policyMap[pType].Merge(epol.Spec.Policy)
	}
	for _, epol := range perNsEpolList.Items {
		pType := epol.Spec.Policy.PolicyType
		policyMap[pType] = policyMap[pType].Merge(epol.Spec.Policy)
	}
	for _, epol := range polNsEpolList.Items {
		pType := epol.Spec.Policy.PolicyType
		policyMap[pType] = policyMap[pType].Merge(epol.Spec.Policy)
	}

	orderedPolicyMap := map[string]*policy.Policy{
		"signer":     {},
		"filter":     {},
		"whitelist":  {},
		"unverified": {},
		"mode":       {}, // TODO: design & implement mode policy (enforce/detection)
		"ignore":     {},
	}

	for key, pol := range orderedPolicyMap {
		if key == "signer" {
			pol = pol.Merge(policyMap[policy.SignerPolicy])
			pol = pol.Merge(policyMap[policy.CustomPolicy])
		} else if key == "filter" {
			pol = pol.Merge(policyMap[policy.IEPolicy])
			pol = pol.Merge(policyMap[policy.DefaultPolicy])
			pol = pol.Merge(policyMap[policy.CustomPolicy])
		} else if key == "whitelist" {
			pol = pol.Merge(policyMap[policy.IEPolicy])
			pol = pol.Merge(policyMap[policy.DefaultPolicy])
			pol = pol.Merge(policyMap[policy.CustomPolicy])
		} else if key == "unverified" {
			pol = pol.Merge(policyMap[policy.SignerPolicy])
		} else if key == "mode" {
			pol = pol.Merge(policyMap[policy.IEPolicy])
		} else if key == "ignore" {
			pol = pol.Merge(policyMap[policy.IEPolicy])
		}
		orderedPolicyMap[key] = pol
	}

	pol := &policy.Policy{
		AllowUnverified:           orderedPolicyMap["unverified"].AllowUnverified,
		IgnoreRequest:             orderedPolicyMap["ignore"].IgnoreRequest,
		AllowedSigner:             orderedPolicyMap["signer"].AllowedSigner,
		AllowedForInternalRequest: orderedPolicyMap["filter"].AllowedForInternalRequest,
		AllowedChange:             orderedPolicyMap["whitelist"].AllowedChange,
	}

	return pol

}
