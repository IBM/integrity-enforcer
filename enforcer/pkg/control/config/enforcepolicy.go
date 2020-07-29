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

	allPolicies := []*policy.Policy{}
	for _, epol := range epolList.Items {
		allPolicies = append(allPolicies, epol.Spec.Policy)
	}
	for _, epol := range perNsEpolList.Items {
		allPolicies = append(allPolicies, epol.Spec.Policy)

	}
	for _, epol := range polNsEpolList.Items {
		allPolicies = append(allPolicies, epol.Spec.Policy)

	}

	orderedPolicyMap := map[string]*policy.Policy{
		"signer":     {},
		"filter":     {},
		"whitelist":  {},
		"unverified": {},
		"mode":       {}, // TODO: design & implement mode policy (enforce/detection)
		"ignore":     {},
	}

	for _, pol := range allPolicies {
		if pol.PolicyType == policy.SignerPolicy {
			orderedPolicyMap["signer"] = orderedPolicyMap["signer"].Merge(pol)
			orderedPolicyMap["unverified"] = orderedPolicyMap["unverified"].Merge(pol)
		}
		if pol.PolicyType == policy.IEPolicy {
			orderedPolicyMap["filter"] = orderedPolicyMap["filter"].Merge(pol)
			orderedPolicyMap["whitelist"] = orderedPolicyMap["whitelist"].Merge(pol)
			orderedPolicyMap["mode"] = orderedPolicyMap["mode"].Merge(pol)
			orderedPolicyMap["ignore"] = orderedPolicyMap["ignore"].Merge(pol)
		}
		if pol.PolicyType == policy.DefaultPolicy {
			orderedPolicyMap["filter"] = orderedPolicyMap["filter"].Merge(pol)
			orderedPolicyMap["whitelist"] = orderedPolicyMap["whitelist"].Merge(pol)
		}
		if pol.PolicyType == policy.CustomPolicy {
			orderedPolicyMap["signer"] = orderedPolicyMap["signer"].Merge(pol)
			orderedPolicyMap["filter"] = orderedPolicyMap["filter"].Merge(pol)
			orderedPolicyMap["whitelist"] = orderedPolicyMap["whitelist"].Merge(pol)
		}

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
