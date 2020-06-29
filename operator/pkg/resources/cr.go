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

package resources

import (
	"io/ioutil"

	epol "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/enforcepolicy/v1alpha1"
	ec "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/enforcerconfig/v1alpha1"
	rs "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourcesignature/v1alpha1"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/policy"
	researchv1alpha1 "github.com/IBM/integrity-enforcer/operator/pkg/apis/research/v1alpha1"
	"github.com/ghodss/yaml"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const iePolicyName = "ie-policy"
const defaultPolicyName = "default-policy"
const signerPolicyName = "signer-policy"
const defaultPolicyYamlPath = "/resources/default-policy.yaml"

// enforcer config cr
func BuildEnforcerConfigForIE(cr *researchv1alpha1.IntegrityEnforcer) *ec.EnforcerConfig {
	ecc := &ec.EnforcerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.EnforcerConfigCrName,
			Namespace: cr.Namespace,
		},
		Spec: ec.EnforcerConfigSpec{
			EnforcerConfig: &cr.Spec.EnforcerConfig,
		},
	}
	return ecc
}

//enforce policy cr
func BuildSignerEnforcePolicyForIE(cr *researchv1alpha1.IntegrityEnforcer) *epol.EnforcePolicy {
	var signerPolicy *policy.Policy

	if cr.Spec.SignerPolicy != nil {
		signerPolicy = &policy.Policy{
			AllowedSigner: cr.Spec.SignerPolicy.AllowedSigner,
			PolicyType:    policy.SignerPolicy,
		}
	} else {
		signerPolicy = &policy.Policy{
			AllowedSigner: []policy.SignerMatchPattern{
				{
					Request: policy.RequestMatchPattern{Namespace: "sample"},
					Subject: policy.SubjectMatchPattern{Email: "sample"},
				},
			},
			PolicyType: policy.SignerPolicy,
		}
	}
	epcr := &epol.EnforcePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      signerPolicyName,
			Namespace: cr.Namespace,
		},
		Spec: epol.EnforcePolicySpec{
			Policy: signerPolicy,
		},
	}
	return epcr
}

//enforce policy cr
func BuildDefaultEnforcePolicyForIE(cr *researchv1alpha1.IntegrityEnforcer) *epol.EnforcePolicy {
	var defaultPolicy *epol.EnforcePolicy
	if cr.Spec.DefaultPolicy != nil {
		defPolInCR := cr.Spec.DefaultPolicy
		defPolInCR.PolicyType = policy.DefaultPolicy
		defaultPolicy = &epol.EnforcePolicy{
			Spec: epol.EnforcePolicySpec{
				Policy: defPolInCR,
			},
		}
	} else {
		deafultPolicyBytes, err := ioutil.ReadFile(defaultPolicyYamlPath)
		if err != nil {
			//
		}

		err = yaml.Unmarshal(deafultPolicyBytes, &defaultPolicy)
		if err != nil {
			//
		}
	}
	defaultPolicy.ObjectMeta.Name = defaultPolicyName
	defaultPolicy.ObjectMeta.Namespace = cr.Namespace
	return defaultPolicy
}

func BuildIntegrityEnforcerEnforcePolicyForIE(cr *researchv1alpha1.IntegrityEnforcer) *epol.EnforcePolicy {
	pol := &cr.Spec.EnforcePolicy
	pol.PolicyType = policy.IEPolicy
	epcr := &epol.EnforcePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      iePolicyName,
			Namespace: cr.Namespace,
		},
		Spec: epol.EnforcePolicySpec{
			Policy: pol,
		},
	}
	return epcr
}

// resource signature cr
func BuildResourceSignatureForCR(cr *researchv1alpha1.IntegrityEnforcer) *rs.ResourceSignature {
	// rscr := &rs.ResourceSignature{
	// 	ObjectMeta: metav1.ObjectMeta{
	// 		Name: cr.Spec.ResourceSignatureName,
	// 	},
	// 	Spec: rs.ResourceSignatureSpec{
	// 		Data: []rs.SignItem{

	// 		},
	// 	},
	// }
	// return rscr
	return nil
}
