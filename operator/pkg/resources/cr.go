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

	ec "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/enforcerconfig/v1alpha1"
	iedpol "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/iedefaultpolicy/v1alpha1"
	iespol "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/iesignerpolicy/v1alpha1"
	iepol "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/integrityenforcerpolicy/v1alpha1"
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

//signer enforce policy cr
func BuildSignerEnforcePolicyForIE(cr *researchv1alpha1.IntegrityEnforcer) *iespol.IESignerPolicy {
	var signerPolicy *policy.IESignerPolicy

	if cr.Spec.SignerPolicy != nil {
		signerPolicy = &policy.IESignerPolicy{
			AllowedSigner: cr.Spec.SignerPolicy.AllowedSigner,
			PolicyType:    policy.SignerPolicy,
		}
	} else {
		signerPolicy = &policy.IESignerPolicy{
			AllowedSigner: []policy.SignerMatchPattern{
				{
					Request: policy.RequestMatchPattern{Namespace: "sample"},
					Subject: policy.SubjectMatchPattern{CommonName: "sample"},
				},
			},
			PolicyType: policy.SignerPolicy,
		}
	}
	epcr := &iespol.IESignerPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      signerPolicyName,
			Namespace: cr.Namespace,
		},
		Spec: iespol.IESignerPolicySpec{
			IESignerPolicy: signerPolicy,
		},
	}
	return epcr
}

//default enforce policy cr
func BuildDefaultEnforcePolicyForIE(cr *researchv1alpha1.IntegrityEnforcer) *iedpol.IEDefaultPolicy {
	var defaultPolicy *iedpol.IEDefaultPolicy
	if cr.Spec.DefaultPolicy != nil {
		defPolInCR := cr.Spec.DefaultPolicy
		defPolInCR.PolicyType = policy.DefaultPolicy
		defaultPolicy = &iedpol.IEDefaultPolicy{
			Spec: iedpol.IEDefaultPolicySpec{
				IEDefaultPolicy: defPolInCR,
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

// ie policy cr
func BuildIntegrityEnforcerPolicyForIE(cr *researchv1alpha1.IntegrityEnforcer) *iepol.IntegrityEnforcerPolicy {
	pol := &cr.Spec.EnforcePolicy
	pol.PolicyType = policy.IEPolicy
	epcr := &iepol.IntegrityEnforcerPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      iePolicyName,
			Namespace: cr.Namespace,
		},
		Spec: iepol.IntegrityEnforcerPolicySpec{
			IntegrityEnforcerPolicy: pol,
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
