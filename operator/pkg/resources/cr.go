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
	ec "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/enforcerconfig/v1alpha1"
	rs "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourcesignature/v1alpha1"
	iespol "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/signpolicy/v1alpha1"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/policy"
	researchv1alpha1 "github.com/IBM/integrity-enforcer/operator/pkg/apis/research/v1alpha1"
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
			EnforcerConfig: cr.Spec.EnforcerConfig,
		},
	}
	return ecc
}

//sign enforce policy cr
func BuildSignEnforcePolicyForIE(cr *researchv1alpha1.IntegrityEnforcer) *iespol.SignPolicy {
	var signPolicy *policy.SignPolicy

	if cr.Spec.SignPolicy != nil {
		signPolicy = &policy.SignPolicy{
			Signer:     cr.Spec.SignPolicy.Signer,
			PolicyType: policy.SignerPolicy,
		}
	} else {
		signPolicy = &policy.SignPolicy{
			Signer: []policy.SignerMatchPattern{
				{
					Request: policy.RequestMatchPattern{Namespace: "sample"},
					Condition: policy.SubjectCondition{
						Name:    "SampleSigner",
						Subject: policy.SubjectMatchPattern{CommonName: "sample"},
					},
				},
			},
			PolicyType: policy.SignerPolicy,
		}
	}
	epcr := &iespol.SignPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      signerPolicyName,
			Namespace: cr.Namespace,
		},
		Spec: iespol.SignPolicySpec{
			SignPolicy: signPolicy,
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
