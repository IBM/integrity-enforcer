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
	"fmt"
	"io/ioutil"

	apiv1alpha1 "github.com/IBM/integrity-enforcer/integrity-verifier-operator/api/v1alpha1"
	rsp "github.com/IBM/integrity-enforcer/verifier/pkg/apis/resourcesigningprofile/v1alpha1"
	iespol "github.com/IBM/integrity-enforcer/verifier/pkg/apis/signpolicy/v1alpha1"
	ec "github.com/IBM/integrity-enforcer/verifier/pkg/apis/verifierconfig/v1alpha1"
	policy "github.com/IBM/integrity-enforcer/verifier/pkg/common/policy"
	profile "github.com/IBM/integrity-enforcer/verifier/pkg/common/profile"
	econf "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/config"
	"github.com/ghodss/yaml"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("controller_integrityverifier")

// verifier config cr
func BuildVerifierConfigForIV(cr *apiv1alpha1.IntegrityVerifier, scheme *runtime.Scheme) *ec.VerifierConfig {
	ecc := &ec.VerifierConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetVerifierConfigCRName(),
			Namespace: cr.Namespace,
		},
		Spec: ec.VerifierConfigSpec{
			VerifierConfig: cr.Spec.VerifierConfig,
		},
	}
	if ecc.Spec.VerifierConfig.Namespace == "" {
		ecc.Spec.VerifierConfig.Namespace = cr.Namespace
	}
	if ecc.Spec.VerifierConfig.SignatureNamespace == "" {
		ecc.Spec.VerifierConfig.SignatureNamespace = cr.Namespace
	}
	if ecc.Spec.VerifierConfig.ProfileNamespace == "" {
		ecc.Spec.VerifierConfig.ProfileNamespace = cr.Namespace
	}
	if ecc.Spec.VerifierConfig.IVServerUserName == "" {
		ecc.Spec.VerifierConfig.IVServerUserName = fmt.Sprintf("system:serviceaccount:%s:%s", cr.Namespace, cr.GetServiceAccountName())
	}
	if len(ecc.Spec.VerifierConfig.KeyPathList) == 0 {
		keyPathList := []string{}
		for _, keyConf := range cr.Spec.KeyRings {
			keyPathList = append(keyPathList, fmt.Sprintf("/%s/%s", keyConf.Name, apiv1alpha1.DefaultKeyringFilename))
		}
		ecc.Spec.VerifierConfig.KeyPathList = keyPathList
	}
	operatorSA := getOperatorServiceAccount()

	ecc.Spec.VerifierConfig.IVResourceCondition = &econf.IVResourceCondition{
		References:             cr.GetIVResourceList(scheme),
		OperatorServiceAccount: operatorSA,
	}
	if ecc.Spec.VerifierConfig.CommonProfile == nil {
		var defaultrsp *rsp.ResourceSigningProfile
		deafultRspBytes, _ := ioutil.ReadFile(apiv1alpha1.DefaultResourceSigningProfileYamlPath)

		err := yaml.Unmarshal(deafultRspBytes, &defaultrsp)

		if err != nil {
			reqLogger := log.WithValues("BuildVerifierConfigForIV", cr.GetVerifierConfigCRName())
			reqLogger.Error(err, "Failed to load default CommonProfile from file.")
		}
		if operatorSA != "" {
			// add IV operator SA to ignoreRules in commonProfile
			operatorSAPattern := profile.RulePattern(operatorSA)
			ignoreRules := defaultrsp.Spec.IgnoreRules
			ignoreRules = append(ignoreRules, &profile.Rule{Match: []*profile.RequestPattern{{UserName: &operatorSAPattern}}})
			defaultrsp.Spec.IgnoreRules = ignoreRules
		}
		ecc.Spec.VerifierConfig.CommonProfile = &(defaultrsp.Spec)
	}

	return ecc
}

//sign verifier policy cr
func BuildSignEnforcePolicyForIV(cr *apiv1alpha1.IntegrityVerifier) *iespol.SignPolicy {
	var signPolicy *policy.SignPolicy

	if cr.Spec.SignPolicy != nil {
		signPolicy = cr.Spec.SignPolicy
	} else {
		signPolicy = &policy.SignPolicy{
			Policies: []policy.SignPolicyCondition{
				{
					Namespaces: []string{"sample"},
					Signers:    []string{"SampleSigner"},
				},
			},
			Signers: []policy.SignerCondition{
				{
					Name: "SampleSigner",
					Subjects: []policy.SubjectMatchPattern{
						{
							CommonName: "sample",
						},
					},
				},
			},
		}
	}
	epcr := &iespol.SignPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetSignPolicyCRName(),
			Namespace: cr.Namespace,
		},
		Spec: iespol.SignPolicySpec{
			SignPolicy: signPolicy,
		},
	}
	return epcr
}

func BuildResourceSigningProfileForIV(cr *apiv1alpha1.IntegrityVerifier, prof *apiv1alpha1.ProfileConfig) *rsp.ResourceSigningProfile {
	rspfromcr := &rsp.ResourceSigningProfile{}
	rspfromcr.Spec = *(prof.ResourceSigningProfileSpec)
	rspfromcr.ObjectMeta.Name = prof.Name
	rspfromcr.ObjectMeta.Namespace = cr.Namespace
	return rspfromcr
}
