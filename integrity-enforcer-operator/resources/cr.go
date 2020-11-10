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

	ec "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/enforcerconfig/v1alpha1"
	rsp "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourcesigningprofile/v1alpha1"
	iespol "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/signpolicy/v1alpha1"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/common/policy"
	profile "github.com/IBM/integrity-enforcer/enforcer/pkg/common/profile"
	econf "github.com/IBM/integrity-enforcer/enforcer/pkg/enforcer/config"
	apiv1alpha1 "github.com/IBM/integrity-enforcer/integrity-enforcer-operator/api/v1alpha1"
	"github.com/ghodss/yaml"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const defaultResourceSigningProfileYamlPath = "/resources/default-rsp.yaml"
const defaultKeyringFilename = "pubring.gpg"

var log = logf.Log.WithName("controller_integrityenforcer")

// enforcer config cr
func BuildEnforcerConfigForIE(cr *apiv1alpha1.IntegrityEnforcer, scheme *runtime.Scheme) *ec.EnforcerConfig {
	ecc := &ec.EnforcerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetEnforcerConfigCRName(),
			Namespace: cr.Namespace,
		},
		Spec: ec.EnforcerConfigSpec{
			EnforcerConfig: cr.Spec.EnforcerConfig,
		},
	}
	if ecc.Spec.EnforcerConfig.Namespace == "" {
		ecc.Spec.EnforcerConfig.Namespace = cr.Namespace
	}
	if ecc.Spec.EnforcerConfig.SignatureNamespace == "" {
		ecc.Spec.EnforcerConfig.SignatureNamespace = cr.Namespace
	}
	if ecc.Spec.EnforcerConfig.ProfileNamespace == "" {
		ecc.Spec.EnforcerConfig.ProfileNamespace = cr.Namespace
	}
	if ecc.Spec.EnforcerConfig.IEServerUserName == "" {
		ecc.Spec.EnforcerConfig.IEServerUserName = fmt.Sprintf("system:serviceaccount:%s:%s", cr.Namespace, cr.GetServiceAccountName())
	}
	if len(ecc.Spec.EnforcerConfig.KeyPathList) == 0 {
		keyPathList := []string{}
		for _, keyConf := range cr.Spec.KeyRings {
			keyPathList = append(keyPathList, fmt.Sprintf("/%s/%s", keyConf.Name, defaultKeyringFilename))
		}
		ecc.Spec.EnforcerConfig.KeyPathList = keyPathList
	}
	operatorSA := getOperatorServiceAccount()

	ecc.Spec.EnforcerConfig.IEResourceCondition = &econf.IEResourceCondition{
		References:             cr.GetIEResourceList(scheme),
		OperatorServiceAccount: operatorSA,
	}
	if ecc.Spec.EnforcerConfig.CommonProfile == nil {
		var defaultrsp *rsp.ResourceSigningProfile
		deafultRspBytes, _ := ioutil.ReadFile(defaultResourceSigningProfileYamlPath)

		err := yaml.Unmarshal(deafultRspBytes, &defaultrsp)

		if err != nil {
			reqLogger := log.WithValues("BuildEnforcerConfigForIE", cr.GetEnforcerConfigCRName())
			reqLogger.Error(err, "Failed to load default CommonProfile from file.")
		}
		if operatorSA != "" {
			// add IE operator SA to ignoreRules in commonProfile
			operatorSAPattern := profile.RulePattern(operatorSA)
			ignoreRules := defaultrsp.Spec.IgnoreRules
			ignoreRules = append(ignoreRules, &profile.Rule{Match: []*profile.RequestPattern{{UserName: &operatorSAPattern}}})
			defaultrsp.Spec.IgnoreRules = ignoreRules
		}
		ecc.Spec.EnforcerConfig.CommonProfile = &(defaultrsp.Spec)
	}

	return ecc
}

//sign enforce policy cr
func BuildSignEnforcePolicyForIE(cr *apiv1alpha1.IntegrityEnforcer) *iespol.SignPolicy {
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

func BuildResourceSigningProfileForIE(cr *apiv1alpha1.IntegrityEnforcer, prof *apiv1alpha1.ProfileConfig) *rsp.ResourceSigningProfile {
	rspfromcr := &rsp.ResourceSigningProfile{}

	rspfromcr.Spec = *(prof.ResourceSigningProfileSpec)

	rspfromcr.ObjectMeta.Name = prof.Name
	rspfromcr.ObjectMeta.Namespace = cr.Namespace
	return rspfromcr
}
