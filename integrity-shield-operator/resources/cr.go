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

	apiv1alpha1 "github.com/IBM/integrity-enforcer/integrity-shield-operator/api/v1alpha1"
	rsp "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	ec "github.com/IBM/integrity-enforcer/shield/pkg/apis/shieldconfig/v1alpha1"
	iespol "github.com/IBM/integrity-enforcer/shield/pkg/apis/signpolicy/v1alpha1"
	"github.com/IBM/integrity-enforcer/shield/pkg/common"
	econf "github.com/IBM/integrity-enforcer/shield/pkg/shield/config"
	"github.com/ghodss/yaml"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("controller_integrityshield")

// shield config cr
func BuildShieldConfigForIShield(cr *apiv1alpha1.IntegrityShield, scheme *runtime.Scheme, defaultRspYamlPath string) *ec.ShieldConfig {

	ecc := &ec.ShieldConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetShieldConfigCRName(),
			Namespace: cr.Namespace,
		},
		Spec: ec.ShieldConfigSpec{
			ShieldConfig: cr.Spec.ShieldConfig,
		},
	}
	if ecc.Spec.ShieldConfig.Namespace == "" {
		ecc.Spec.ShieldConfig.Namespace = cr.Namespace
	}
	if ecc.Spec.ShieldConfig.SignatureNamespace == "" {
		ecc.Spec.ShieldConfig.SignatureNamespace = cr.Namespace
	}
	if ecc.Spec.ShieldConfig.ProfileNamespace == "" {
		ecc.Spec.ShieldConfig.ProfileNamespace = cr.Namespace
	}
	if ecc.Spec.ShieldConfig.IShieldServerUserName == "" {
		ecc.Spec.ShieldConfig.IShieldServerUserName = fmt.Sprintf("system:serviceaccount:%s:%s", cr.Namespace, cr.GetServiceAccountName())
	}
	if len(ecc.Spec.ShieldConfig.KeyPathList) == 0 {
		keyPathList := []string{}
		for _, keyConf := range cr.Spec.KeyRings {
			keyPathList = append(keyPathList, fmt.Sprintf("/%s/%s", keyConf.Name, apiv1alpha1.DefaultKeyringFilename))
		}
		ecc.Spec.ShieldConfig.KeyPathList = keyPathList
	}
	operatorSA := getOperatorServiceAccount()

	iShieldOperatorResources, iShieldServerResources := cr.GetIShieldResourceList(scheme)

	ecc.Spec.ShieldConfig.IShieldResourceCondition = &econf.IShieldResourceCondition{
		OperatorResources:      iShieldOperatorResources,
		ServerResources:        iShieldServerResources,
		OperatorServiceAccount: operatorSA,
	}
	if ecc.Spec.ShieldConfig.CommonProfile == nil {
		var defaultrsp *rsp.ResourceSigningProfile

		deafultRspBytes, _ := ioutil.ReadFile(defaultRspYamlPath)

		err := yaml.Unmarshal(deafultRspBytes, &defaultrsp)

		if err != nil {
			reqLogger := log.WithValues("BuildShieldConfigForIShield", cr.GetShieldConfigCRName())
			reqLogger.Error(err, "Failed to load default CommonProfile from file.")
		}
		if operatorSA != "" {
			// add IShield operator SA to ignoreRules in commonProfile
			operatorSAPattern := common.RulePattern(operatorSA)
			ignoreRules := defaultrsp.Spec.IgnoreRules
			ignoreRules = append(ignoreRules, &common.Rule{Match: []*common.RequestPattern{{UserName: &operatorSAPattern}}})
			defaultrsp.Spec.IgnoreRules = ignoreRules
		}
		ecc.Spec.ShieldConfig.CommonProfile = &(defaultrsp.Spec)
	}

	return ecc
}

//sign shield policy cr
func BuildSignPolicyForIShield(cr *apiv1alpha1.IntegrityShield) *iespol.SignPolicy {
	var signPolicy *common.SignPolicy

	if cr.Spec.SignPolicy != nil {
		signPolicy = cr.Spec.SignPolicy
	} else {
		signPolicy = &common.SignPolicy{
			Policies: []common.SignPolicyCondition{
				{
					Namespaces: []string{"sample"},
					Signers:    []string{"SampleSigner"},
				},
			},
			Signers: []common.SignerCondition{
				{
					Name: "SampleSigner",
					Subjects: []common.SubjectMatchPattern{
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

func BuildResourceSigningProfileForIShield(cr *apiv1alpha1.IntegrityShield, prof *apiv1alpha1.ProfileConfig) *rsp.ResourceSigningProfile {
	rspfromcr := &rsp.ResourceSigningProfile{}
	rspfromcr.Spec = *(prof.ResourceSigningProfileSpec)
	rspfromcr.ObjectMeta.Name = prof.Name
	rspfromcr.ObjectMeta.Namespace = cr.Namespace
	return rspfromcr
}
