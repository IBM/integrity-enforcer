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
	"path/filepath"

	apiv1alpha1 "github.com/IBM/integrity-enforcer/integrity-shield-operator/api/v1alpha1"
	rsp "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	ec "github.com/IBM/integrity-enforcer/shield/pkg/apis/shieldconfig/v1alpha1"
	sigconf "github.com/IBM/integrity-enforcer/shield/pkg/apis/signerconfig/v1alpha1"
	"github.com/IBM/integrity-enforcer/shield/pkg/common"
	econf "github.com/IBM/integrity-enforcer/shield/pkg/shield/config"
	"github.com/ghodss/yaml"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("controller_integrityshield")

// shield config cr
func BuildShieldConfigForIShield(cr *apiv1alpha1.IntegrityShield, scheme *runtime.Scheme, commonProfileYamlPathList []string) *ec.ShieldConfig {

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
	if ecc.Spec.ShieldConfig.IShieldCRName == "" {
		ecc.Spec.ShieldConfig.IShieldCRName = cr.Name
	}
	if ecc.Spec.ShieldConfig.IShieldServerUserName == "" {
		ecc.Spec.ShieldConfig.IShieldServerUserName = fmt.Sprintf("system:serviceaccount:%s:%s", cr.Namespace, cr.GetServiceAccountName())
	}
	if len(ecc.Spec.ShieldConfig.KeyPathList) == 0 {
		keyPathList := []string{}
		for _, keyConf := range cr.Spec.KeyConfig {
			sigType := keyConf.SignatureType
			if sigType == common.SignatureTypeDefault {
				sigType = common.SignatureTypePGP
			}
			if sigType == common.SignatureTypePGP {
				fileName := keyConf.FileName
				if fileName == "" {
					fileName = apiv1alpha1.DefaultKeyringFilename
				}
				// specify .gpg file name in case of pgp --> change to dir name?
				keyPath := fmt.Sprintf("/%s/%s/%s", keyConf.Name, sigType, fileName)
				keyPathList = append(keyPathList, keyPath)
			} else if sigType == common.SignatureTypeX509 {
				// specify only mounted dir name in case of x509
				keyPath := fmt.Sprintf("/%s/%s/", keyConf.Name, sigType)
				keyPathList = append(keyPathList, keyPath)
			}

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
		commonProfile := &common.CommonProfile{}

		for _, presetPath := range commonProfileYamlPathList {
			var tmpProfile *common.CommonProfile
			fpath := filepath.Clean(presetPath)
			tmpProfileBytes, _ := ioutil.ReadFile(fpath) // NOSONAR
			err := yaml.Unmarshal(tmpProfileBytes, &tmpProfile)
			if err != nil {
				reqLogger := log.WithValues("BuildShieldConfigForIShield", cr.GetShieldConfigCRName())
				reqLogger.Error(err, fmt.Sprintf("Failed to load preset CommonProfile from file `%s`", fpath))
			}
			commonProfile.IgnoreRules = append(commonProfile.IgnoreRules, tmpProfile.IgnoreRules...)
			commonProfile.IgnoreAttrs = append(commonProfile.IgnoreAttrs, tmpProfile.IgnoreAttrs...)
		}

		if operatorSA != "" {
			// add IShield operator SA to ignoreRules in commonProfile
			operatorSAPattern := common.RulePattern(operatorSA)
			ignoreRules := commonProfile.IgnoreRules

			ignoreRules = append(ignoreRules, &common.Rule{Match: []*common.RequestPattern{{UserName: &operatorSAPattern}}})
			commonProfile.IgnoreRules = ignoreRules
		}

		for _, ir := range cr.Spec.IgnoreRules {
			tmpRule := ir
			commonProfile.IgnoreRules = append(commonProfile.IgnoreRules, &tmpRule)
		}
		for _, ia := range cr.Spec.IgnoreAttrs {
			tmpAttr := ia
			commonProfile.IgnoreAttrs = append(commonProfile.IgnoreAttrs, &tmpAttr)
		}

		ecc.Spec.ShieldConfig.CommonProfile = commonProfile
	}

	return ecc
}

//signer config cr
func BuildSignerConfigForIShield(cr *apiv1alpha1.IntegrityShield) *sigconf.SignerConfig {
	var signerConfig *common.SignerConfig

	if cr.Spec.SignerConfig != nil {
		signerConfig = cr.Spec.SignerConfig
	} else {
		signerConfig = &common.SignerConfig{
			Policies: []common.SignerConfigCondition{
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
	epcr := &sigconf.SignerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetSignerConfigCRName(),
			Namespace: cr.Namespace,
		},
		Spec: sigconf.SignerConfigSpec{
			Config: signerConfig,
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
