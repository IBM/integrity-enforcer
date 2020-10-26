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
	rpp "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourcesigningprofile/v1alpha1"
	iespol "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/signpolicy/v1alpha1"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/policy"
	researchv1alpha1 "github.com/IBM/integrity-enforcer/operator/api/v1alpha1"
	"github.com/ghodss/yaml"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const defaultRppName = "default-rpp"
const primaryRppName = "primary-rpp"
const signerPolicyName = "signer-policy"
const defaultResourceSigningProfileYamlPath = "/resources/default-rsp.yaml"
const defaultCertPoolPath = "/ie-certpool-secret/"
const defaultKeyringPath = "/keyring/pubring.gpg"

var log = logf.Log.WithName("controller_integrityenforcer")

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
		ecc.Spec.EnforcerConfig.IEServerUserName = fmt.Sprintf("system:serviceaccount:%s:%s", cr.Namespace, cr.Spec.Security.ServiceAccountName)
	}
	if ecc.Spec.EnforcerConfig.CertPoolPath == "" {
		ecc.Spec.EnforcerConfig.CertPoolPath = defaultCertPoolPath
	}
	if ecc.Spec.EnforcerConfig.KeyringPath == "" {
		ecc.Spec.EnforcerConfig.KeyringPath = defaultKeyringPath
	}
	if ecc.Spec.EnforcerConfig.CommonProfile == nil {
		var defaultrpp *rpp.ResourceSigningProfile
		deafultRppBytes, _ := ioutil.ReadFile(defaultResourceSigningProfileYamlPath)

		err := yaml.Unmarshal(deafultRppBytes, &defaultrpp)
		reqLogger := log.WithValues("BuildEnforcerConfigForIE", cr.Spec.EnforcerConfigCrName)
		reqLogger.Info("Building Config for IE")

		if err != nil {
			//reqLogger := log.WithValues("BuildEnforcerConfigForIE", cr.Spec.EnforcerConfigCrName)
			reqLogger.Error(err, "Failed to load default CommonProfile from file.")
		}
		ecc.Spec.EnforcerConfig.CommonProfile = &(defaultrpp.Spec)
		reqLogger.Info("completed Building Config for IE")
	}

	return ecc
}

//sign enforce policy cr
func BuildSignEnforcePolicyForIE(cr *researchv1alpha1.IntegrityEnforcer) *iespol.SignPolicy {
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
			Name:      signerPolicyName,
			Namespace: cr.Namespace,
		},
		Spec: iespol.SignPolicySpec{
			SignPolicy: signPolicy,
		},
	}
	return epcr
}

// primary rpp
func BuildPrimaryResourceSigningProfileForIE(cr *researchv1alpha1.IntegrityEnforcer) *rpp.ResourceSigningProfile {
	primaryrpp := &rpp.ResourceSigningProfile{}

	if cr.Spec.PrimaryRpp != nil {
		primaryrpp.Spec = *cr.Spec.PrimaryRpp
	}

	primaryrpp.ObjectMeta.Name = primaryRppName
	primaryrpp.ObjectMeta.Namespace = cr.Namespace
	return primaryrpp
}
