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
	crpp "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/vclusterresourceprotectionprofile/v1alpha1"
	rpp "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/vresourceprotectionprofile/v1alpha1"
	iespol "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/vsignpolicy/v1alpha1"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/policy"
	researchv1alpha1 "github.com/IBM/integrity-enforcer/operator/pkg/apis/research/v1alpha1"
	"github.com/ghodss/yaml"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const defaultRppName = "default-rpp"
const defaultCrppName = "default-crpp"
const signerPolicyName = "signer-policy"
const defaultResourceProtectionProfileYamlPath = "/resources/default-rpp.yaml"
const defaultClusterResourceProtectionProfileYamlPath = "/resources/default-crpp.yaml"

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
	return ecc
}

//sign enforce policy cr
func BuildSignEnforcePolicyForIE(cr *researchv1alpha1.IntegrityEnforcer) *iespol.VSignPolicy {
	var signPolicy *policy.VSignPolicy

	if cr.Spec.SignPolicy != nil {
		signPolicy = cr.Spec.SignPolicy
	} else {
		signPolicy = &policy.VSignPolicy{
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
	epcr := &iespol.VSignPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      signerPolicyName,
			Namespace: cr.Namespace,
		},
		Spec: iespol.VSignPolicySpec{
			VSignPolicy: signPolicy,
		},
	}
	return epcr
}

// default rpp
func BuildDefaultResourceProtectionProfileForIE(cr *researchv1alpha1.IntegrityEnforcer) *rpp.VResourceProtectionProfile {
	var defaultrpp *rpp.VResourceProtectionProfile
	reqLogger := log.WithValues("BuildDefaultResourceProtectionProfile", defaultRppName)

	if cr.Spec.DefaultRpp != nil {
		defaultrpp = cr.Spec.DefaultRpp
	} else {
		deafultRppBytes, err := ioutil.ReadFile(defaultResourceProtectionProfileYamlPath)
		if err != nil {
			reqLogger.Error(err, "Failed to read default rpp file")
		}

		err = yaml.Unmarshal(deafultRppBytes, &defaultrpp)
		if err != nil {
			reqLogger.Error(err, "Failed to unmarshal yaml")
		}
	}

	defaultrpp.ObjectMeta.Name = defaultRppName
	defaultrpp.ObjectMeta.Namespace = cr.Namespace
	return defaultrpp
}

// default crpp
func BuildDefaultClusterResourceProtectionProfileForIE(cr *researchv1alpha1.IntegrityEnforcer) *crpp.VClusterResourceProtectionProfile {
	var defaultcrpp *crpp.VClusterResourceProtectionProfile
	reqLogger := log.WithValues("BuildDefaultClusterResourceProtectionProfile", defaultCrppName)

	deafultCrppBytes, err := ioutil.ReadFile(defaultClusterResourceProtectionProfileYamlPath)
	if err != nil {
		reqLogger.Error(err, "Failed to read default crpp file")
	}

	err = yaml.Unmarshal(deafultCrppBytes, &defaultcrpp)
	if err != nil {
		reqLogger.Error(err, "Failed to unmarshal yaml")
	}

	defaultcrpp.ObjectMeta.Name = defaultCrppName
	defaultcrpp.ObjectMeta.Namespace = cr.Namespace
	return defaultcrpp
}
