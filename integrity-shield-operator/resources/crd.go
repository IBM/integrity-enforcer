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
	apiv1alpha1 "github.com/IBM/integrity-enforcer/integrity-shield-operator/api/v1alpha1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func buildCRD(name, namespace string, crdNames extv1.CustomResourceDefinitionNames) *extv1.CustomResourceDefinition {
	xPreserve := true
	newCRD := &extv1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomResourceDefinition",
			APIVersion: "apiextensions.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "apis.integrityshield.io",
			//Version: "v1beta1",
			Names: crdNames,
			Scope: "Namespaced",
			Validation: &extv1.CustomResourceValidation{
				OpenAPIV3Schema: &extv1.JSONSchemaProps{
					Type:                   "object",
					XPreserveUnknownFields: &xPreserve,
				},
			},
			Versions: []extv1.CustomResourceDefinitionVersion{
				{
					Name:    "v1alpha1",
					Served:  true,
					Storage: true,
				},
			},
		},
	}
	return newCRD
}

//sign policy crd
func BuildSignPolicyCRD(cr *apiv1alpha1.IntegrityShield) *extv1.CustomResourceDefinition {
	crdNames := extv1.CustomResourceDefinitionNames{
		Kind:     "SignPolicy",
		Plural:   "signpolicies",
		ListKind: "SignPolicyList",
		Singular: "signpolicy",
	}
	return buildCRD(cr.GetSignPolicyCRDName(), cr.Namespace, crdNames)
}

//shield config crd
func BuildShieldConfigCRD(cr *apiv1alpha1.IntegrityShield) *extv1.CustomResourceDefinition {
	crdNames := extv1.CustomResourceDefinitionNames{
		Kind:       "ShieldConfig",
		Plural:     "shieldconfigs",
		ListKind:   "ShieldConfigList",
		Singular:   "shieldconfig",
		ShortNames: []string{"econf", "econfs"},
	}
	return buildCRD(cr.GetShieldConfigCRDName(), cr.Namespace, crdNames)
}

//resource signature crd
func BuildResourceSignatureCRD(cr *apiv1alpha1.IntegrityShield) *extv1.CustomResourceDefinition {
	crdNames := extv1.CustomResourceDefinitionNames{
		Kind:       "ResourceSignature",
		Plural:     "resourcesignatures",
		ListKind:   "ResourceSignatureList",
		Singular:   "resourcesignature",
		ShortNames: []string{"rsig", "rsigs"},
	}
	return buildCRD(cr.GetResourceSignatureCRDName(), cr.Namespace, crdNames)
}

// helm release metadata crd
func BuildHelmReleaseMetadataCRD(cr *apiv1alpha1.IntegrityShield) *extv1.CustomResourceDefinition {
	crdNames := extv1.CustomResourceDefinitionNames{
		Kind:       "HelmReleaseMetadata",
		Plural:     "helmreleasemetadatas",
		ListKind:   "HelmReleaseMetadataList",
		Singular:   "helmreleasemetadata",
		ShortNames: []string{"hrm", "hrms"},
	}
	return buildCRD(cr.GetHelmReleaseMetadataCRDName(), cr.Namespace, crdNames)
}

// resourcesigningprofile crd
func BuildResourceSigningProfileCRD(cr *apiv1alpha1.IntegrityShield) *extv1.CustomResourceDefinition {

	crdNames := extv1.CustomResourceDefinitionNames{
		Kind:       "ResourceSigningProfile",
		Plural:     "resourcesigningprofiles",
		ListKind:   "ResourceSigningProfileList",
		Singular:   "resourcesigningprofile",
		ShortNames: []string{"rsp", "rsps"},
	}
	return buildCRD(cr.GetResourceSigningProfileCRDName(), cr.Namespace, crdNames)
}
