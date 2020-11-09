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
	apiv1alpha1 "github.com/IBM/integrity-enforcer/integrity-enforcer-operator/api/v1alpha1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//sign policy crd
func BuildSignPolicyCRD(cr *apiv1alpha1.IntegrityEnforcer) *extv1.CustomResourceDefinition {

	subjectMatchCondition := &extv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]extv1.JSONSchemaProps{
			"email": {
				Type: "string",
			},
			"uid": {
				Type: "string",
			},
		},
	}

	requestMatchCondition := &extv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]extv1.JSONSchemaProps{
			"apiVersion": {
				Type: "string",
			},
			"kind": {
				Type: "string",
			},
			"name": {
				Type: "string",
			},
			"namespace": {
				Type: "string",
			},
			"operation": {
				Type: "string",
			},
			"type": {
				Type: "string",
			},
			"usergroup": {
				Type: "string",
			},
			"username": {
				Type: "string",
			},
		},
	}

	newCRD := &extv1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomResourceDefinition",
			APIVersion: "apiextensions.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetSignPolicyCRDName(),
			Namespace: cr.Namespace,
		},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "apis.integrityenforcer.io",
			//Version: "v1beta1",
			Names: extv1.CustomResourceDefinitionNames{
				Kind:     "SignPolicy",
				Plural:   "signpolicies",
				ListKind: "SignPolicyList",
				Singular: "signpolicy",
			},
			Scope: "Namespaced",
			Validation: &extv1.CustomResourceValidation{
				OpenAPIV3Schema: &extv1.JSONSchemaProps{
					Type: "object",
					Properties: map[string]extv1.JSONSchemaProps{
						"apiVersion": {
							Type: "string",
						},
						"kind": {
							Type: "string",
						},
						"metadata": {
							Type: "object",
						},
						"spec": {
							Type: "object",
							Properties: map[string]extv1.JSONSchemaProps{
								"signer": {
									Type: "array",
									Items: &extv1.JSONSchemaPropsOrArray{
										Schema: &extv1.JSONSchemaProps{
											Type: "object",
											Properties: map[string]extv1.JSONSchemaProps{
												"subject": *subjectMatchCondition,
												"request": *requestMatchCondition,
											},
										},
									},
								},
								"allowUnverified": {
									Type: "array",
									Items: &extv1.JSONSchemaPropsOrArray{
										Schema: &extv1.JSONSchemaProps{
											Type: "object",
											Properties: map[string]extv1.JSONSchemaProps{
												"namespace": {
													Type: "string",
												},
											},
										},
									},
								},
								"policyType": {
									Type: "string",
								},
								"description": {
									Type: "string",
								},
							},
						},
						"status": {
							Type: "object",
						},
					},
				},
			},
			Version: "v1alpha1",
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

//enforcer config crd
func BuildEnforcerConfigCRD(cr *apiv1alpha1.IntegrityEnforcer) *extv1.CustomResourceDefinition {
	xPreserve := true
	newCRD := &extv1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomResourceDefinition",
			APIVersion: "apiextensions.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetEnforcerConfigCRDName(),
			Namespace: cr.Namespace,
		},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "apis.integrityenforcer.io",
			//Version: "v1beta1",
			Names: extv1.CustomResourceDefinitionNames{
				Kind:       "EnforcerConfig",
				Plural:     "enforcerconfigs",
				ListKind:   "EnforcerConfigList",
				Singular:   "enforcerconfig",
				ShortNames: []string{"econf", "econfs"},
			},
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

//resource signature crd
func BuildResourceSignatureCRD(cr *apiv1alpha1.IntegrityEnforcer) *extv1.CustomResourceDefinition {
	xPreserve := true
	newCRD := &extv1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomResourceDefinition",
			APIVersion: "apiextensions.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetResourceSignatureCRDName(),
			Namespace: cr.Namespace,
		},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "apis.integrityenforcer.io",
			//Version: "v1beta1",
			Names: extv1.CustomResourceDefinitionNames{
				Kind:       "ResourceSignature",
				Plural:     "resourcesignatures",
				ListKind:   "ResourceSignatureList",
				Singular:   "resourcesignature",
				ShortNames: []string{"rsig", "rsigs"},
			},
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

// helm release metadata crd
func BuildHelmReleaseMetadataCRD(cr *apiv1alpha1.IntegrityEnforcer) *extv1.CustomResourceDefinition {
	xPreserve := true
	newCRD := &extv1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomResourceDefinition",
			APIVersion: "apiextensions.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetHelmReleaseMetadataCRDName(),
			Namespace: cr.Namespace,
		},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "apis.integrityenforcer.io",
			//Version: "v1beta1",
			Names: extv1.CustomResourceDefinitionNames{
				Kind:       "HelmReleaseMetadata",
				Plural:     "helmreleasemetadatas",
				ListKind:   "HelmReleaseMetadataList",
				Singular:   "helmreleasemetadata",
				ShortNames: []string{"hrm", "hrms"},
			},
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

// resourcesigningprofile crd
func BuildResourceSigningProfileCRD(cr *apiv1alpha1.IntegrityEnforcer) *extv1.CustomResourceDefinition {
	xPreserve := true
	newCRD := &extv1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomResourceDefinition",
			APIVersion: "apiextensions.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetResourceSigningProfileCRDName(),
			Namespace: cr.Namespace,
		},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "apis.integrityenforcer.io",
			//Version: "v1beta1",
			Names: extv1.CustomResourceDefinitionNames{
				Kind:       "ResourceSigningProfile",
				Plural:     "resourcesigningprofiles",
				ListKind:   "ResourceSigningProfileList",
				Singular:   "resourcesigningprofile",
				ShortNames: []string{"rsp", "rsps"},
			},
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
