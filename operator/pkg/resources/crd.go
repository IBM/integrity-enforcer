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
	researchv1alpha1 "github.com/IBM/integrity-enforcer/operator/pkg/apis/research/v1alpha1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//enforce policy crd
func BuildEnforcePolicyCRD(cr *researchv1alpha1.IntegrityEnforcer) *extv1.CustomResourceDefinition {

	requestMatchCondition := &extv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]extv1.JSONSchemaProps{
			"apiVersion": {
				Type: "string",
			},
			"firstUser": {
				Type: "boolean",
			},
			"k8screatedby": {
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

	ownerMatchCondition := &extv1.JSONSchemaProps{
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
		},
	}

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

	stringArray := &extv1.JSONSchemaProps{
		Items: &extv1.JSONSchemaPropsOrArray{
			Schema: &extv1.JSONSchemaProps{
				Type: "string",
			},
		},
		Type: "array",
	}

	requestMatchConditionArray := &extv1.JSONSchemaProps{
		Type: "array",
		Items: &extv1.JSONSchemaPropsOrArray{
			Schema: requestMatchCondition,
		},
	}

	allowedServiceAccountMatchCondition := &extv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]extv1.JSONSchemaProps{
			"authorizedServiceAccount": *stringArray,
			"allowChangesBySignedServiceAccount": {
				Type: "boolean",
			},
			"request": *requestMatchCondition,
		},
	}

	allowedServiceAccountMatchConditionArray := &extv1.JSONSchemaProps{
		Type: "array",
		Items: &extv1.JSONSchemaPropsOrArray{
			Schema: allowedServiceAccountMatchCondition,
		},
	}

	newCRD := &extv1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomResourceDefinition",
			APIVersion: "apiextensions.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "enforcepolicies.research.ibm.com",
			Namespace: cr.Namespace,
		},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "research.ibm.com",
			//Version: "v1beta1",
			Names: extv1.CustomResourceDefinitionNames{
				Kind:     "EnforcePolicy",
				Plural:   "enforcepolicies",
				ListKind: "EnforcePolicyList",
				Singular: "enforcepolicy",
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
								"allowedByRule": *requestMatchConditionArray,
								"allowedChange": {
									Type: "array",
									Items: &extv1.JSONSchemaPropsOrArray{
										Schema: &extv1.JSONSchemaProps{
											Type: "object",
											Properties: map[string]extv1.JSONSchemaProps{
												"key":     *stringArray,
												"owner":   *ownerMatchCondition,
												"request": *requestMatchCondition,
											},
										},
									},
								},
								"allowedForInternalRequest": *requestMatchConditionArray,
								"allowedSigner": {
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
								"enforce":               *requestMatchConditionArray,
								"ignoreRequest":         *requestMatchConditionArray,
								"permitIfCreator":       *allowedServiceAccountMatchConditionArray,
								"permitIfVerifiedOwner": *allowedServiceAccountMatchConditionArray,
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
func BuildEnforcerConfigCRD(cr *researchv1alpha1.IntegrityEnforcer) *extv1.CustomResourceDefinition {
	xPreserve := true
	newCRD := &extv1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomResourceDefinition",
			APIVersion: "apiextensions.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "enforcerconfigs.research.ibm.com",
			Namespace: cr.Namespace,
		},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "research.ibm.com",
			//Version: "v1beta1",
			Names: extv1.CustomResourceDefinitionNames{
				Kind:     "EnforcerConfig",
				Plural:   "enforcerconfigs",
				ListKind: "EnforcerConfigList",
				Singular: "enforcerconfig",
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
func BuildResourceSignatureCRD(cr *researchv1alpha1.IntegrityEnforcer) *extv1.CustomResourceDefinition {
	xPreserve := true
	newCRD := &extv1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomResourceDefinition",
			APIVersion: "apiextensions.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "resourcesignatures.research.ibm.com",
			Namespace: cr.Namespace,
		},
		Spec: extv1.CustomResourceDefinitionSpec{
			Group: "research.ibm.com",
			//Version: "v1beta1",
			Names: extv1.CustomResourceDefinitionNames{
				Kind:     "ResourceSignature",
				Plural:   "resourcesignatures",
				ListKind: "ResourceSignatureList",
				Singular: "resourcesignature",
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
