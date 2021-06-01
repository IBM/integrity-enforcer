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
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func buildCRD(name, namespace string, crdNames extv1.CustomResourceDefinitionNames, namespaced bool) *extv1.CustomResourceDefinition {
	trueVar := true
	scope := extv1.NamespaceScoped
	if !namespaced {
		scope = extv1.ClusterScoped
	}
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
			Scope: scope,
			Versions: []extv1.CustomResourceDefinitionVersion{
				{
					Name:    "v1alpha1",
					Served:  true,
					Storage: true,
					Schema: &extv1.CustomResourceValidation{
						OpenAPIV3Schema: &extv1.JSONSchemaProps{
							XPreserveUnknownFields: &trueVar,
						},
					},
				},
			},
		},
	}
	return newCRD
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
	return buildCRD(cr.GetShieldConfigCRDName(), cr.Namespace, crdNames, true)
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
	return buildCRD(cr.GetResourceSignatureCRDName(), cr.Namespace, crdNames, true)
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
	return buildCRD(cr.GetHelmReleaseMetadataCRDName(), cr.Namespace, crdNames, true)
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
	return buildCRD(cr.GetResourceSigningProfileCRDName(), cr.Namespace, crdNames, true)
}

// resourceauditreview crd
func BuildResourceAuditReviewCRD(cr *apiv1alpha1.IntegrityShield) *extv1.CustomResourceDefinition {

	crdNames := extv1.CustomResourceDefinitionNames{
		Kind:       "ResourceAuditReview",
		Plural:     "resourceauditreviews",
		ListKind:   "ResourceAuditReviewList",
		Singular:   "resourceauditreview",
		ShortNames: []string{"rar", "rars"},
	}
	return buildCRD(cr.GetResourceAuditReviewCRDName(), cr.Namespace, crdNames, false)
}

// // protectedresourceintegrity crd
// func BuildProtectedResourceIntegrityCRD(cr *apiv1alpha1.IntegrityShield) *extv1.CustomResourceDefinition {

// 	crdNames := extv1.CustomResourceDefinitionNames{
// 		Kind:       "ProtectedResourceIntegrity",
// 		Plural:     "protectedresourceintegrities",
// 		ListKind:   "ProtectedResourceIntegrityList",
// 		Singular:   "protectedresourceintegrity",
// 		ShortNames: []string{"pri", "pris"},
// 	}
// 	crd := buildCRD(cr.GetProtectedResourceIntegrityCRDName(), cr.Namespace, crdNames)
// 	// crd.Spec.AdditionalPrinterColumns = []extv1.CustomResourceColumnDefinition{
// 	// 	{
// 	// 		Name:        "Profiles",
// 	// 		Type:        "string",
// 	// 		Description: "ResourceSigningProfiles that cover this resource",
// 	// 		JSONPath:    ".status.profiles",
// 	// 		Priority:    0,
// 	// 	},
// 	// 	{
// 	// 		Name:        "Verified",
// 	// 		Type:        "boolean",
// 	// 		Description: "A boolean value represents if a signature for this resource is verified or not",
// 	// 		JSONPath:    ".status.verified",
// 	// 		Priority:    0,
// 	// 	},
// 	// 	{
// 	// 		Name:        "LastVerified",
// 	// 		Type:        "date",
// 	// 		Description: "The latest timestamp when its signature was verified by inspector",
// 	// 		JSONPath:    ".status.lastVerified",
// 	// 		Priority:    0,
// 	// 	},
// 	// 	{
// 	// 		Name:        "LastUpdated",
// 	// 		Type:        "date",
// 	// 		Description: "The latest timestamp when signature verification was done by inspector",
// 	// 		JSONPath:    ".status.lastUpdated",
// 	// 		Priority:    0,
// 	// 	},
// 	// 	{
// 	// 		Name:        "Result",
// 	// 		Type:        "string",
// 	// 		Description: "A result from a verification of integrity-shield-server",
// 	// 		JSONPath:    ".status.result",
// 	// 		Priority:    1,
// 	// 	},
// 	// 	{
// 	// 		Name:        "AllowedUsernames",
// 	// 		Type:        "string",
// 	// 		Description: "Usernames that are allowed to change this resource without signature",
// 	// 		JSONPath:    ".status.allowedUsernames",
// 	// 		Priority:    1,
// 	// 	},
// 	// }
// 	return crd
// }
