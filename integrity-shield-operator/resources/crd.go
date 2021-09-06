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
	apiv1alpha1 "github.com/IBM/integrity-shield/integrity-shield-operator/api/v1alpha1"
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
func BuildManifestIntegrityProfileCRD(cr *apiv1alpha1.IntegrityShield) *extv1.CustomResourceDefinition {
	crdNames := extv1.CustomResourceDefinitionNames{
		Kind:       "ManifestIntegrityProfile",
		Plural:     "manifestintegrityprofiles",
		ListKind:   "ManifestIntegrityProfileList",
		Singular:   "manifestintegrityprofile",
		ShortNames: []string{"mip", "mips"},
	}
	return buildCRD("manifestintegrityprofiles.apis.integrityshield.io", cr.Namespace, crdNames, true)
}

//shield config crd
func BuildVerifyResourceResultCRD(cr *apiv1alpha1.IntegrityShield) *extv1.CustomResourceDefinition {
	crdNames := extv1.CustomResourceDefinitionNames{
		Kind:       "VerifyResourceStatus",
		Plural:     "verifyresourcestatuses",
		ListKind:   "VerifyResourceStatusList",
		Singular:   "verifyresourcestatus",
		ShortNames: []string{"vrs"},
	}
	return buildCRD("verifyresourcestatuses.apis.integrityshield.io", cr.Namespace, crdNames, true)
}
