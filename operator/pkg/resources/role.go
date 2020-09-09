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
	"strings"

	researchv1alpha1 "github.com/IBM/integrity-enforcer/operator/pkg/apis/research/v1alpha1"
	scc "github.com/openshift/api/security/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//scc
func BuildSecurityContextConstraints(cr *researchv1alpha1.IntegrityEnforcer) *scc.SecurityContextConstraints {
	user := strings.Join([]string{"system:serviceaccount", cr.Namespace, cr.Spec.Security.ServiceAccountName}, ":")
	privilegeEscalation := false
	allowPrivilegeEscalation := false
	var priority int32 = 500001
	metaLabels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}

	return &scc.SecurityContextConstraints{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SecurityContextConstraints",
			APIVersion: scc.GroupVersion.Group + "/" + scc.GroupVersion.Version,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   cr.Spec.Security.SecurityContextConstraintsName,
			Labels: metaLabels,
		},
		Priority:                        &priority,
		AllowPrivilegedContainer:        false,
		DefaultAddCapabilities:          []corev1.Capability{},
		RequiredDropCapabilities:        []corev1.Capability{},
		AllowedCapabilities:             []corev1.Capability{},
		AllowHostDirVolumePlugin:        false,
		AllowedFlexVolumes:              []scc.AllowedFlexVolume{},
		AllowHostNetwork:                false,
		AllowHostPID:                    false,
		AllowHostIPC:                    false,
		DefaultAllowPrivilegeEscalation: &privilegeEscalation,
		AllowPrivilegeEscalation:        &allowPrivilegeEscalation,
		SELinuxContext:                  scc.SELinuxContextStrategyOptions{Type: scc.SELinuxStrategyRunAsAny, SELinuxOptions: &corev1.SELinuxOptions{}},
		RunAsUser:                       scc.RunAsUserStrategyOptions{Type: scc.RunAsUserStrategyMustRunAsNonRoot},
		SupplementalGroups:              scc.SupplementalGroupsStrategyOptions{},
		FSGroup:                         scc.FSGroupStrategyOptions{},
		ReadOnlyRootFilesystem:          false,
		Users:                           []string{user},
		Groups:                          []string{},
		SeccompProfiles:                 []string{},
		AllowedUnsafeSysctls:            []string{},
		ForbiddenSysctls:                []string{},
		Volumes:                         []scc.FSType{scc.FSTypeEmptyDir, scc.FSTypeSecret},
	}
}

//sa
func BuildServiceAccountForIE(cr *researchv1alpha1.IntegrityEnforcer) *corev1.ServiceAccount {
	labels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.Security.ServiceAccountName,
			Namespace: cr.Namespace,
			Labels:    labels,
		},
	}
	return sa
}

//cluster role
func BuildClusterRoleForIE(cr *researchv1alpha1.IntegrityEnforcer) *rbacv1.ClusterRole {
	labels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.Security.ClusterRole,
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"extensions", "", "research.ibm.com",
				},
				Resources: []string{
					"secrets", "namespaces", "resourcesignatures", "enforcerconfigs", "signpolicies", "protectrules",
				},
				Verbs: []string{
					"get", "list", "watch", "patch", "update",
				},
			},
			{
				APIGroups: []string{
					"*",
				},
				Resources: []string{
					"*",
				},
				Verbs: []string{
					"get",
				},
			},
			// {
			// 	APIGroups: []string{
			// 		"extensions",
			// 	},
			// 	Resources: []string{
			// 		"podsecuritypolicies",
			// 	},
			// 	Verbs: []string{
			// 		"use",
			// 	},
			// 	ResourceNames: []string{
			// 		cr.Spec.Security.PodSecurityPolicyName,
			// 	},
			// },
		},
	}
	return role
}

//cluster role-binding
func BuildClusterRoleBindingForIE(cr *researchv1alpha1.IntegrityEnforcer) *rbacv1.ClusterRoleBinding {
	labels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}
	rolebinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.Security.ClusterRoleBinding,
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      cr.Spec.Security.ServiceAccountName,
				Namespace: cr.Namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     cr.Spec.Security.ClusterRole,
		},
	}
	return rolebinding
}

//role
func BuildRoleForIE(cr *researchv1alpha1.IntegrityEnforcer) *rbacv1.Role {
	labels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.Security.ClusterRole + "-sim",
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"*",
				},
				Resources: []string{
					"*",
				},
				Verbs: []string{
					"get", "create",
				},
			},
		},
	}
	return role
}

//role-binding
func BuildRoleBindingForIE(cr *researchv1alpha1.IntegrityEnforcer) *rbacv1.RoleBinding {
	labels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}
	rolebinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.Security.ClusterRoleBinding + "-sim",
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      cr.Spec.Security.ServiceAccountName,
				Namespace: cr.Namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     cr.Spec.Security.ClusterRole + "-sim",
		},
	}
	return rolebinding
}

//pod security policy
func BuildPodSecurityPolicy(cr *researchv1alpha1.IntegrityEnforcer) *policyv1.PodSecurityPolicy {
	labels := map[string]string{
		"app": cr.Name,
	}
	psp := &policyv1.PodSecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.Security.PodSecurityPolicyName,
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Spec: policyv1.PodSecurityPolicySpec{
			Privileged: true,
			FSGroup: policyv1.FSGroupStrategyOptions{
				Rule: policyv1.FSGroupStrategyMustRunAs,
				Ranges: []policyv1.IDRange{
					{
						Min: 1,
						Max: 65535,
					},
				},
			},
			RunAsUser: policyv1.RunAsUserStrategyOptions{
				Rule: policyv1.RunAsUserStrategyRunAsAny,
			},
			SELinux: policyv1.SELinuxStrategyOptions{
				Rule: policyv1.SELinuxStrategyRunAsAny,
			},
			SupplementalGroups: policyv1.SupplementalGroupsStrategyOptions{
				Rule: policyv1.SupplementalGroupsStrategyMustRunAs,
				Ranges: []policyv1.IDRange{
					{
						Min: 1,
						Max: 65535,
					},
				},
			},
			Volumes: []policyv1.FSType{
				policyv1.ConfigMap,
				policyv1.HostPath,
				policyv1.EmptyDir,
				policyv1.Secret,
				policyv1.PersistentVolumeClaim,
			},
			AllowedHostPaths: []policyv1.AllowedHostPath{
				{
					PathPrefix: "/",
				},
			},
			AllowedCapabilities: []corev1.Capability{
				policyv1.AllowAllCapabilities,
			},
			HostNetwork: true,
			HostIPC:     true,
			HostPID:     true,
		},
	}
	return psp
}
