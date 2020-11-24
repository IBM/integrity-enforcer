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
	apiv1alpha1 "github.com/IBM/integrity-enforcer/integrity-verifier-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//sa
func BuildServiceAccountForIV(cr *apiv1alpha1.IntegrityVerifier) *corev1.ServiceAccount {
	labels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetServiceAccountName(),
			Namespace: cr.Namespace,
			Labels:    labels,
		},
	}
	return sa
}

//cluster role
func BuildClusterRoleForIV(cr *apiv1alpha1.IntegrityVerifier) *rbacv1.ClusterRole {
	labels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetClusterRoleName(),
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"extensions", "", "apis.integrityverifier.io",
				},
				Resources: []string{
					"secrets", "namespaces", "resourcesignatures", "verifierconfigs", "signpolicies", "signpolicies", "resourcesigningprofiles", "resourcesignatures",
				},
				Verbs: []string{
					"get", "list", "watch", "patch", "update",
				},
			},
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"events",
				},
				Verbs: []string{
					"create", "update", "get",
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
func BuildClusterRoleBindingForIV(cr *apiv1alpha1.IntegrityVerifier) *rbacv1.ClusterRoleBinding {
	labels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}
	rolebinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetClusterRoleBindingName(),
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      cr.GetServiceAccountName(),
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
func BuildRoleForIV(cr *apiv1alpha1.IntegrityVerifier) *rbacv1.Role {
	labels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetDryRunRoleName(),
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
					"get", "create", "update",
				},
			},
		},
	}
	return role
}

//role-binding
func BuildRoleBindingForIV(cr *apiv1alpha1.IntegrityVerifier) *rbacv1.RoleBinding {
	labels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}
	rolebinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetDryRunRoleBindingName(),
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      cr.GetServiceAccountName(),
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

//role
func BuildRoleForIVAdmin(cr *apiv1alpha1.IntegrityVerifier) *rbacv1.Role {
	labels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetIVAdminRoleName(),
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"integrityverifiers",
					"verifierconfigs",
					"signpolicies",
				},
				Verbs: []string{
					"update", "create", "delete", "get", "list", "watch", "patch",
				},
			},
		},
	}
	return role
}

//role-binding
func BuildRoleBindingForIVAdmin(cr *apiv1alpha1.IntegrityVerifier) *rbacv1.RoleBinding {
	labels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}
	rolebinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetIVAdminRoleBindingName(),
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Subjects: cr.Spec.Security.IVAdminSubjects,
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "iv-admin-role",
		},
	}
	return rolebinding
}

//role
func BuildClusterRoleForIVAdmin(cr *apiv1alpha1.IntegrityVerifier) *rbacv1.ClusterRole {
	labels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetIVAdminClusterRoleName(),
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"resourcesigningprofiles",
					"resourcesignatures",
				},
				Verbs: []string{
					"update", "create", "delete", "get", "list", "watch", "patch",
				},
			},
		},
	}
	return role
}

//role-binding
func BuildClusterRoleBindingForIVAdmin(cr *apiv1alpha1.IntegrityVerifier) *rbacv1.ClusterRoleBinding {
	labels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}
	rolebinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetIVAdminClusterRoleBindingName(),
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Subjects: cr.Spec.Security.IVAdminSubjects,
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "iv-admin-clusterrole",
		},
	}
	return rolebinding
}

//pod security policy
func BuildPodSecurityPolicy(cr *apiv1alpha1.IntegrityVerifier) *policyv1.PodSecurityPolicy {
	labels := map[string]string{
		"app": cr.Name,
	}
	psp := &policyv1.PodSecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetPodSecurityPolicyName(),
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
