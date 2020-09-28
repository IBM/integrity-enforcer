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
	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	researchv1alpha1 "github.com/IBM/integrity-enforcer/develop/signservice/signservice-operator/pkg/apis/research/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	intstr "k8s.io/apimachinery/pkg/util/intstr"
)

const SignServiceServiceName = "ie-signservice"
const SignServiceServerCertName = "ie-signservice-cert"

func BuildSignServiceSecretForIE(cr *researchv1alpha1.SignService) *corev1.Secret {
	metaLabels := map[string]string{
		"app":                    cr.Name,
		"app.kubernetes.io/name": cr.Spec.SignServiceSecretName,
		// "app.kubernetes.io/component":  instance.ReleaseName(),
		"app.kubernetes.io/managed-by": "operator",
		// "app.kubernetes.io/instance":   instance.ReleaseName(),
		// "release":                      instance.ReleaseName(),
		"role": "security",
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.SignServiceSecretName,
			Namespace: cr.Namespace,
			Labels:    metaLabels,
		},
		Data: make(map[string][]byte),
		Type: corev1.SecretTypeOpaque,
	}
	return sec
}

func BuildIECertPoolSecretForIE(cr *researchv1alpha1.SignService) *corev1.Secret {
	metaLabels := map[string]string{
		"app":                    cr.Name,
		"app.kubernetes.io/name": cr.Spec.IECertPoolSecretName,
		// "app.kubernetes.io/component":  instance.ReleaseName(),
		"app.kubernetes.io/managed-by": "operator",
		// "app.kubernetes.io/instance":   instance.ReleaseName(),
		// "release":                      instance.ReleaseName(),
		"role": "security",
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.IECertPoolSecretName,
			Namespace: cr.Namespace,
			Labels:    metaLabels,
		},
		Data: make(map[string][]byte),
		Type: corev1.SecretTypeOpaque,
	}
	return sec
}

//server-secret.yaml
func BuildKeyringSecretForIE(cr *researchv1alpha1.SignService) *corev1.Secret {
	metaLabels := map[string]string{
		"app":                    cr.Name,
		"app.kubernetes.io/name": cr.Spec.KeyRingSecretName,
		// "app.kubernetes.io/component":  instance.ReleaseName(),
		"app.kubernetes.io/managed-by": "operator",
		// "app.kubernetes.io/instance":   instance.ReleaseName(),
		// "release":                      instance.ReleaseName(),
		"role": "security",
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.KeyRingSecretName,
			Namespace: cr.Namespace,
			Labels:    metaLabels,
		},
		Data: make(map[string][]byte),
		Type: corev1.SecretTypeOpaque,
	}
	return sec
}

func BuildPrivateKeyringSecretForIE(cr *researchv1alpha1.SignService) *corev1.Secret {
	metaLabels := map[string]string{
		"app":                    cr.Name,
		"app.kubernetes.io/name": cr.Spec.PrivateKeyRingSecretName,
		// "app.kubernetes.io/component":  instance.ReleaseName(),
		"app.kubernetes.io/managed-by": "operator",
		// "app.kubernetes.io/instance":   instance.ReleaseName(),
		// "release":                      instance.ReleaseName(),
		"role": "security",
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.PrivateKeyRingSecretName,
			Namespace: cr.Namespace,
			Labels:    metaLabels,
		},
		Data: make(map[string][]byte),
		Type: corev1.SecretTypeOpaque,
	}
	return sec
}

func BuildServerCertSecretForIE(cr *researchv1alpha1.SignService) *corev1.Secret {
	metaLabels := map[string]string{
		"app":                    cr.Name,
		"app.kubernetes.io/name": SignServiceServerCertName,
		// "app.kubernetes.io/component":  instance.ReleaseName(),
		"app.kubernetes.io/managed-by": "operator",
		// "app.kubernetes.io/instance":   instance.ReleaseName(),
		// "release":                      instance.ReleaseName(),
		"role": "security",
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SignServiceServerCertName,
			Namespace: cr.Namespace,
			Labels:    metaLabels,
		},
		Data: map[string][]byte{
			"server.crt": []byte(``),
			"server.key": []byte(``),
			"ca.crt":     []byte(``),
		},
		Type: corev1.SecretTypeOpaque,
	}
	return sec
}

//sa
func BuildSignServiceServiceAccount(cr *researchv1alpha1.SignService) *corev1.ServiceAccount {
	labels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.ServiceAccountName,
			Namespace: cr.Namespace,
			Labels:    labels,
		},
	}
	return sa
}

//role
func BuildSignServiceRole(cr *researchv1alpha1.SignService) *rbacv1.Role {
	labels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Name,
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Rules: []rbacv1.PolicyRule{},
	}
	return role
}

//role-binding
func BuildSignServiceRoleBinding(cr *researchv1alpha1.SignService) *rbacv1.RoleBinding {
	labels := map[string]string{
		"app":                          cr.Name,
		"app.kubernetes.io/name":       cr.Name,
		"app.kubernetes.io/managed-by": "operator",
		"role":                         "security",
	}
	rolebinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Name,
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      cr.Spec.ServiceAccountName,
				Namespace: cr.Namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     cr.Name,
		},
	}
	return rolebinding
}

//signservice deployment
func BuildSignServiceDeploymentForCR(cr *researchv1alpha1.SignService) *appsv1.Deployment {
	labels := map[string]string{"app": cr.Spec.SignService.AppName}
	var defaultReplicas int32 = 1

	container := v1.Container{
		Name:            "signservice",
		Image:           cr.Spec.SignService.Image,
		ImagePullPolicy: cr.Spec.SignService.ImagePullPolicy,
		Ports: []v1.ContainerPort{
			{
				Name:          "ac-sign",
				ContainerPort: cr.Spec.SignService.Port,
				Protocol:      v1.ProtocolTCP,
			},
		},
		VolumeMounts: []v1.VolumeMount{
			{
				MountPath: "/signservice-secret",
				Name:      "signservice-secret",
			},
			{
				MountPath: "/ie-certpool-secret",
				Name:      "ie-certpool-secret",
			},
			{
				MountPath: "/keyring-secret",
				Name:      "keyring-secret",
			},
			{
				MountPath: "/private-keyring-secret",
				Name:      "private-keyring-secret",
			},
			{
				MountPath: "/certs",
				Name:      "ie-server-cert",
			},
		},
	}

	containers := []v1.Container{
		container,
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Name,
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{

			Replicas: &defaultReplicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": cr.Spec.SignService.AppName},
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: v1.PodSpec{
					ImagePullSecrets:   cr.Spec.ImagePullSecrets,
					ServiceAccountName: cr.Spec.ServiceAccountName,
					Containers:         containers,

					Volumes: []v1.Volume{
						SecretVolume("signservice-secret", cr.Spec.SignServiceSecretName),
						SecretVolume("ie-certpool-secret", cr.Spec.IECertPoolSecretName),
						SecretVolume("keyring-secret", cr.Spec.KeyRingSecretName),
						SecretVolume("private-keyring-secret", cr.Spec.PrivateKeyRingSecretName),
						SecretVolume("ie-server-cert", SignServiceServerCertName),
					},
				},
			},
		},
	}
}

//signservice service
func BuildSignServiceServiceForCR(cr *researchv1alpha1.SignService) *corev1.Service {
	var targetport intstr.IntOrString
	targetport.Type = intstr.String
	targetport.StrVal = "ac-sign"
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SignServiceServiceName,
			Namespace: cr.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       cr.Spec.SignService.Port,
					TargetPort: targetport, //"ac-sign"
				},
			},
			Selector: map[string]string{"app": SignServiceServiceName},
		},
	}
	return svc
}
