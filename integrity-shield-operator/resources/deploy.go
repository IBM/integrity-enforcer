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
	"reflect"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	intstr "k8s.io/apimachinery/pkg/util/intstr"

	apiv1alpha1 "github.com/IBM/integrity-shield/integrity-shield-operator/api/v1alpha1"
	v1 "k8s.io/api/core/v1"
)

//deployment

// shield api
func BuildDeploymentForIShieldServer(cr *apiv1alpha1.IntegrityShield) *appsv1.Deployment {
	var servervolumemounts []v1.VolumeMount
	var volumes []v1.Volume
	labels := cr.Spec.MetaLabels
	volumes = []v1.Volume{
		SecretVolume("ishield-api-certs", cr.Spec.ServerTlsSecretName),
		EmptyDirVolume("tmp"),
	}

	servervolumemounts = []v1.VolumeMount{
		{
			MountPath: "/run/secrets/tls",
			Name:      "ishield-api-certs",
			ReadOnly:  true,
		},
		{
			MountPath: "/tmp",
			Name:      "tmp",
		},
	}

	serverContainer := v1.Container{
		Name:            cr.Spec.Server.Name,
		SecurityContext: cr.Spec.Server.SecurityContext,
		Image:           cr.Spec.Server.Image,
		ImagePullPolicy: cr.Spec.Server.ImagePullPolicy,
		ReadinessProbe: &v1.Probe{
			InitialDelaySeconds: 10,
			PeriodSeconds:       10,
			Handler: v1.Handler{
				HTTPGet: &v1.HTTPGetAction{
					Path:   "/health/readiness",
					Port:   intstr.IntOrString{IntVal: 8080},
					Scheme: v1.URISchemeHTTPS,
				},
			},
		},
		LivenessProbe: &v1.Probe{
			InitialDelaySeconds: 10,
			PeriodSeconds:       10,
			Handler: v1.Handler{
				HTTPGet: &v1.HTTPGetAction{
					Path:   "/health/liveness",
					Port:   intstr.IntOrString{IntVal: 8080},
					Scheme: v1.URISchemeHTTPS,
				},
			},
		},
		Ports: []v1.ContainerPort{
			{
				Name:          "ishield-api",
				ContainerPort: cr.Spec.Server.Port,
				Protocol:      v1.ProtocolTCP,
			},
		},
		VolumeMounts: servervolumemounts,
		Env: []v1.EnvVar{
			{
				Name:  "POD_NAMESPACE",
				Value: cr.Namespace,
			},
			{
				Name:  "REQUEST_HANDLER_CONFIG_KEY",
				Value: cr.Spec.RequestHandlerConfigKey,
			},
			{
				Name:  "REQUEST_HANDLER_CONFIG_NAME",
				Value: cr.Spec.RequestHandlerConfigName,
			},
			{
				Name:  "CONSTRAINT_CONFIG_NAME",
				Value: cr.Spec.ConstraintConfigName,
			},
			{
				Name:  "CONSTRAINT_CONFIG_KEY",
				Value: cr.Spec.ConstraintConfigKey,
			},
		},
		Resources: cr.Spec.Server.Resources,
	}

	containers := []v1.Container{
		serverContainer,
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.Server.Name,
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Strategy: appsv1.DeploymentStrategy{
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxSurge:       cr.Spec.MaxSurge,
					MaxUnavailable: cr.Spec.MaxUnavailable,
				},
			},
			Replicas: cr.Spec.ReplicaCount,
			Selector: &metav1.LabelSelector{
				MatchLabels: cr.Spec.Server.SelectorLabels,
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: cr.Spec.Server.SelectorLabels,
				},
				Spec: v1.PodSpec{
					ServiceAccountName: cr.Spec.Security.ServerServiceAccountName,
					SecurityContext:    cr.Spec.Security.PodSecurityContext,
					Containers:         containers,
					NodeSelector:       cr.Spec.NodeSelector,
					Affinity:           cr.Spec.Affinity,
					Tolerations:        cr.Spec.Tolerations,

					Volumes: volumes,
				},
			},
		},
	}
}

// admission controller
func BuildDeploymentForAdmissionController(cr *apiv1alpha1.IntegrityShield) *appsv1.Deployment {
	labels := cr.Spec.MetaLabels

	volumes := []v1.Volume{
		SecretVolume("webhook-tls", cr.Spec.WebhookServerTlsSecretName),
		EmptyDirVolume("tmp"),
	}

	servervolumemounts := []v1.VolumeMount{
		{
			MountPath: "/run/secrets/tls",
			Name:      "webhook-tls",
			ReadOnly:  true,
		},
		{
			MountPath: "/tmp",
			Name:      "tmp",
		},
	}

	serverContainer := v1.Container{
		Command: []string{
			"/myapp/k8s-manifest-sigstore",
		},
		Name:            cr.Spec.ControllerContainer.Name,
		SecurityContext: cr.Spec.ControllerContainer.SecurityContext,
		Image:           cr.Spec.ControllerContainer.Image,
		ImagePullPolicy: cr.Spec.ControllerContainer.ImagePullPolicy,
		ReadinessProbe: &v1.Probe{
			Handler: v1.Handler{
				Exec: &v1.ExecAction{
					Command: []string{
						"ls",
					},
				},
			},
		},
		LivenessProbe: &v1.Probe{
			Handler: v1.Handler{
				Exec: &v1.ExecAction{
					Command: []string{
						"ls",
					},
				},
			},
		},
		Ports: []v1.ContainerPort{
			{
				Name:          "validator-port",
				ContainerPort: cr.Spec.ControllerContainer.Port,
				Protocol:      v1.ProtocolTCP,
			},
		},
		VolumeMounts: servervolumemounts,
		Env: []v1.EnvVar{
			{
				Name:  "POD_NAMESPACE",
				Value: cr.Namespace,
			},
			{
				Name:  "LOG_LEVEL",
				Value: cr.Spec.ControllerContainer.Log.LogLevel,
			},
			{
				Name:  "LOG_FORMAT",
				Value: cr.Spec.ControllerContainer.Log.LogFormat,
			},
			{
				Name:  "CONTROLLER_CONFIG_KEY",
				Value: cr.Spec.AdmissionControllerConfigKey,
			},
			{
				Name:  "CONTROLLER_CONFIG_NAME",
				Value: cr.Spec.AdmissionControllerConfigName,
			},
			{
				Name:  "REQUEST_HANDLER_CONFIG_KEY",
				Value: cr.Spec.RequestHandlerConfigKey,
			},
			{
				Name:  "REQUEST_HANDLER_CONFIG_NAME",
				Value: cr.Spec.RequestHandlerConfigName,
			},
			{
				Name:  "CONSTRAINT_CONFIG_NAME",
				Value: cr.Spec.ConstraintConfigName,
			},
			{
				Name:  "CONSTRAINT_CONFIG_KEY",
				Value: cr.Spec.ConstraintConfigKey,
			},
		},
		Resources: cr.Spec.ControllerContainer.Resources,
	}

	containers := []v1.Container{
		serverContainer,
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.ControllerContainer.Name,
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Strategy: appsv1.DeploymentStrategy{
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxSurge:       cr.Spec.MaxSurge,
					MaxUnavailable: cr.Spec.MaxUnavailable,
				},
			},
			Replicas: cr.Spec.ReplicaCount,
			Selector: &metav1.LabelSelector{
				MatchLabels: cr.Spec.ControllerContainer.SelectorLabels,
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: cr.Spec.ControllerContainer.SelectorLabels,
				},
				Spec: v1.PodSpec{
					ServiceAccountName: cr.Spec.Security.ServerServiceAccountName,
					SecurityContext:    cr.Spec.Security.PodSecurityContext,
					Containers:         containers,
					NodeSelector:       cr.Spec.NodeSelector,
					Affinity:           cr.Spec.Affinity,
					Tolerations:        cr.Spec.Tolerations,

					Volumes: volumes,
				},
			},
		},
	}
}

// Observer
func BuildDeploymentForObserver(cr *apiv1alpha1.IntegrityShield) *appsv1.Deployment {
	labels := cr.Spec.MetaLabels
	volumes := []v1.Volume{
		EmptyDirVolume("tmp"),
	}
	servervolumemounts := []v1.VolumeMount{
		{
			MountPath: "/tmp",
			Name:      "tmp",
		},
	}

	serverContainer := v1.Container{
		Name:            cr.Spec.Observer.Name,
		SecurityContext: cr.Spec.Observer.SecurityContext,
		Image:           cr.Spec.Observer.Image,
		ImagePullPolicy: cr.Spec.Observer.ImagePullPolicy,
		VolumeMounts:    servervolumemounts,
		Env: []v1.EnvVar{
			{
				Name:  "POD_NAMESPACE",
				Value: cr.Namespace,
			},
			{
				Name:  "LOG_LEVEL",
				Value: cr.Spec.Observer.LogLevel,
			},
			{
				Name:  "REQUEST_HANDLER_CONFIG_KEY",
				Value: cr.Spec.RequestHandlerConfigKey,
			},
			{
				Name:  "REQUEST_HANDLER_CONFIG_NAME",
				Value: cr.Spec.RequestHandlerConfigName,
			},
			{
				Name:  "OBSERVER_RESULT_ENABLED",
				Value: strconv.FormatBool(cr.Spec.Observer.ExportDetailResult),
			},
			{
				Name:  "OBSERVER_RESULT_CONFIG_NAME",
				Value: cr.Spec.Observer.ResultDetailConfigName,
			},
			{
				Name:  "OBSERVER_RESULT_CONFIG_KEY",
				Value: cr.Spec.Observer.ResultDetailConfigKey,
			},
			{
				Name:  "CONSTRAINT_CONFIG_NAME",
				Value: cr.Spec.ConstraintConfigName,
			},
			{
				Name:  "CONSTRAINT_CONFIG_KEY",
				Value: cr.Spec.ConstraintConfigKey,
			},
			{
				Name:  "INTERVAL",
				Value: cr.Spec.Observer.Interval,
			},
		},
		Resources: cr.Spec.ControllerContainer.Resources,
	}

	containers := []v1.Container{
		serverContainer,
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.Observer.Name,
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Strategy: appsv1.DeploymentStrategy{
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxSurge:       cr.Spec.MaxSurge,
					MaxUnavailable: cr.Spec.MaxUnavailable,
				},
			},
			Replicas: cr.Spec.ReplicaCount,
			Selector: &metav1.LabelSelector{
				MatchLabels: cr.Spec.Observer.SelectorLabels,
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: cr.Spec.Observer.SelectorLabels,
				},
				Spec: v1.PodSpec{
					ServiceAccountName: cr.Spec.Security.ObserverServiceAccountName,
					SecurityContext:    cr.Spec.Security.PodSecurityContext,
					Containers:         containers,
					NodeSelector:       cr.Spec.NodeSelector,
					Affinity:           cr.Spec.Affinity,
					Tolerations:        cr.Spec.Tolerations,

					Volumes: volumes,
				},
			},
		},
	}
}

var int420Var int32 = 420

func SecretVolume(name, secretName string) v1.Volume {

	return v1.Volume{
		Name: name,
		VolumeSource: v1.VolumeSource{
			Secret: &v1.SecretVolumeSource{
				SecretName:  secretName,
				DefaultMode: &int420Var,
			},
		},
	}

}

func EmptyDirVolume(name string) v1.Volume {

	return v1.Volume{
		Name: name,
		VolumeSource: v1.VolumeSource{
			EmptyDir: &v1.EmptyDirVolumeSource{},
		},
	}
}

// EqualDeployments returns a Boolean
func EqualDeployments(expected *appsv1.Deployment, found *appsv1.Deployment) bool {
	if !EqualLabels(found.ObjectMeta.Labels, expected.ObjectMeta.Labels) {
		return false
	}
	if !EqualPods(expected.Spec.Template, found.Spec.Template) {
		return false
	}
	return true
}

// EqualPods returns a Boolean
func EqualPods(expected v1.PodTemplateSpec, found v1.PodTemplateSpec) bool {
	if !EqualLabels(found.ObjectMeta.Labels, expected.ObjectMeta.Labels) {
		return false
	}
	if !EqualAnnotations(found.ObjectMeta.Annotations, expected.ObjectMeta.Annotations) {
		return false
	}
	if !reflect.DeepEqual(found.Spec.ServiceAccountName, expected.Spec.ServiceAccountName) {
		return false
	}
	if len(found.Spec.Containers) != len(expected.Spec.Containers) {
		return false
	}
	if !EqualContainers(expected.Spec.Containers[0], found.Spec.Containers[0]) {
		return false
	}
	return true
}

// EqualContainers returns a Boolean
func EqualContainers(expected v1.Container, found v1.Container) bool {
	if !reflect.DeepEqual(found.Name, expected.Name) {
		return false
	}
	if !reflect.DeepEqual(found.Image, expected.Image) {
		return false
	}
	if !reflect.DeepEqual(found.ImagePullPolicy, expected.ImagePullPolicy) {
		return false
	}
	if !reflect.DeepEqual(found.VolumeMounts, expected.VolumeMounts) {
		return false
	}
	if !reflect.DeepEqual(found.SecurityContext, expected.SecurityContext) {
		return false
	}
	if !reflect.DeepEqual(found.Ports, expected.Ports) {
		return false
	}
	if !reflect.DeepEqual(found.Args, expected.Args) {
		return false
	}
	if !reflect.DeepEqual(found.Env, expected.Env) {
		return false
	}
	return true
}

func EqualLabels(found map[string]string, expected map[string]string) bool {
	return reflect.DeepEqual(found, expected)
}

func EqualAnnotations(found map[string]string, expected map[string]string) bool {
	return reflect.DeepEqual(found, expected)
}
