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
	"fmt"
	"reflect"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv1alpha1 "github.com/IBM/integrity-enforcer/integrity-enforcer-operator/api/v1alpha1"
	v1 "k8s.io/api/core/v1"
)

//deployment
func BuildDeploymentForCR(cr *apiv1alpha1.IntegrityEnforcer) *appsv1.Deployment {
	labels := cr.Spec.MetaLabels

	var volumemounts []v1.VolumeMount
	var servervolumemounts []v1.VolumeMount
	var volumes []v1.Volume

	volumemounts = []v1.VolumeMount{
		{
			MountPath: "/ie-app/public",
			Name:      "log-volume",
		},
	}

	volumes = []v1.Volume{
		SecretVolume("ie-tls-certs", cr.GetWebhookServerTlsSecretName()),
		EmptyDirVolume("log-volume"),
		EmptyDirVolume("tmp"),
	}
	for _, keyConf := range cr.Spec.KeyRings {
		tmpSecretVolume := SecretVolume(keyConf.Name, keyConf.Name)
		volumes = append(volumes, tmpSecretVolume)
	}

	servervolumemounts = []v1.VolumeMount{
		{
			MountPath: "/run/secrets/tls",
			Name:      "ie-tls-certs",
			ReadOnly:  true,
		},
		{
			MountPath: "/tmp",
			Name:      "tmp",
		},
		{
			MountPath: "/ie-app/public",
			Name:      "log-volume",
		},
	}
	for _, keyConf := range cr.Spec.KeyRings {
		tmpVolumeMount := v1.VolumeMount{MountPath: "/" + keyConf.Name, Name: keyConf.Name}
		servervolumemounts = append(servervolumemounts, tmpVolumeMount)
	}

	if cr.Spec.Logger.EsConfig.Enabled && cr.Spec.Logger.EsConfig.Scheme == "https" {
		tlsVolMnt := v1.VolumeMount{
			MountPath: "/run/secrets/es_tls",
			Name:      "es-tls-certs",
			ReadOnly:  true,
		}
		volumemounts = append(volumemounts, tlsVolMnt)
		volumes = append(volumes, SecretVolume("es-tls-certs", cr.Spec.Logger.EsSecretName))
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
				Exec: &v1.ExecAction{
					Command: []string{
						"ls",
					},
				},
			},
		},
		Ports: []v1.ContainerPort{
			{
				Name:          "ac-api",
				ContainerPort: cr.Spec.Server.Port,
				Protocol:      v1.ProtocolTCP,
			},
		},
		VolumeMounts: servervolumemounts,
		Env: []v1.EnvVar{
			{
				Name:  "ENFORCER_NS",
				Value: cr.Namespace,
			},
			{
				Name:  "ENFORCER_CONFIG_NAME",
				Value: cr.GetEnforcerConfigCRName(),
			},
			{
				Name:  "CHART_BASE_URL",
				Value: cr.Spec.Server.ChartBaseUrl,
			},
			{
				Name:  "ENFORCER_CM_RELOAD_SEC",
				Value: strconv.Itoa(int(cr.Spec.Server.EnforcerCmReloadSec)),
			},
			{
				Name:  "ENFORCE_POLICY_RELOAD_SEC",
				Value: strconv.Itoa(int(cr.Spec.Server.EnforcePolicyReloadSec)),
			},
		},
		Resources: cr.Spec.Server.Resources,
	}

	loggerContainer := v1.Container{
		Name:            cr.Spec.Logger.Name,
		SecurityContext: cr.Spec.Logger.SecurityContext,
		Image:           cr.Spec.Logger.Image,
		ImagePullPolicy: cr.Spec.Logger.ImagePullPolicy,
		VolumeMounts:    volumemounts,
		Env: []v1.EnvVar{
			{
				Name:  "STDOUT_ENABLED",
				Value: strconv.FormatBool(cr.Spec.Logger.StdOutput),
			},
			{
				Name:  "HTTPOUT_ENABLED",
				Value: strconv.FormatBool(cr.Spec.Logger.HttpConfig.Enabled),
			},
			{
				Name:  "HTTPOUT_ENDPOINT_URL",
				Value: cr.Spec.Logger.HttpConfig.Endpoint,
			},
			{
				Name:  "ES_ENABLED",
				Value: strconv.FormatBool(cr.Spec.Logger.EsConfig.Enabled),
			},
			{
				Name:  "FLUENT_ELASTICSEARCH_SCHEME",
				Value: cr.Spec.Logger.EsConfig.Scheme,
			},
			{
				Name:  "FLUENT_ELASTICSEARCH_HOST",
				Value: cr.Spec.Logger.EsConfig.Host,
			},
			{
				Name:  "FLUENT_ELASTICSEARCH_PORT",
				Value: strconv.Itoa(int(cr.Spec.Logger.EsConfig.Port)),
			},
			{
				Name:  "FLUENT_ELASTICSEARCH_SSL_VERIFY",
				Value: strconv.FormatBool(cr.Spec.Logger.EsConfig.SslVerify),
			},
			{
				Name:  "CA_FILE",
				Value: fmt.Sprintf("/run/secrets/es_tls/%s", cr.Spec.Logger.EsConfig.CaFile),
			},
			{
				Name:  "CLIENT_CERT",
				Value: fmt.Sprintf("/run/secrets/es_tls/%s", cr.Spec.Logger.EsConfig.ClientCert),
			},
			{
				Name:  "CLIENT_KEY",
				Value: fmt.Sprintf("/run/secrets/es_tls/%s", cr.Spec.Logger.EsConfig.ClientKey),
			},
			{
				Name:  "ES_INDEX_PREFIX",
				Value: cr.Spec.Logger.EsConfig.IndexPrefix,
			},
			{
				Name:  "EVENTS_FILE_PATH",
				Value: "/ie-app/public/events.txt",
			},
		},
		Resources: cr.Spec.Logger.Resources,
	}

	containers := []v1.Container{
		serverContainer,
	}

	if cr.Spec.Logger.Enabled {
		containers = append(containers, loggerContainer)
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetIEServerDeploymentName(),
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
				MatchLabels: cr.Spec.SelectorLabels,
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: cr.Spec.SelectorLabels,
				},
				Spec: v1.PodSpec{
					ImagePullSecrets:   cr.Spec.ImagePullSecrets,
					ServiceAccountName: cr.GetServiceAccountName(),
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
	if !reflect.DeepEqual(found, expected) {
		return false
	}
	return true
}

func EqualAnnotations(found map[string]string, expected map[string]string) bool {
	if !reflect.DeepEqual(found, expected) {
		return false
	}
	return true
}

// ie-rule-table-lock ConfigMap
func BuildRuleTableLockConfigMapForCR(cr *apiv1alpha1.IntegrityEnforcer) *v1.ConfigMap {
	labels := cr.Spec.MetaLabels

	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetRuleTableLockCMName(),
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		BinaryData: map[string][]byte{"table": nil},
	}
}

// ie-ignore-table-lock ConfigMap
func BuildIgnoreRuleTableLockConfigMapForCR(cr *apiv1alpha1.IntegrityEnforcer) *v1.ConfigMap {
	labels := cr.Spec.MetaLabels

	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetIgnoreTableLockCMName(),
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		BinaryData: map[string][]byte{"table": nil},
	}
}

// ie-force-check-table-lock ConfigMap
func BuildForceCheckRuleTableLockConfigMapForCR(cr *apiv1alpha1.IntegrityEnforcer) *v1.ConfigMap {
	labels := cr.Spec.MetaLabels

	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.GetForceCheckTableLockCMName(),
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		BinaryData: map[string][]byte{"table": nil},
	}
}
