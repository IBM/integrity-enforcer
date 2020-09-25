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

package v1alpha1

import (
	rpp "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourceprotectionprofile/v1alpha1"
	iec "github.com/IBM/integrity-enforcer/enforcer/pkg/config"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/policy"
	admv1 "k8s.io/api/admissionregistration/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	intstr "k8s.io/apimachinery/pkg/util/intstr"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// IntegrityEnforcerSpec defines the desired state of IntegrityEnforcer
type IntegrityEnforcerSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	MaxSurge         *intstr.IntOrString       `json:"maxSurge,omitempty"`
	MaxUnavailable   *intstr.IntOrString       `json:"maxUnavailable,omitempty"`
	ReplicaCount     *int32                    `json:"replicaCount,omitempty"`
	MetaLabels       map[string]string         `json:"labels,omitempty"`
	SelectorLabels   map[string]string         `json:"selector,omitempty"`
	NodeSelector     map[string]string         `json:"nodeSelector,omitempty"`
	Affinity         *v1.Affinity              `json:"affinity,omitempty"`
	Tolerations      []v1.Toleration           `json:"tolerations,omitempty"`
	ImagePullSecrets []v1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	Security     SecurityConfig  `json:"security,omitempty"`
	VerifyType   string          `json:"verifyType,omitempty"`
	KeyRing      KeyRingConfig   `json:"keyRingConfig,omitempty"`
	CertPool     CertPoolConfig  `json:"certPoolConfig,omitempty"`
	Server       ServerContainer `json:"server,omitempty"`
	Logger       LoggerContainer `json:"logger,omitempty"`
	RegKeySecret RegKeySecret    `json:"regKeySecret,omitempty"`
	GlobalConfig GlobalConfig    `json:"globalConfig,omitempty"`

	EnforcerConfigCrName string                         `json:"enforcerConfigCrName,omitempty"`
	EnforcerConfig       *iec.EnforcerConfig            `json:"enforcerConfig,omitempty"`
	SignPolicy           *policy.SignPolicy             `json:"signPolicy,omitempty"`
	DefaultRpp           *rpp.ResourceProtectionProfile `json:"defaultResourceProtectionProfile,omitempty"`

	SignatureNamespace string `json:"signatureNamespace,omitempty"`
	PolicyNamespace    string `json:"policyNamespace,omitempty"`

	WebhookServerTlsSecretName string     `json:"webhookServerTlsSecretName,omitempty"`
	WebhookServiceName         string     `json:"webhookServiceName,omitempty"`
	WebhookConfigName          string     `json:"webhookConfigName,omitempty"`
	WebhookNamespacedResource  admv1.Rule `json:"webhookNamespacedResource,omitempty"`
	WebhookClusterResource     admv1.Rule `json:"webhookClusterResource,omitempty"`
}

type SecurityConfig struct {
	ServiceAccountName             string                 `json:"serviceAccountName,omitempty"`
	SecurityContextConstraintsName string                 `json:"securityContextConstraintsName,omitempty"`
	ClusterRole                    string                 `json:"clusterRole,omitempty"`
	ClusterRoleBinding             string                 `json:"clusterRoleBinding,omitempty"`
	PodSecurityPolicyName          string                 `json:"podSecurityPolicyName,omitempty"`
	PodSecurityContext             *v1.PodSecurityContext `json:"securityContext,omitempty"`
}

type GlobalConfig struct {
	Arch          []string `json:"arch,omitempty"`
	NoCertManager bool     `json:"noCertManager,omitempty"`
	OpenShift     bool     `json:"openShift,omitempty"`
	Roks          bool     `json:"roks,omitempty"`
}

type RegKeySecret struct {
	Name  string `json:"name,omitempty"`
	Value []byte `json:"value,omitempty"`
}

type CertPoolConfig struct {
	Name             string `json:"name,omitempty"`
	CreateIfNotExist bool   `json:"createIfNotExist,omitempty"`
	KeyValue         []byte `json:"keyValue,omitempty"`
}

type KeyRingConfig struct {
	Name             string `json:"name,omitempty"`
	CreateIfNotExist bool   `json:"createIfNotExist,omitempty"`
	KeyValue         []byte `json:"keyValue,omitempty"`
}

type ServerContainer struct {
	Name                   string                  `json:"name,omitempty"`
	SecurityContext        *v1.SecurityContext     `json:"securityContext,omitempty"`
	ImagePullPolicy        v1.PullPolicy           `json:"imagePullPolicy,omitempty"`
	Image                  string                  `json:"image,omitempty"`
	Port                   int32                   `json:"port,omitempty"`
	Resources              v1.ResourceRequirements `json:"resources,omitempty"`
	ChartBaseUrl           string                  `json:"chartBaseUrl,omitempty"`
	ContextLogEnabled      bool                    `json:"contextLogEnabled,omitempty"`
	EnforcerCmReloadSec    int32                   `json:"enforcerCmReloadSec,omitempty"`
	EnforcePolicyReloadSec int32                   `json:"enforcePolicyReloadSec,omitempty"`
}

type LoggerContainer struct {
	Enabled         bool                    `json:"enabled,omitempty"`
	Name            string                  `json:"name,omitempty"`
	SecurityContext *v1.SecurityContext     `json:"securityContext,omitempty"`
	ImagePullPolicy v1.PullPolicy           `json:"imagePullPolicy,omitempty"`
	Image           string                  `json:"image,omitempty"`
	StdOutput       bool                    `json:"stdOutput,omitempty"`
	HttpConfig      *HttpConfig             `json:"http,omitempty"`
	Resources       v1.ResourceRequirements `json:"resources,omitempty"`
	EsConfig        *EsConfig               `json:"es,omitempty"`
	EsSecretName    string                  `json:"esSecretName,omitempty"`
}

type EsConfig struct {
	Enabled     bool   `json:"enabled,omitempty"`
	Scheme      string `json:"scheme,omitempty"`
	Host        string `json:"host,omitempty"`
	Port        int32  `json:"port,omitempty"`
	SslVerify   bool   `json:"sslVerify,omitempty"`
	IndexPrefix string `json:"indexPrefix,omitempty"`
	ClientKey   string `json:"clientKey,omitempty"`
	ClientCert  string `json:"clientCert,omitempty"`
	CaFile      string `json:"caFile,omitempty"`
}

type HttpConfig struct {
	Enabled  bool   `json:"enabled,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	// Scheme      string `json:"scheme,omitempty"`
	// Host        string `json:"host,omitempty"`
	// Port        int32  `json:"port,omitempty"`
	// SslVerify   bool   `json:"sslVerify,omitempty"`
	// IndexPrefix string `json:"indexPrefix,omitempty"`
	// ClientKey   string `json:"clientKey,omitempty"`
	// ClientCert  string `json:"clientCert,omitempty"`
	// CaFile      string `json:"caFile,omitempty"`
}

// IntegrityEnforcerStatus defines the observed state of IntegrityEnforcer
type IntegrityEnforcerStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IntegrityEnforcer is the Schema for the integrityenforcers API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=integrityenforcers,scope=Namespaced
type IntegrityEnforcer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IntegrityEnforcerSpec   `json:"spec,omitempty"`
	Status IntegrityEnforcerStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IntegrityEnforcerList contains a list of IntegrityEnforcer
type IntegrityEnforcerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IntegrityEnforcer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IntegrityEnforcer{}, &IntegrityEnforcerList{})
}
