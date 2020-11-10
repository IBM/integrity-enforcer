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
	"os"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	intstr "k8s.io/apimachinery/pkg/util/intstr"

	rsp "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourcesigningprofile/v1alpha1"
	common "github.com/IBM/integrity-enforcer/enforcer/pkg/common/common"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/common/policy"
	iec "github.com/IBM/integrity-enforcer/enforcer/pkg/enforcer/config"
	scc "github.com/openshift/api/security/v1"
	admv1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	policyv1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	ec "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/enforcerconfig/v1alpha1"
	spol "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/signpolicy/v1alpha1"
)

const (
	DefaultEnforcerConfigCRDName         = "enforcerconfigs.apis.integrityenforcer.io"
	DefaultSignPolicyCRDName             = "signpolicies.apis.integrityenforcer.io"
	DefaultResourceSignatureCRDName      = "resourcesignatures.apis.integrityenforcer.io"
	DefaultResourceSigningProfileCRDName = "resourcesigningprofiles.apis.integrityenforcer.io"
	DefaultHelmReleaseMetadataCRDName    = "helmreleasemetadatas.apis.integrityenforcer.io"
	DefaultSignPolicyCRName              = "sign-policy"
	DefaultIEAdminClusterRoleName        = "ie-admin-clusterrole"
	DefaultIEAdminClusterRoleBindingName = "ie-admin-clusterrolebinding"
	DefaultIEAdminRoleName               = "ie-admin-role"
	DefaultIEAdminRoleBindingName        = "ie-admin-rolebinding"
	DefaultRuleTableLockCMName           = "ie-rule-table-lock"
	DefaultIgnoreTableLockCMName         = "ie-ignore-table-lock"
	DefaultForceCheckTableLockCMName     = "ie-force-check-table-lock"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// IntegrityEnforcerSpec defines the desired state of IntegrityEnforcer
type IntegrityEnforcerSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	MaxSurge         *intstr.IntOrString       `json:"maxSurge,omitempty"`
	MaxUnavailable   *intstr.IntOrString       `json:"maxUnavailable,omitempty"`
	ReplicaCount     *int32                    `json:"replicaCount,omitempty"`
	MetaLabels       map[string]string         `json:"labels,omitempty"`
	SelectorLabels   map[string]string         `json:"selector,omitempty"`
	NodeSelector     map[string]string         `json:"nodeSelector,omitempty"`
	Affinity         *v1.Affinity              `json:"affinity,omitempty"`
	Tolerations      []v1.Toleration           `json:"tolerations,omitempty"`
	ImagePullSecrets []v1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	IgnoreDefaultIECR bool            `json:"ignoreDefaultIECR,omitempty"`
	LabeledNamespaces []string        `json:"labeledNamespaces,omitempty"`
	Security          SecurityConfig  `json:"security,omitempty"`
	KeyRings          []KeyRingConfig `json:"keyRingConfigs,omitempty"`
	Server            ServerContainer `json:"server,omitempty"`
	Logger            LoggerContainer `json:"logger,omitempty"`
	RegKeySecret      RegKeySecret    `json:"regKeySecret,omitempty"`
	GlobalConfig      GlobalConfig    `json:"globalConfig,omitempty"`

	EnforcerConfigCrName    string              `json:"enforcerConfigCrName,omitempty"`
	EnforcerConfig          *iec.EnforcerConfig `json:"enforcerConfig,omitempty"`
	SignPolicy              *policy.SignPolicy  `json:"signPolicy,omitempty"`
	ResourceSigningProfiles []*ProfileConfig    `json:"resourceSigningProfiles,omitempty"`

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
	IEAdminSubjects                []rbacv1.Subject       `json:"ieAdminSubjects,omitempty"`
	AutoIEAdminCreationDisabled    bool                   `json:"autoIEAdminRoleCreationDisabled,omitempty"`
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

type ProfileConfig struct {
	*rsp.ResourceSigningProfileSpec `json:"resourceSigningProfileSpec,omitempty"`
	Name string `json:"name,omitempty"`
}

// IntegrityEnforcerStatus defines the observed state of IntegrityEnforcer
type IntegrityEnforcerStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// IntegrityEnforcer is the Schema for the integrityenforcers API
type IntegrityEnforcer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IntegrityEnforcerSpec   `json:"spec,omitempty"`
	Status IntegrityEnforcerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// IntegrityEnforcerList contains a list of IntegrityEnforcer
type IntegrityEnforcerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IntegrityEnforcer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IntegrityEnforcer{}, &IntegrityEnforcerList{})
}

func (self *IntegrityEnforcer) GetSecurityContextConstraintsName() string {
	return self.Spec.Security.SecurityContextConstraintsName
}

func (self *IntegrityEnforcer) GetEnforcerConfigCRDName() string {
	return DefaultEnforcerConfigCRDName
}

func (self *IntegrityEnforcer) GetSignPolicyCRDName() string {
	return DefaultSignPolicyCRDName
}

func (self *IntegrityEnforcer) GetResourceSignatureCRDName() string {
	return DefaultResourceSignatureCRDName
}

func (self *IntegrityEnforcer) GetResourceSigningProfileCRDName() string {
	return DefaultResourceSigningProfileCRDName
}

func (self *IntegrityEnforcer) GetHelmReleaseMetadataCRDName() string {
	return DefaultHelmReleaseMetadataCRDName
}

func (self *IntegrityEnforcer) GetEnforcerConfigCRName() string {
	return self.Spec.EnforcerConfigCrName
}

func (self *IntegrityEnforcer) GetSignPolicyCRName() string {
	return DefaultSignPolicyCRName
}

func (self *IntegrityEnforcer) GetRegKeySecretName() string {
	return self.Spec.RegKeySecret.Name
}

func (self *IntegrityEnforcer) GetWebhookServerTlsSecretName() string {
	return self.Spec.WebhookServerTlsSecretName
}

func (self *IntegrityEnforcer) GetServiceAccountName() string {
	return self.Spec.Security.ServiceAccountName
}

func (self *IntegrityEnforcer) GetClusterRoleName() string {
	return self.Spec.Security.ClusterRole
}

func (self *IntegrityEnforcer) GetClusterRoleBindingName() string {
	return self.Spec.Security.ClusterRoleBinding
}

func (self *IntegrityEnforcer) GetDryRunRoleName() string {
	return self.Spec.Security.ClusterRole + "-sim"
}

func (self *IntegrityEnforcer) GetDryRunRoleBindingName() string {
	return self.Spec.Security.ClusterRoleBinding + "-sim"
}

func (self *IntegrityEnforcer) GetIEAdminClusterRoleName() string {
	return DefaultIEAdminClusterRoleName
}

func (self *IntegrityEnforcer) GetIEAdminClusterRoleBindingName() string {
	return DefaultIEAdminClusterRoleBindingName
}

func (self *IntegrityEnforcer) GetIEAdminRoleName() string {
	return DefaultIEAdminRoleName
}

func (self *IntegrityEnforcer) GetIEAdminRoleBindingName() string {
	return DefaultIEAdminRoleBindingName
}

func (self *IntegrityEnforcer) GetPodSecurityPolicyName() string {
	return self.Spec.Security.PodSecurityPolicyName
}

func (self *IntegrityEnforcer) GetRuleTableLockCMName() string {
	return DefaultRuleTableLockCMName
}

func (self *IntegrityEnforcer) GetIgnoreTableLockCMName() string {
	return DefaultIgnoreTableLockCMName
}

func (self *IntegrityEnforcer) GetForceCheckTableLockCMName() string {
	return DefaultForceCheckTableLockCMName
}

func (self *IntegrityEnforcer) GetIEServerDeploymentName() string {
	return self.Name
}

func (self *IntegrityEnforcer) GetWebhookServiceName() string {
	return self.Spec.WebhookServiceName
}

func (self *IntegrityEnforcer) GetWebhookConfigName() string {
	return self.Spec.WebhookConfigName
}

func (self *IntegrityEnforcer) GetIEResourceList(scheme *runtime.Scheme) []*common.ResourceRef {
	opPodName := os.Getenv("POD_NAME")
	opPodNamespace := os.Getenv("POD_NAMESPACE")
	tmpParts := strings.Split(opPodName, "-")

	opDeployName := ""
	if len(tmpParts) > 2 {
		opDeployName = strings.Join(tmpParts[:len(tmpParts)-2], "-")
	}

	// (&Object{}).TypeMeta.APIVersion is not correct but empty string "", unless it is resolved by scheme.
	// getTypeFromObj() resolves it.
	_deployType := getTypeFromObj(&appsv1.Deployment{}, scheme)
	_sccType := getTypeFromObj(&scc.SecurityContextConstraints{}, scheme)
	_crdType := getTypeFromObj(&extv1.CustomResourceDefinition{}, scheme)
	_ecType := getTypeFromObj(&ec.EnforcerConfig{}, scheme)
	_spolType := getTypeFromObj(&spol.SignPolicy{}, scheme)
	_rspType := getTypeFromObj(&rsp.ResourceSigningProfile{}, scheme)
	_secretType := getTypeFromObj(&v1.Secret{}, scheme)
	_saType := getTypeFromObj(&v1.ServiceAccount{}, scheme)
	_clusterroleType := getTypeFromObj(&rbacv1.ClusterRole{}, scheme)
	_clusterrolebindingType := getTypeFromObj(&rbacv1.ClusterRoleBinding{}, scheme)
	_roleType := getTypeFromObj(&rbacv1.Role{}, scheme)
	_rolebindingType := getTypeFromObj(&rbacv1.RoleBinding{}, scheme)
	_pspType := getTypeFromObj(&policyv1.PodSecurityPolicy{}, scheme)
	_cmType := getTypeFromObj(&v1.ConfigMap{}, scheme)

	ieResourceList := []*common.ResourceRef{
		{
			ApiVersion: _deployType.APIVersion,
			Kind:       _deployType.Kind,
			Name:       opDeployName,
			Namespace:  opPodNamespace,
		},
		{
			ApiVersion: self.APIVersion,
			Kind:       self.Kind,
			Name:       self.Name,
			Namespace:  self.Namespace,
		},
		{
			ApiVersion: _sccType.APIVersion,
			Kind:       _sccType.Kind,
			Name:       self.GetSecurityContextConstraintsName(),
		},
		{
			ApiVersion: _crdType.APIVersion,
			Kind:       _crdType.Kind,
			Name:       self.GetEnforcerConfigCRDName(),
		},
		{
			ApiVersion: _crdType.APIVersion,
			Kind:       _crdType.Kind,
			Name:       self.GetSignPolicyCRDName(),
		},
		{
			ApiVersion: _crdType.APIVersion,
			Kind:       _crdType.Kind,
			Name:       self.GetResourceSignatureCRDName(),
		},
		{
			ApiVersion: _crdType.APIVersion,
			Kind:       _crdType.Kind,
			Name:       self.GetResourceSigningProfileCRDName(),
		},
		{
			ApiVersion: _crdType.APIVersion,
			Kind:       _crdType.Kind,
			Name:       self.GetHelmReleaseMetadataCRDName(),
		},
		{
			ApiVersion: _ecType.APIVersion,
			Kind:       _ecType.Kind,
			Name:       self.GetEnforcerConfigCRName(),
			Namespace:  self.Namespace,
		},
		{
			ApiVersion: _spolType.APIVersion,
			Kind:       _spolType.Kind,
			Name:       self.GetSignPolicyCRName(),
			Namespace:  self.Namespace,
		},
		{
			ApiVersion: _secretType.APIVersion,
			Kind:       _secretType.Kind,
			Name:       self.GetRegKeySecretName(),
			Namespace:  self.Namespace,
		},
		{
			ApiVersion: _secretType.APIVersion,
			Kind:       _secretType.Kind,
			Name:       self.GetWebhookServerTlsSecretName(),
			Namespace:  self.Namespace,
		},
		{
			ApiVersion: _saType.APIVersion,
			Kind:       _saType.Kind,
			Name:       self.GetServiceAccountName(),
			Namespace:  self.Namespace,
		},
		{
			ApiVersion: _clusterroleType.APIVersion,
			Kind:       _clusterroleType.Kind,
			Name:       self.GetClusterRoleName(),
		},
		{
			ApiVersion: _clusterrolebindingType.APIVersion,
			Kind:       _clusterrolebindingType.Kind,
			Name:       self.GetClusterRoleBindingName(),
		},
		{
			ApiVersion: _roleType.APIVersion,
			Kind:       _roleType.Kind,
			Name:       self.GetDryRunRoleName(),
			Namespace:  self.Namespace,
		},
		{
			ApiVersion: _rolebindingType.APIVersion,
			Kind:       _rolebindingType.Kind,
			Name:       self.GetDryRunRoleBindingName(),
			Namespace:  self.Namespace,
		},
		{
			ApiVersion: _clusterroleType.APIVersion,
			Kind:       _clusterroleType.Kind,
			Name:       self.GetIEAdminClusterRoleName(),
		},
		{
			ApiVersion: _clusterrolebindingType.APIVersion,
			Kind:       _clusterrolebindingType.Kind,
			Name:       self.GetIEAdminClusterRoleBindingName(),
		},
		{
			ApiVersion: _roleType.APIVersion,
			Kind:       _roleType.Kind,
			Name:       self.GetIEAdminRoleName(),
			Namespace:  self.Namespace,
		},
		{
			ApiVersion: _rolebindingType.APIVersion,
			Kind:       _rolebindingType.Kind,
			Name:       self.GetIEAdminRoleBindingName(),
			Namespace:  self.Namespace,
		},
		{
			ApiVersion: _pspType.APIVersion,
			Kind:       _pspType.Kind,
			Name:       self.GetPodSecurityPolicyName(),
			Namespace:  self.Namespace,
		},
		{
			ApiVersion: _cmType.APIVersion,
			Kind:       _cmType.Kind,
			Name:       self.GetRuleTableLockCMName(),
			Namespace:  self.Namespace,
		},
		{
			ApiVersion: _cmType.APIVersion,
			Kind:       _cmType.Kind,
			Name:       self.GetIgnoreTableLockCMName(),
			Namespace:  self.Namespace,
		},
		{
			ApiVersion: _cmType.APIVersion,
			Kind:       _cmType.Kind,
			Name:       self.GetForceCheckTableLockCMName(),
			Namespace:  self.Namespace,
		},
		{
			ApiVersion: _deployType.APIVersion,
			Kind:       _deployType.Kind,
			Name:       self.GetIEServerDeploymentName(),
			Namespace:  self.Namespace,
		},
	}
	if len(self.Spec.ResourceSigningProfiles) > 0 {
		for _, prof := range self.Spec.ResourceSigningProfiles {
			tmpRef := &common.ResourceRef{
				ApiVersion: _rspType.APIVersion,
				Kind:       _rspType.Kind,
				Name:       prof.Name,
				Namespace:  self.Namespace,
			}
			ieResourceList = append(ieResourceList, tmpRef)
		}
	}

	return ieResourceList
}

func getTypeFromObj(obj runtime.Object, scheme *runtime.Scheme) metav1.TypeMeta {
	apiVersion := ""
	kind := ""
	gvks, _, err := scheme.ObjectKinds(obj)
	if err == nil && len(gvks) > 0 {
		apiVersion = gvks[0].GroupVersion().String()
		kind = gvks[0].Kind
	}
	return metav1.TypeMeta{APIVersion: apiVersion, Kind: kind}
}
