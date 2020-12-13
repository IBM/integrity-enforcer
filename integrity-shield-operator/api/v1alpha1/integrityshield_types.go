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

	rsp "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	iec "github.com/IBM/integrity-enforcer/shield/pkg/shield/config"
	admv1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	policyv1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	ec "github.com/IBM/integrity-enforcer/shield/pkg/apis/shieldconfig/v1alpha1"
	spol "github.com/IBM/integrity-enforcer/shield/pkg/apis/signpolicy/v1alpha1"
)

const (
	DefaultIntegrityShieldCRDName             = "integrityshields.apis.integrityshield.io"
	DefaultShieldConfigCRDName                = "shieldconfigs.apis.integrityshield.io"
	DefaultSignPolicyCRDName                  = "signpolicies.apis.integrityshield.io"
	DefaultResourceSignatureCRDName           = "resourcesignatures.apis.integrityshield.io"
	DefaultResourceSigningProfileCRDName      = "resourcesigningprofiles.apis.integrityshield.io"
	DefaultHelmReleaseMetadataCRDName         = "helmreleasemetadatas.apis.integrityshield.io"
	DefaultSignPolicyCRName                   = "sign-policy"
	DefaultIShieldAdminClusterRoleName        = "ishield-admin-clusterrole"
	DefaultIShieldAdminClusterRoleBindingName = "ishield-admin-clusterrolebinding"
	DefaultIShieldAdminRoleName               = "ishield-admin-role"
	DefaultIShieldAdminRoleBindingName        = "ishield-admin-rolebinding"
	DefaultIShieldCRYamlPath                  = "./resources/default-ishield-cr.yaml"
	DefaultResourceSigningProfileYamlPath     = "./resources/default-rsp.yaml"
	DefaultKeyringFilename                    = "pubring.gpg"
	DefaultIShieldWebhookTimeout              = 10
	SATokenPath                               = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// IntegrityShieldSpec defines the desired state of IntegrityShield
type IntegrityShieldSpec struct {
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

	IgnoreDefaultIShieldCR bool            `json:"ignoreDefaultIShieldCR,omitempty"`
	Security               SecurityConfig  `json:"security,omitempty"`
	KeyRings               []KeyRingConfig `json:"keyRingConfigs,omitempty"`
	Server                 ServerContainer `json:"server,omitempty"`
	Logger                 LoggerContainer `json:"logger,omitempty"`
	RegKeySecret           RegKeySecret    `json:"regKeySecret,omitempty"`

	ShieldConfigCrName      string             `json:"shieldConfigCrName,omitempty"`
	ShieldConfig            *iec.ShieldConfig  `json:"shieldConfig,omitempty"`
	SignPolicy              *common.SignPolicy `json:"signPolicy,omitempty"`
	ResourceSigningProfiles []*ProfileConfig   `json:"resourceSigningProfiles,omitempty"`

	WebhookServerTlsSecretName string     `json:"webhookServerTlsSecretName,omitempty"`
	WebhookServiceName         string     `json:"webhookServiceName,omitempty"`
	WebhookConfigName          string     `json:"webhookConfigName,omitempty"`
	WebhookNamespacedResource  admv1.Rule `json:"webhookNamespacedResource,omitempty"`
	WebhookClusterResource     admv1.Rule `json:"webhookClusterResource,omitempty"`
}

type SecurityConfig struct {
	ServiceAccountName               string                 `json:"serviceAccountName,omitempty"`
	SecurityContextConstraintsName   string                 `json:"securityContextConstraintsName,omitempty"`
	ClusterRole                      string                 `json:"clusterRole,omitempty"`
	ClusterRoleBinding               string                 `json:"clusterRoleBinding,omitempty"`
	PodSecurityPolicyName            string                 `json:"podSecurityPolicyName,omitempty"`
	PodSecurityContext               *v1.PodSecurityContext `json:"securityContext,omitempty"`
	IShieldAdminSubjects             []rbacv1.Subject       `json:"iShieldAdminSubjects,omitempty"`
	AutoIShieldAdminCreationDisabled bool                   `json:"autoIShieldAdminRoleCreationDisabled,omitempty"`
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
	ShieldCmReloadSec      int32                   `json:"shieldCmReloadSec,omitempty"`
	EnforcePolicyReloadSec int32                   `json:"shieldPolicyReloadSec,omitempty"`
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
	*rsp.ResourceSigningProfileSpec `json:",omitempty"`
	Name                            string `json:"name,omitempty"`
}

// IntegrityShieldStatus defines the observed state of IntegrityShield
type IntegrityShieldStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// IntegrityShield is the Schema for the integrityshields API
type IntegrityShield struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IntegrityShieldSpec   `json:"spec,omitempty"`
	Status IntegrityShieldStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// IntegrityShieldList contains a list of IntegrityShield
type IntegrityShieldList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IntegrityShield `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IntegrityShield{}, &IntegrityShieldList{})
}

func (self *IntegrityShield) GetSecurityContextConstraintsName() string {
	return self.Spec.Security.SecurityContextConstraintsName
}

func (self *IntegrityShield) GetIntegrityShieldCRDName() string {
	return DefaultIntegrityShieldCRDName
}

func (self *IntegrityShield) GetShieldConfigCRDName() string {
	return DefaultShieldConfigCRDName
}

func (self *IntegrityShield) GetSignPolicyCRDName() string {
	return DefaultSignPolicyCRDName
}

func (self *IntegrityShield) GetResourceSignatureCRDName() string {
	return DefaultResourceSignatureCRDName
}

func (self *IntegrityShield) GetResourceSigningProfileCRDName() string {
	return DefaultResourceSigningProfileCRDName
}

func (self *IntegrityShield) GetHelmReleaseMetadataCRDName() string {
	return DefaultHelmReleaseMetadataCRDName
}

func (self *IntegrityShield) GetShieldConfigCRName() string {
	return self.Spec.ShieldConfigCrName
}

func (self *IntegrityShield) GetSignPolicyCRName() string {
	return DefaultSignPolicyCRName
}

func (self *IntegrityShield) GetRegKeySecretName() string {
	return self.Spec.RegKeySecret.Name
}

func (self *IntegrityShield) GetWebhookServerTlsSecretName() string {
	return self.Spec.WebhookServerTlsSecretName
}

func (self *IntegrityShield) GetServiceAccountName() string {
	return self.Spec.Security.ServiceAccountName
}

func (self *IntegrityShield) GetClusterRoleName() string {
	return self.Spec.Security.ClusterRole
}

func (self *IntegrityShield) GetClusterRoleBindingName() string {
	return self.Spec.Security.ClusterRoleBinding
}

func (self *IntegrityShield) GetDryRunRoleName() string {
	return self.Spec.Security.ClusterRole + "-sim"
}

func (self *IntegrityShield) GetDryRunRoleBindingName() string {
	return self.Spec.Security.ClusterRoleBinding + "-sim"
}

func (self *IntegrityShield) GetIShieldAdminClusterRoleName() string {
	return DefaultIShieldAdminClusterRoleName
}

func (self *IntegrityShield) GetIShieldAdminClusterRoleBindingName() string {
	return DefaultIShieldAdminClusterRoleBindingName
}

func (self *IntegrityShield) GetIShieldAdminRoleName() string {
	return DefaultIShieldAdminRoleName
}

func (self *IntegrityShield) GetIShieldAdminRoleBindingName() string {
	return DefaultIShieldAdminRoleBindingName
}

func (self *IntegrityShield) GetPodSecurityPolicyName() string {
	return self.Spec.Security.PodSecurityPolicyName
}

func (self *IntegrityShield) GetIShieldServerDeploymentName() string {
	return self.Name
}

func (self *IntegrityShield) GetWebhookServiceName() string {
	return self.Spec.WebhookServiceName
}

func (self *IntegrityShield) GetWebhookConfigName() string {
	return self.Spec.WebhookConfigName
}

func (self *IntegrityShield) GetIShieldResourceList(scheme *runtime.Scheme) ([]*common.ResourceRef, []*common.ResourceRef) {

	if scheme == nil {
		return []*common.ResourceRef{}, []*common.ResourceRef{}
	}

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
	_crdType := getTypeFromObj(&extv1.CustomResourceDefinition{}, scheme)
	_ecType := getTypeFromObj(&ec.ShieldConfig{}, scheme)
	_spolType := getTypeFromObj(&spol.SignPolicy{}, scheme)
	_rspType := getTypeFromObj(&rsp.ResourceSigningProfile{}, scheme)
	_secretType := getTypeFromObj(&v1.Secret{}, scheme)
	_saType := getTypeFromObj(&v1.ServiceAccount{}, scheme)
	_clusterroleType := getTypeFromObj(&rbacv1.ClusterRole{}, scheme)
	_clusterrolebindingType := getTypeFromObj(&rbacv1.ClusterRoleBinding{}, scheme)
	_roleType := getTypeFromObj(&rbacv1.Role{}, scheme)
	_rolebindingType := getTypeFromObj(&rbacv1.RoleBinding{}, scheme)
	_pspType := getTypeFromObj(&policyv1.PodSecurityPolicy{}, scheme)

	iShieldOperatorResourceList := []*common.ResourceRef{
		{
			Kind: _crdType.Kind,
			Name: self.GetIntegrityShieldCRDName(),
		},
		{
			Kind:      _deployType.Kind,
			Name:      opDeployName,
			Namespace: opPodNamespace,
		},
		{
			Kind:      self.Kind,
			Name:      self.Name,
			Namespace: self.Namespace,
		},
	}

	iShieldServerResourceList := []*common.ResourceRef{
		{
			Kind: _crdType.Kind,
			Name: self.GetShieldConfigCRDName(),
		},
		{
			Kind: _crdType.Kind,
			Name: self.GetSignPolicyCRDName(),
		},
		{
			Kind: _crdType.Kind,
			Name: self.GetResourceSignatureCRDName(),
		},
		{
			Kind: _crdType.Kind,
			Name: self.GetResourceSigningProfileCRDName(),
		},
		{
			Kind: _crdType.Kind,
			Name: self.GetHelmReleaseMetadataCRDName(),
		},
		{
			Kind:      _ecType.Kind,
			Name:      self.GetShieldConfigCRName(),
			Namespace: self.Namespace,
		},
		{
			Kind:      _spolType.Kind,
			Name:      self.GetSignPolicyCRName(),
			Namespace: self.Namespace,
		},
		{
			Kind:      _secretType.Kind,
			Name:      self.GetRegKeySecretName(),
			Namespace: self.Namespace,
		},
		{
			Kind:      _secretType.Kind,
			Name:      self.GetWebhookServerTlsSecretName(),
			Namespace: self.Namespace,
		},
		{
			Kind:      _saType.Kind,
			Name:      self.GetServiceAccountName(),
			Namespace: self.Namespace,
		},
		{
			Kind: _clusterroleType.Kind,
			Name: self.GetClusterRoleName(),
		},
		{
			Kind: _clusterrolebindingType.Kind,
			Name: self.GetClusterRoleBindingName(),
		},
		{
			Kind:      _roleType.Kind,
			Name:      self.GetDryRunRoleName(),
			Namespace: self.Namespace,
		},
		{
			Kind:      _rolebindingType.Kind,
			Name:      self.GetDryRunRoleBindingName(),
			Namespace: self.Namespace,
		},
		{
			Kind: _clusterroleType.Kind,
			Name: self.GetIShieldAdminClusterRoleName(),
		},
		{
			Kind: _clusterrolebindingType.Kind,
			Name: self.GetIShieldAdminClusterRoleBindingName(),
		},
		{
			Kind:      _roleType.Kind,
			Name:      self.GetIShieldAdminRoleName(),
			Namespace: self.Namespace,
		},
		{
			Kind:      _rolebindingType.Kind,
			Name:      self.GetIShieldAdminRoleBindingName(),
			Namespace: self.Namespace,
		},
		{
			Kind:      _pspType.Kind,
			Name:      self.GetPodSecurityPolicyName(),
			Namespace: self.Namespace,
		},
		{
			Kind:      _deployType.Kind,
			Name:      self.GetIShieldServerDeploymentName(),
			Namespace: self.Namespace,
		},
	}
	if len(self.Spec.ResourceSigningProfiles) > 0 {
		for _, prof := range self.Spec.ResourceSigningProfiles {
			tmpRef := &common.ResourceRef{
				Kind:      _rspType.Kind,
				Name:      prof.Name,
				Namespace: self.Namespace,
			}
			iShieldServerResourceList = append(iShieldServerResourceList, tmpRef)
		}
	}

	return iShieldOperatorResourceList, iShieldServerResourceList
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
