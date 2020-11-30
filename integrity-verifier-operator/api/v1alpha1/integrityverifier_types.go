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

	rsp "github.com/IBM/integrity-enforcer/verifier/pkg/apis/resourcesigningprofile/v1alpha1"
	common "github.com/IBM/integrity-enforcer/verifier/pkg/common/common"
	policy "github.com/IBM/integrity-enforcer/verifier/pkg/common/policy"
	iec "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/config"
	admv1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	policyv1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	spol "github.com/IBM/integrity-enforcer/verifier/pkg/apis/signpolicy/v1alpha1"
	ec "github.com/IBM/integrity-enforcer/verifier/pkg/apis/verifierconfig/v1alpha1"
)

const (
	DefaultIntegrityVerifierCRDName       = "integrityverifiers.apis.integrityverifier.io"
	DefaultVerifierConfigCRDName          = "verifierconfigs.apis.integrityverifier.io"
	DefaultSignPolicyCRDName              = "signpolicies.apis.integrityverifier.io"
	DefaultResourceSignatureCRDName       = "resourcesignatures.apis.integrityverifier.io"
	DefaultResourceSigningProfileCRDName  = "resourcesigningprofiles.apis.integrityverifier.io"
	DefaultHelmReleaseMetadataCRDName     = "helmreleasemetadatas.apis.integrityverifier.io"
	DefaultSignPolicyCRName               = "sign-policy"
	DefaultIVAdminClusterRoleName         = "iv-admin-clusterrole"
	DefaultIVAdminClusterRoleBindingName  = "iv-admin-clusterrolebinding"
	DefaultIVAdminRoleName                = "iv-admin-role"
	DefaultIVAdminRoleBindingName         = "iv-admin-rolebinding"
	DefaultRuleTableLockCMName            = "iv-rule-table-lock"
	DefaultIgnoreTableLockCMName          = "iv-ignore-table-lock"
	DefaultForceCheckTableLockCMName      = "iv-force-check-table-lock"
	DefaultIVCRYamlPath                   = "./resources/default-iv-cr.yaml"
	DefaultResourceSigningProfileYamlPath = "./resources/default-rsp.yaml"
	DefaultKeyringFilename                = "pubring.gpg"
	DefaultIVWebhookTimeout               = 10
	SATokenPath                           = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// IntegrityVerifierSpec defines the desired state of IntegrityVerifier
type IntegrityVerifierSpec struct {
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

	IgnoreDefaultIVCR bool            `json:"ignoreDefaultIVCR,omitempty"`
	Security          SecurityConfig  `json:"security,omitempty"`
	KeyRings          []KeyRingConfig `json:"keyRingConfigs,omitempty"`
	Server            ServerContainer `json:"server,omitempty"`
	Logger            LoggerContainer `json:"logger,omitempty"`
	RegKeySecret      RegKeySecret    `json:"regKeySecret,omitempty"`

	VerifierConfigCrName    string              `json:"verifierConfigCrName,omitempty"`
	VerifierConfig          *iec.VerifierConfig `json:"verifierConfig,omitempty"`
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
	IVAdminSubjects                []rbacv1.Subject       `json:"ivAdminSubjects,omitempty"`
	AutoIVAdminCreationDisabled    bool                   `json:"autoIVAdminRoleCreationDisabled,omitempty"`
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
	VerifierCmReloadSec    int32                   `json:"verifierCmReloadSec,omitempty"`
	EnforcePolicyReloadSec int32                   `json:"verifierPolicyReloadSec,omitempty"`
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

// IntegrityVerifierStatus defines the observed state of IntegrityVerifier
type IntegrityVerifierStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// IntegrityVerifier is the Schema for the integrityverifiers API
type IntegrityVerifier struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IntegrityVerifierSpec   `json:"spec,omitempty"`
	Status IntegrityVerifierStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// IntegrityVerifierList contains a list of IntegrityVerifier
type IntegrityVerifierList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IntegrityVerifier `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IntegrityVerifier{}, &IntegrityVerifierList{})
}

func (self *IntegrityVerifier) GetSecurityContextConstraintsName() string {
	return self.Spec.Security.SecurityContextConstraintsName
}

func (self *IntegrityVerifier) GetIntegrityVerifierCRDName() string {
	return DefaultIntegrityVerifierCRDName
}

func (self *IntegrityVerifier) GetVerifierConfigCRDName() string {
	return DefaultVerifierConfigCRDName
}

func (self *IntegrityVerifier) GetSignPolicyCRDName() string {
	return DefaultSignPolicyCRDName
}

func (self *IntegrityVerifier) GetResourceSignatureCRDName() string {
	return DefaultResourceSignatureCRDName
}

func (self *IntegrityVerifier) GetResourceSigningProfileCRDName() string {
	return DefaultResourceSigningProfileCRDName
}

func (self *IntegrityVerifier) GetHelmReleaseMetadataCRDName() string {
	return DefaultHelmReleaseMetadataCRDName
}

func (self *IntegrityVerifier) GetVerifierConfigCRName() string {
	return self.Spec.VerifierConfigCrName
}

func (self *IntegrityVerifier) GetSignPolicyCRName() string {
	return DefaultSignPolicyCRName
}

func (self *IntegrityVerifier) GetRegKeySecretName() string {
	return self.Spec.RegKeySecret.Name
}

func (self *IntegrityVerifier) GetWebhookServerTlsSecretName() string {
	return self.Spec.WebhookServerTlsSecretName
}

func (self *IntegrityVerifier) GetServiceAccountName() string {
	return self.Spec.Security.ServiceAccountName
}

func (self *IntegrityVerifier) GetClusterRoleName() string {
	return self.Spec.Security.ClusterRole
}

func (self *IntegrityVerifier) GetClusterRoleBindingName() string {
	return self.Spec.Security.ClusterRoleBinding
}

func (self *IntegrityVerifier) GetDryRunRoleName() string {
	return self.Spec.Security.ClusterRole + "-sim"
}

func (self *IntegrityVerifier) GetDryRunRoleBindingName() string {
	return self.Spec.Security.ClusterRoleBinding + "-sim"
}

func (self *IntegrityVerifier) GetIVAdminClusterRoleName() string {
	return DefaultIVAdminClusterRoleName
}

func (self *IntegrityVerifier) GetIVAdminClusterRoleBindingName() string {
	return DefaultIVAdminClusterRoleBindingName
}

func (self *IntegrityVerifier) GetIVAdminRoleName() string {
	return DefaultIVAdminRoleName
}

func (self *IntegrityVerifier) GetIVAdminRoleBindingName() string {
	return DefaultIVAdminRoleBindingName
}

func (self *IntegrityVerifier) GetPodSecurityPolicyName() string {
	return self.Spec.Security.PodSecurityPolicyName
}

func (self *IntegrityVerifier) GetRuleTableLockCMName() string {
	return DefaultRuleTableLockCMName
}

func (self *IntegrityVerifier) GetIgnoreTableLockCMName() string {
	return DefaultIgnoreTableLockCMName
}

func (self *IntegrityVerifier) GetForceCheckTableLockCMName() string {
	return DefaultForceCheckTableLockCMName
}

func (self *IntegrityVerifier) GetIVServerDeploymentName() string {
	return self.Name
}

func (self *IntegrityVerifier) GetWebhookServiceName() string {
	return self.Spec.WebhookServiceName
}

func (self *IntegrityVerifier) GetWebhookConfigName() string {
	return self.Spec.WebhookConfigName
}

func (self *IntegrityVerifier) GetIVResourceList(scheme *runtime.Scheme) []*common.ResourceRef {
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
	_ecType := getTypeFromObj(&ec.VerifierConfig{}, scheme)
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
			Kind:      _deployType.Kind,
			Name:      opDeployName,
			Namespace: opPodNamespace,
		},
		{
			Kind:      self.Kind,
			Name:      self.Name,
			Namespace: self.Namespace,
		},
		{
			Kind: _crdType.Kind,
			Name: self.GetIntegrityVerifierCRDName(),
		},
		{
			Kind: _crdType.Kind,
			Name: self.GetVerifierConfigCRDName(),
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
			Name:      self.GetVerifierConfigCRName(),
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
			Name: self.GetIVAdminClusterRoleName(),
		},
		{
			Kind: _clusterrolebindingType.Kind,
			Name: self.GetIVAdminClusterRoleBindingName(),
		},
		{
			Kind:      _roleType.Kind,
			Name:      self.GetIVAdminRoleName(),
			Namespace: self.Namespace,
		},
		{
			Kind:      _rolebindingType.Kind,
			Name:      self.GetIVAdminRoleBindingName(),
			Namespace: self.Namespace,
		},
		{
			Kind:      _pspType.Kind,
			Name:      self.GetPodSecurityPolicyName(),
			Namespace: self.Namespace,
		},
		{
			Kind:      _cmType.Kind,
			Name:      self.GetRuleTableLockCMName(),
			Namespace: self.Namespace,
		},
		{
			Kind:      _cmType.Kind,
			Name:      self.GetIgnoreTableLockCMName(),
			Namespace: self.Namespace,
		},
		{
			Kind:      _cmType.Kind,
			Name:      self.GetForceCheckTableLockCMName(),
			Namespace: self.Namespace,
		},
		{
			Kind:      _deployType.Kind,
			Name:      self.GetIVServerDeploymentName(),
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
