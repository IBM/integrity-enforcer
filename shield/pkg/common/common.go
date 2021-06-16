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

package common

import (
	"fmt"
	"math/big"
	"strconv"

	"github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
	"github.com/jinzhu/copier"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	IShieldCustomResourceAPIVersion = "apis.integrityshield.io/v1alpha1"
	IShieldCustomResourceKind       = "IntegrityShield"

	SignatureCustomResourceAPIVersion = "apis.integrityshield.io/v1alpha1"
	SignatureCustomResourceKind       = "ResourceSignature"

	ShieldConfigCustomResourceAPIVersion = "apis.integrityshield.io/v1alpha1"
	ShieldConfigCustomResourceKind       = "ShieldConfig"

	SignerConfigCustomResourceAPIVersion = "apis.integrityshield.io/v1alpha1"
	SignerConfigCustomResourceKind       = "SignerConfig"

	ProfileCustomResourceAPIVersion = "apis.integrityshield.io/v1alpha1"
	ProfileCustomResourceKind       = "ResourceSigningProfile"

	HelmReleaseMetadataCustomResourceAPIVersion = "apis.integrityshield.io/v1alpha1"
	HelmReleaseMetadataCustomResourceKind       = "HelmReleasemetadata"
)

const (
	ResourceIntegrityLabelKey          = "integrityshield.io/resourceIntegrity"
	SignedByAnnotationKey              = "integrityshield.io/signedBy"
	LastVerifiedTimestampAnnotationKey = "integrityshield.io/lastVerifiedTimestamp"
	ResourceSignatureUIDAnnotationKey  = "integrityshield.io/resourceSignatureUID"

	SignatureAnnotationKey        = "cosign.sigstore.dev/signature"
	MessageAnnotationKey          = "cosign.sigstore.dev/message"
	CertificateAnnotationKey      = "cosign.sigstore.dev/certificate"
	BundleAnnotationKey           = "cosign.sigstore.dev/bundle"
	SignatureTypeAnnotationKey    = "cosign.sigstore.dev/signatureType"
	MessageScopeAnnotationKey     = "cosign.sigstore.dev/messageScope"
	MutableAttrsAnnotationKey     = "cosign.sigstore.dev/mutableAttrs"
	ManifestImageRefAnnotationKey = "cosign.sigstore.dev/imageRef"

	ResSigLabelApiVer = "integrityshield.io/sigobject-apiversion"
	ResSigLabelKind   = "integrityshield.io/sigobject-kind"
	ResSigLabelTime   = "integrityshield.io/sigtime"

	LabelValueVerified   = "verified"
	LabelValueUnverified = "unverified"
)

const (
	EventTypeAnnotationKey   = "integrityshield.io/eventType"
	EventResultAnnotationKey = "integrityshield.io/eventResult"

	EventTypeValueReconcileReport = "reconcile-report"
	EventTypeValueVerifyResult    = "verify-result"
	EventResultValueAllow         = "allow"
	EventResultValueDeny          = "deny"
)

type SignatureType string

const (
	SignatureTypeDefault  = ""
	SignatureTypePGP      = "pgp"
	SignatureTypeX509     = "x509"
	SignatureTypeSigStore = "sigstore"
)

type DecisionType string

const (
	DecisionUndetermined = "undetermined"
	DecisionAllow        = "allow"
	DecisionDeny         = "deny"
	DecisionError        = "error"
)

const (
	DefaultSigStoreRootCertSecretName = "ishield-sigstore-root-cert"
)

/**********************************************

                NamespaceSelector

***********************************************/

type NamespaceSelector struct {
	LabelSelector *metav1.LabelSelector `json:"labelSelector,omitempty"`
	Include       []string              `json:"include,omitempty"`
	Exclude       []string              `json:"exclude,omitempty"`
}

func (self *NamespaceSelector) MatchNamespace(namespace *v1.Namespace) bool {
	labelMatched := false
	if self.LabelSelector != nil {
		if ok, _ := kubeutil.MatchLabels(namespace, self.LabelSelector); ok {
			labelMatched = true
		}
	}
	if len(self.Include) == 0 && len(self.Exclude) == 0 {
		return labelMatched
	} else {
		return self.MatchNamespaceName(namespace.GetName())
	}
}

func (self *NamespaceSelector) MatchNamespaceName(nsName string) bool {
	included := MatchWithPatternArray(nsName, self.Include)
	excluded := MatchWithPatternArray(nsName, self.Exclude)
	return included && !excluded
}

func (s1 *NamespaceSelector) Merge(s2 *NamespaceSelector) *NamespaceSelector {
	if s2 == nil {
		return s1
	}
	newSelector := &NamespaceSelector{}
	newSelector.Include = GetUnionOfArrays(s1.Include, s2.Include)
	newSelector.Exclude = GetUnionOfArrays(s1.Exclude, s2.Exclude)
	return newSelector
}

func (s1 *NamespaceSelector) DeepCopyInto(s2 *NamespaceSelector) {
	copier.Copy(&s2, &s1)
}

func (s1 *NamespaceSelector) DeepCopy() *NamespaceSelector {
	s2 := &NamespaceSelector{}
	s1.DeepCopyInto(s2)
	return s2
}

/**********************************************

                ResourceRef

***********************************************/

type ResourceRef struct {
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	Kind       string `json:"kind"`
	ApiVersion string `json:"apiVersion"`
}

func (self *ResourceRef) Equals(ref *ResourceRef) bool {
	return (ref != nil &&
		self.Name == ref.Name &&
		self.Namespace == ref.Namespace &&
		self.Kind == ref.Kind &&
		self.ApiVersion == ref.ApiVersion)
}

func (self *ResourceRef) EqualsWithoutVersionCheck(ref *ResourceRef) bool {
	return (ref != nil &&
		self.Name == ref.Name &&
		self.Namespace == ref.Namespace &&
		self.Kind == ref.Kind)
}

/**********************************************

                CheckError

***********************************************/

type CheckError struct {
	Msg    string `json:"msg"`
	Reason string `json:"reason"`
	Error  error  `json:"error"`
}

func (self *CheckError) MakeMessage() string {
	if self.Error != nil {
		if self.Reason != "" {
			return self.Reason
		} else {
			return self.Error.Error()
		}
	} else if self.Reason != "" {
		return self.Reason
	} else {
		return self.Msg
	}
}

/**********************************************

                ResourceLabel

***********************************************/

type ResourceLabel struct {
	values map[string]string
}

func NewResourceLabel(values map[string]string) *ResourceLabel {
	return &ResourceLabel{
		values: values,
	}
}

func (self *ResourceLabel) IntegrityVerified() bool {
	return self.getString(ResourceIntegrityLabelKey) == LabelValueVerified
}

func (self *ResourceLabel) getString(key string) string {
	if s, ok := self.values[key]; ok {
		return s
	} else {
		return ""
	}
}

func (self *ResourceLabel) getBool(key string, defaultValue bool) bool {
	if s, ok := self.values[key]; ok {
		if b, err := strconv.ParseBool(s); err != nil {
			return defaultValue
		} else {
			return b
		}
	}
	return defaultValue
}

func (self *ResourceLabel) isDefined(key string) bool {
	_, ok := self.values[key]
	return ok
}

/**********************************************

                ResourceAnnotation

***********************************************/

type ResourceAnnotation struct {
	values map[string]string
}

type SignatureAnnotation struct {
	SignatureType    string
	Signature        string
	Certificate      string
	Message          string
	MessageScope     string
	MutableAttrs     string
	SigStoreBundle   string
	ManifestImageRef string
}

func (self *ResourceAnnotation) SignatureAnnotations() *SignatureAnnotation {
	return &SignatureAnnotation{
		Signature:        self.getString(SignatureAnnotationKey),
		SignatureType:    self.getString(SignatureTypeAnnotationKey),
		Certificate:      self.getString(CertificateAnnotationKey),
		Message:          self.getString(MessageAnnotationKey),
		MessageScope:     self.getString(MessageScopeAnnotationKey),
		MutableAttrs:     self.getString(MutableAttrsAnnotationKey),
		SigStoreBundle:   self.getString(BundleAnnotationKey),
		ManifestImageRef: self.getString(ManifestImageRefAnnotationKey),
	}
}

func (self *ResourceAnnotation) getString(key string) string {
	if s, ok := self.values[key]; ok {
		return s
	} else {
		return ""
	}
}

func (self *ResourceAnnotation) getBool(key string, defaultValue bool) bool {
	if s, ok := self.values[key]; ok {
		if b, err := strconv.ParseBool(s); err != nil {
			return defaultValue
		} else {
			return b
		}
	}
	return defaultValue
}

func (self *ResourceAnnotation) isDefined(key string) bool {
	_, ok := self.values[key]
	return ok
}

/**********************************************

                Result

***********************************************/

type SignatureEvalResult struct {
	Signer               *SignerInfo `json:"signer"`
	SignerName           string      `json:"signerName"`
	Checked              bool        `json:"checked"`
	Allow                bool        `json:"allow"`
	MatchedSignerConfig  string      `json:"matchedSignerConfig"`
	ResourceSignatureUID string      `json:"resourceSignatureUID"`
	Error                *CheckError `json:"error"`
}

func (self *SignatureEvalResult) GetSignerName() string {
	if self.SignerName != "" {
		return self.SignerName
	}
	if self.Signer != nil {
		return self.Signer.GetName()
	}
	return ""
}

type SignerInfo struct {
	Email              string
	Name               string
	Comment            string
	Uid                string
	Country            string
	Organization       string
	OrganizationalUnit string
	Locality           string
	Province           string
	StreetAddress      string
	PostalCode         string
	CommonName         string
	SerialNumber       *big.Int
	Fingerprint        []byte
}

func (self *SignerInfo) GetName() string {
	if self.CommonName != "" {
		return self.CommonName
	}
	if self.Email != "" {
		return self.Email
	}
	if self.Name != "" {
		return self.Name
	}
	return ""
}

func (self *SignerInfo) GetNameWithFingerprint() string {
	name := self.GetName()
	if self.Fingerprint != nil {
		name = fmt.Sprintf("%s (%s)", name, self.Fingerprint)
	}
	return name
}

type MutationEvalResult struct {
	IsMutated bool        `json:"isMutated"`
	Diff      string      `json:"diff"`
	Filtered  string      `json:"filtered"`
	Checked   bool        `json:"checked"`
	Error     *CheckError `json:"error"`
}

type ImageVerifyResult struct {
	Error       error    `json:"error"`
	Allowed     bool     `json:"allowed"`
	Reason      string   `json:"reason"`
	Digest      string   `json:"digest"`
	CommonNames []string `json:"commonNames"`
}

type ReasonCode struct {
	Message string `json:"message"`
	Code    string `json:"code"`
}

const (
	REASON_INTERNAL = iota //
	REASON_VALIDATION_FAIL
	REASON_RULE_MATCH
	REASON_VALID_SIG
	REASON_VERIFIED_OWNER
	REASON_UPDATE_BY_SA
	REASON_VERIFIED_SA
	REASON_NO_MUTATION
	REASON_ISHIELD_ADMIN
	REASON_IGNORED_SA
	REASON_NOT_PROTECTED
	REASON_IGNORE_RULE_MATCHED
	REASON_BLOCK_ISHIELD_RESOURCE_OPERATION
	REASON_NOT_VERIFIED
	REASON_SKIP_DELETE
	REASON_ABORTED
	REASON_BREAK_GLASS
	REASON_DETECTION
	REASON_INVALID_SIG
	REASON_NO_SIG
	REASON_NO_VALID_KEYRING
	REASON_NO_MATCH_SIGNER_CONFIG
	REASON_NO_MATCH_IMAGE_PROFILE
	REASON_VALID_SIG_IMAGE
	REASON_INVALID_SIG_IMAGE
	REASON_UNEXPECTED
	REASON_ERROR
)

var ReasonCodeMap = map[int]ReasonCode{
	REASON_INTERNAL: {
		Message: "internal request",
		Code:    "internal",
	},
	REASON_VALIDATION_FAIL: {
		Message: "Format validation failed", // detail follows
		Code:    "validation-fail",
	},
	REASON_RULE_MATCH: {
		Message: "allowed by rule",
		Code:    "rule-match",
	},
	REASON_VALID_SIG: {
		Message: "allowed by valid signer's signature",
		Code:    "valid-sig",
	},
	REASON_VERIFIED_OWNER: {
		Message: "owned by verified owner",
		Code:    "verified-owner",
	},
	REASON_UPDATE_BY_SA: {
		Message: "updated by creator",
		Code:    "updated-by-sa",
	},
	REASON_VERIFIED_SA: {
		Message: "operated by verified sa",
		Code:    "verified-sa",
	},
	REASON_NO_MUTATION: {
		Message: "allowed because no mutation found",
		Code:    "no-mutation",
	},
	REASON_ISHIELD_ADMIN: {
		Message: "ishield admin operation",
		Code:    "ishield-admin",
	},
	REASON_IGNORED_SA: {
		Message: "ignored sa",
		Code:    "ignored-sa",
	},
	REASON_NOT_PROTECTED: {
		Message: "not protected",
		Code:    "unprotected",
	},
	REASON_IGNORE_RULE_MATCHED: {
		Message: "ignore rule matched",
		Code:    "ignore-rule-matched",
	},
	REASON_BLOCK_ISHIELD_RESOURCE_OPERATION: {
		Message: "Direct access to Integrity Shield resource is prohibited. To update them, please update configurations in Integrity Shield CR.",
		Code:    "direct-access-prohibited",
	},
	REASON_SKIP_DELETE: {
		Message: "skip delete request",
		Code:    "skip-delete",
	},
	REASON_ABORTED: {
		Message: "aborted",
		Code:    "aborted",
	},
	REASON_BREAK_GLASS: {
		Message: "allowed by breakglass mode",
		Code:    "breakglass",
	},
	REASON_DETECTION: {
		Message: "allowed by detection mode",
		Code:    "detection",
	},
	REASON_INVALID_SIG: {
		Message: "Signature verification is required for this request, but failed to verify signature",
		Code:    "invalid-signature",
	},
	REASON_NO_SIG: {
		Message: "Signature verification is required for this request, but no signature is found. Please attach a valid signature.",
		Code:    "no-signature",
	},
	REASON_NO_VALID_KEYRING: {
		Message: "Signature verification is required for this request, but no verification keys are correctly loaded. Please set valid key secrets for verification or contact Integrity Shield admins.",
		Code:    "no-valid-keyring",
	},
	REASON_NO_MATCH_SIGNER_CONFIG: {
		Message: "Signature verification is required for this request, but no signer config matches with this resource. Please configure SignerConfig for this resource or contact Integrity Shield admins.",
		Code:    "no-match-signer-config",
	},
	REASON_NO_MATCH_IMAGE_PROFILE: {
		Message: "no image profile matches with this commonName",
		Code:    "no-match-image-profile",
	},
	REASON_VALID_SIG_IMAGE: {
		Message: "this image is signed by a valid signer",
		Code:    "valid-sig-image",
	},
	REASON_INVALID_SIG_IMAGE: {
		Message: "Signature verification is required for this image, but failed to verify signature",
		Code:    "invalid-signature-image",
	},
	REASON_UNEXPECTED: {
		Message: "unexpected",
		Code:    "unexpected",
	},
	REASON_ERROR: {
		Message: "error",
		Code:    "error",
	},
}
