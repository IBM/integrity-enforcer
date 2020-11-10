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
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strconv"
)

const (
	IECustomResourceAPIVersion = "apis.integrityenforcer.io/v1alpha1"
	IECustomResourceKind       = "IntegrityEnforcer"

	SignatureCustomResourceAPIVersion = "apis.integrityenforcer.io/v1alpha1"
	SignatureCustomResourceKind       = "ResourceSignature"
	PolicyCustomResourceAPIVersion    = "apis.integrityenforcer.io/v1alpha1"
	PolicyCustomResourceKind          = "EnforcePolicy"

	IEPolicyCustomResourceAPIVersion      = "apis.integrityenforcer.io/v1alpha1"
	IEPolicyCustomResourceKind            = "IntegrityEnforcerPolicy"
	DefaultPolicyCustomResourceAPIVersion = "apis.integrityenforcer.io/v1alpha1"
	DefaultPolicyCustomResourceKind       = "IEDefaultPolicy"
	SignerPolicyCustomResourceAPIVersion  = "apis.integrityenforcer.io/v1alpha1"
	SignerPolicyCustomResourceKind        = "SignPolicy"
	AppPolicyCustomResourceAPIVersion     = "apis.integrityenforcer.io/v1alpha1"
	AppPolicyCustomResourceKind           = "AppEnforcePolicy"
)

const (
	ResourceIntegrityLabelKey = "integrityenforcer.io/resourceIntegrity"
	ReasonLabelKey            = "integrityenforcer.io/reason"

	ResSigLabelApiVer = "integrityenforcer.io/sigobject-apiversion"
	ResSigLabelKind   = "integrityenforcer.io/sigobject-kind"
	ResSigLabelTime   = "integrityenforcer.io/sigtime"

	LabelValueVerified   = "verified"
	LabelValueUnverified = "unverified"
)

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
	return (self.Name == ref.Name &&
		self.Namespace == ref.Namespace &&
		self.Kind == ref.Kind &&
		self.ApiVersion == ref.ApiVersion)
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

func NewResourceAnnotation(values map[string]string) *ResourceAnnotation {
	return &ResourceAnnotation{
		values: values,
	}
}

type SignatureAnnotation struct {
	ResourceSignatureName string
	SignatureType         string
	Signature             string
	Certificate           string
	Message               string
	MessageScope          string
	MutableAttrs          string
}

func (self *ResourceAnnotation) SignatureAnnotations() *SignatureAnnotation {
	return &SignatureAnnotation{
		ResourceSignatureName: self.getString("resourceSignatureName"),
		Signature:             self.getString("signature"),
		SignatureType:         self.getString("signatureType"),
		Certificate:           self.getString("certificate"),
		Message:               self.getString("message"),
		MessageScope:          self.getString("messageScope"),
		MutableAttrs:          self.getString("mutableAttrs"),
	}
}

func (self *ResourceAnnotation) IntegrityVerified() bool {
	return self.getBool("integrityVerified", false)
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
	Signer        *SignerInfo `json:"signer"`
	SignerName    string      `json:"signerName"`
	Checked       bool        `json:"checked"`
	Allow         bool        `json:"allow"`
	MatchedPolicy string      `json:"matchedPolicy"`
	Error         *CheckError `json:"error"`
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

func NewSignerInfoFromCert(cert *x509.Certificate) *SignerInfo {
	si := NewSignerInfoFromPKIXName(cert.Subject)
	si.SerialNumber = cert.SerialNumber
	return si
}

func NewSignerInfoFromPKIXName(dn pkix.Name) *SignerInfo {
	si := &SignerInfo{}

	if dn.Country != nil {
		si.Country = dn.Country[0]
	}
	if dn.Organization != nil {
		si.Organization = dn.Organization[0]
	}
	if dn.OrganizationalUnit != nil {
		si.OrganizationalUnit = dn.OrganizationalUnit[0]
	}
	if dn.Locality != nil {
		si.Locality = dn.Locality[0]
	}
	if dn.Province != nil {
		si.Province = dn.Province[0]
	}
	if dn.StreetAddress != nil {
		si.StreetAddress = dn.StreetAddress[0]
	}
	if dn.PostalCode != nil {
		si.PostalCode = dn.PostalCode[0]
	}
	if dn.CommonName != "" {
		si.CommonName = dn.CommonName
	}
	// if dn.SerialNumber != "" {
	// 	si.SerialNumber = dn.SerialNumber
	// }
	return si
}

type ResolveOwnerResult struct {
	Owners   *OwnerList  `json:"owners"`
	Verified bool        `json:"verified"`
	Checked  bool        `json:"checked"`
	Error    *CheckError `json:"error"`
}

func (self *ResolveOwnerResult) setOwnerVerified() {
	if self.Owners == nil || self.Owners.Owners == nil {
		self.Verified = false
		return
	}
	owners := self.Owners.Owners
	self.Verified = owners[len(owners)-1].IsIntegrityVerified()
}

type Owner struct {
	Ref        *ResourceRef
	OwnerRef   *ResourceRef
	Annotation *ResourceAnnotation
	Label      *ResourceLabel
}

func (self *Owner) IsIntegrityVerified() bool {
	return self.Label.IntegrityVerified()
}

type OwnerList struct {
	Owners []*Owner
}

func (self *OwnerList) OwnerRefs() []ResourceRef {
	var ownerRefs []ResourceRef
	for _, ow := range self.Owners {
		ownerRefs = append(ownerRefs, *ow.Ref)
	}
	return ownerRefs
}

func (self *OwnerList) VerifiedOwners() []*Owner {
	var verifiedOwners []*Owner
	for _, ow := range self.Owners {
		if ow.IsIntegrityVerified() {
			verifiedOwners = append(verifiedOwners, ow)
		}
	}
	return verifiedOwners
}

type MutationEvalResult struct {
	IsMutated bool        `json:"isMutated"`
	Diff      string      `json:"diff"`
	Filtered  string      `json:"filtered"`
	Checked   bool        `json:"checked"`
	Error     *CheckError `json:"error"`
}

type ReasonCode struct {
	Message string `json:"message"`
	Code    string `json:"code"`
}

const (
	REASON_INTERNAL = iota //
	REASON_RULE_MATCH
	REASON_VALID_SIG
	REASON_VERIFIED_OWNER
	REASON_UPDATE_BY_SA
	REASON_VERIFIED_SA
	REASON_NO_MUTATION
	REASON_IE_ADMIN
	REASON_IGNORED_SA
	REASON_NOT_PROTECTED
	REASON_BLOCK_IE_RESOURCE_OPERATION
	REASON_NOT_ENFORCED
	REASON_SKIP_DELETE
	REASON_ABORTED
	REASON_BREAK_GLASS
	REASON_DETECTION
	REASON_INVALID_SIG
	REASON_NO_SIG
	REASON_NO_POLICY
	REASON_UNEXPECTED
	REASON_ERROR
)

var ReasonCodeMap = map[int]ReasonCode{
	REASON_INTERNAL: {
		Message: "internal request",
		Code:    "internal",
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
	REASON_IE_ADMIN: {
		Message: "IE admin operation",
		Code:    "ie-admin",
	},
	REASON_IGNORED_SA: {
		Message: "ignored sa",
		Code:    "ignored-sa",
	},
	REASON_NOT_PROTECTED: {
		Message: "not protected",
		Code:    "unprotected",
	},
	REASON_BLOCK_IE_RESOURCE_OPERATION: {
		Message: "block oprations for IE resouce",
		Code:    "block-ieresource-operation",
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
		Message: "Failed to verify signature",
		Code:    "invalid-signature",
	},
	REASON_NO_SIG: {
		Message: "No signature found",
		Code:    "no-signature",
	},
	REASON_NO_POLICY: {
		Message: "No signer policies",
		Code:    "no-signer-policy",
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
