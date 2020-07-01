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
	"strconv"
)

const (
	SignatureCustomResourceAPIVersion = "research.ibm.com/v1alpha1"
	SignatureCustomResourceKind       = "ResourceSignature"
	PolicyCustomResourceAPIVersion    = "research.ibm.com/v1alpha1"
	PolicyCustomResourceKind          = "EnforcePolicy"
)

/**********************************************

				ResourceRef

***********************************************/

type ResourceRef struct {
	Name       string
	Namespace  string
	Kind       string
	ApiVersion string
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
	Signature             string
	MessageScope          string
	IgnoreAttrs           string
}

func (self *ResourceAnnotation) SignatureAnnotations() *SignatureAnnotation {
	return &SignatureAnnotation{
		ResourceSignatureName: self.getString("resourceSignatureName"),
		Signature:             self.getString("signature"),
		MessageScope:          self.getString("messageScope"),
		IgnoreAttrs:           self.getString("ignoreAttrs"),
	}
}

func (self *ResourceAnnotation) IntegrityVerified() bool {
	return self.getBool("integrityVerified", false)
}

func (self *ResourceAnnotation) CreatedBy() string {
	return self.getString("ie-createdBy")
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

type SignPolicyEvalResult struct {
	Signer  *SignerInfo `json:"signer"`
	Checked bool        `json:"checked"`
	Allow   bool        `json:"allow"`
	Error   *CheckError `json:"error"`
}

type SignerInfo struct {
	Email   string
	Name    string
	Comment string
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
}

func (self *Owner) IsIntegrityVerified() bool {
	return self.Annotation.IntegrityVerified()
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
	REASON_NO_MUTATION
	REASON_NOT_ENFORCED
	REASON_SKIP_DELETE
	REASON_ABORTED
	REASON_UNVERIFIED
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
	REASON_NO_MUTATION: {
		Message: "allowed because no mutation found",
		Code:    "no-mutation",
	},
	REASON_NOT_ENFORCED: {
		Message: "not enforced",
		Code:    "not-enforced",
	},
	REASON_SKIP_DELETE: {
		Message: "skip delete request",
		Code:    "skip-delete",
	},
	REASON_ABORTED: {
		Message: "aborted",
		Code:    "aborted",
	},
	REASON_UNVERIFIED: {
		Message: "allowed by allowUnverified policy",
		Code:    "unverified",
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
