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

package policy

import (
	"fmt"

	"github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
	"github.com/jinzhu/copier"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type PolicyType string

const (
	UnknownPolicy PolicyType = ""
	DefaultPolicy PolicyType = "DefaultPolicy"
	IEPolicy      PolicyType = "IEPolicy"
	SignerPolicy  PolicyType = "SignerPolicy"
	CustomPolicy  PolicyType = "CustomPolicy"
)

type IntegrityEnforcerMode string

const (
	UnknownMode     IntegrityEnforcerMode = ""
	EnforcementMode IntegrityEnforcerMode = "enforcement"
	DetectionMode   IntegrityEnforcerMode = "detection"
)

const defaultIntegrityEnforcerMode = EnforcementMode

/**********************************************

					Policy

***********************************************/

type Policy struct {
	AllowUnverified []AllowUnverifiedCondition `json:"allowUnverified,omitempty"`
	Ignore          []RequestMatchPattern      `json:"ignore,omitempty"`
	Signer          []SignerMatchPattern       `json:"signer,omitempty"`
	Allow           AllowRequestCondition      `json:"allow,omitempty"`
	Mode            IntegrityEnforcerMode      `json:"mode,omitempty"`
	PolicyType      PolicyType                 `json:"policyType,omitempty"`
	Description     string                     `json:"description,omitempty"`
}

type IEDefaultPolicy struct {
	Allow       AllowRequestCondition `json:"allowe,omitempty"`
	PolicyType  PolicyType            `json:"policyType,omitempty"`
	Description string                `json:"description,omitempty"`
}

func (self *IEDefaultPolicy) Policy() *Policy {
	return &Policy{
		Allow:       self.Allow,
		PolicyType:  self.PolicyType,
		Description: self.Description,
	}
}

type AppEnforcePolicy struct {
	Allow       AllowRequestCondition `json:"allow,omitempty"`
	Signer      []SignerMatchPattern  `json:"signer,omitempty"`
	PolicyType  PolicyType            `json:"policyType,omitempty"`
	Description string                `json:"description,omitempty"`
}

func (self *AppEnforcePolicy) Policy() *Policy {
	return &Policy{
		Allow:       self.Allow,
		Signer:      self.Signer,
		PolicyType:  self.PolicyType,
		Description: self.Description,
	}
}

type IntegrityEnforcerPolicy struct {
	Allow       AllowRequestCondition `json:"allow,omitempty"`
	Signer      []SignerMatchPattern  `json:"allowedSigner,omitempty"`
	Ignore      []RequestMatchPattern `json:"ignore,omitempty"`
	Mode        IntegrityEnforcerMode `json:"mode,omitempty"`
	PolicyType  PolicyType            `json:"policyType,omitempty"`
	Description string                `json:"description,omitempty"`
}

func (self *IntegrityEnforcerPolicy) Policy() *Policy {
	return &Policy{
		Allow:       self.Allow,
		Signer:      self.Signer,
		Ignore:      self.Ignore,
		Mode:        self.Mode,
		PolicyType:  self.PolicyType,
		Description: self.Description,
	}
}

type IESignerPolicy struct {
	Signer          []SignerMatchPattern       `json:"signer,omitempty"`
	AllowUnverified []AllowUnverifiedCondition `json:"allowUnverified,omitempty"`
	PolicyType      PolicyType                 `json:"policyType,omitempty"`
	Description     string                     `json:"description,omitempty"`
}

func (self *IESignerPolicy) Policy() *Policy {
	return &Policy{
		Signer:          self.Signer,
		AllowUnverified: self.AllowUnverified,
		PolicyType:      self.PolicyType,
		Description:     self.Description,
	}
}

func (self *Policy) CheckFormat() (bool, string) {
	pType := self.PolicyType

	if pType == UnknownPolicy {
		return false, "\"policyType\" must be set for any Policy"
	}

	if pType == DefaultPolicy || pType == IEPolicy || pType == SignerPolicy {
		return false, fmt.Sprintf("\"namespace\" must be empty for %s", pType)
	}
	if pType == CustomPolicy {
		return false, fmt.Sprintf("\"namespace\" must be specified for %s", pType)
	}
	if pType == SignerPolicy {
		hasIgnore := len(self.Ignore) > 0
		hasAllowChange := len(self.Allow.Change) > 0
		hasAllowRequest := len(self.Allow.Request) > 0
		if hasIgnore || hasAllowChange || hasAllowRequest {
			return false, fmt.Sprintf("%s must contain only AllowedSigner rule", pType)
		}
	}
	if pType == CustomPolicy {
		hasSigner := len(self.Signer) > 0
		if hasSigner {
			return false, fmt.Sprintf("%s must not contain AllowedSigner rule", pType)
		}
	}
	return true, ""
}

func (self *Policy) Validate(reqc *common.ReqContext, enforcerNs, policyNs string) (bool, string) {
	// ok, errMsg := self.CheckFormat()
	// if !ok {
	// 	return false, fmt.Sprintf("Policy in invalid format; %s", errMsg)
	// }
	// ns := reqc.Namespace

	// polNs := policyNs
	// pType := self.PolicyType

	// if pType == CustomPolicy && ns != polNs {
	// 	return false, fmt.Sprintf("%s must be created in namespace \"%s\", but requested in \"%s\"", pType, polNs, ns)
	// }

	return true, ""
}

type AllowRequestCondition struct {
	Request []RequestMatchPattern    `json:"request,omitempty"`
	Change  []AllowedChangeCondition `json:"change,omitempty"`
}

type AllowedChangeCondition struct {
	Request RequestMatchPattern `json:"request,omitempty"`
	Key     []string            `json:"key,omitempty"`
}

type SubjectMatchPattern struct {
	Email              string `json:"email,omitempty"`
	Uid                string `json:"uid,omitempty"`
	Country            string `json:"country,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizationalUnit,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Province           string `json:"province,omitempty"`
	StreetAddress      string `json:"streetAddress,omitempty"`
	PostalCode         string `json:"postalCode,omitempty"`
	CommonName         string `json:"commonName,omitempty"`
	SerialNumber       string `json:"serialNumber,omitempty"`
}

type AllowUnverifiedCondition struct {
	Namespace string `json:"namespace,omitempty"`
}

type SignerMatchPattern struct {
	Request RequestMatchPattern `json:"request,omitempty"`
	Subject SubjectMatchPattern `json:"subject,omitempty"`
}

type AllowedUserPattern struct {
	AllowChangesBySignedServiceAccount bool                `json:"allowChangesBySignedServiceAccount,omitempty"`
	AuthorizedServiceAccount           []string            `json:"authorizedServiceAccount,omitempty"`
	Request                            RequestMatchPattern `json:"request,omitempty"`
}

type RequestMatchPattern struct {
	Namespace    string `json:"namespace,omitempty"`
	Name         string `json:"name,omitempty"`
	Operation    string `json:"operation,omitempty"`
	ApiVersion   string `json:"apiVersion,omitempty"`
	Kind         string `json:"kind,omitempty"`
	UserName     string `json:"username,omitempty"`
	Type         string `json:"type,omitempty"`
	K8sCreatedBy string `json:"k8screatedby,omitempty"`
	UserGroup    string `json:"usergroup,omitempty"`
}

func (v *RequestMatchPattern) Match(reqc *common.ReqContext) bool {
	gv := schema.GroupVersion{
		Group:   reqc.ApiGroup,
		Version: reqc.ApiVersion,
	}
	apiVersion := gv.String()

	return MatchPattern(v.Namespace, reqc.Namespace) &&
		MatchPattern(v.Name, reqc.Name) &&
		MatchPattern(v.Operation, reqc.Operation) &&
		MatchPattern(v.Kind, reqc.Kind) &&
		MatchPattern(v.ApiVersion, apiVersion) &&
		MatchPattern(v.UserName, reqc.UserName) &&
		MatchPattern(v.Type, reqc.Type) &&
		MatchPattern(v.K8sCreatedBy, reqc.OrgMetadata.K8sCreatedBy) &&
		MatchPatternWithArray(v.UserGroup, reqc.UserGroups)

}

func (v *AllowUnverifiedCondition) Match(reqc *common.ReqContext) bool {
	if v.Namespace == reqc.Namespace || v.Namespace == "*" {
		return true
	}
	return false
}

func (p *Policy) DeepCopyInto(p2 *Policy) {
	copier.Copy(&p2, &p)
}

func (p *Policy) DeepCopy() *Policy {
	p2 := &Policy{}
	p.DeepCopyInto(p2)
	return p2
}

func (p *AppEnforcePolicy) DeepCopyInto(p2 *AppEnforcePolicy) {
	copier.Copy(&p2, &p)
}

func (p *AppEnforcePolicy) DeepCopy() *AppEnforcePolicy {
	p2 := &AppEnforcePolicy{}
	p.DeepCopyInto(p2)
	return p2
}

func (p *IESignerPolicy) DeepCopyInto(p2 *IESignerPolicy) {
	copier.Copy(&p2, &p)
}

func (p *IESignerPolicy) DeepCopy() *IESignerPolicy {
	p2 := &IESignerPolicy{}
	p.DeepCopyInto(p2)
	return p2
}

func (p *IntegrityEnforcerPolicy) DeepCopyInto(p2 *IntegrityEnforcerPolicy) {
	copier.Copy(&p2, &p)
}

func (p *IntegrityEnforcerPolicy) DeepCopy() *IntegrityEnforcerPolicy {
	p2 := &IntegrityEnforcerPolicy{}
	p.DeepCopyInto(p2)
	return p2
}

func (p *IEDefaultPolicy) DeepCopyInto(p2 *IEDefaultPolicy) {
	copier.Copy(&p2, &p)
}

func (p *IEDefaultPolicy) DeepCopy() *IEDefaultPolicy {
	p2 := &IEDefaultPolicy{}
	p.DeepCopyInto(p2)
	return p2
}

func (p *Policy) Merge(p2 *Policy) *Policy {
	mode := p.Mode
	if p2.Mode != UnknownMode {
		mode = p2.Mode
	}
	return &Policy{
		Ignore:          append(p.Ignore, p2.Ignore...),
		Signer:          append(p.Signer, p2.Signer...),
		Allow:           append(p.Allow, p2.Allow...),
		AllowUnverified: append(p.AllowUnverified, p2.AllowUnverified...),
		Mode:            mode,
	}
}
