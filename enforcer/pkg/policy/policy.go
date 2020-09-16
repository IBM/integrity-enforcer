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
	"reflect"
	"strings"

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

type ScopeType string

const (
	ScopeUndefined  ScopeType = ""
	ScopeNamespaced ScopeType = "Namespaced"
	ScopeCluster    ScopeType = "Cluster"
)

type IntegrityEnforcerMode string

const (
	UnknownMode IntegrityEnforcerMode = ""
	EnforceMode IntegrityEnforcerMode = "enforce"
	DetectMode  IntegrityEnforcerMode = "detect"
)

const defaultIntegrityEnforcerMode = EnforceMode

/**********************************************

					Policy

***********************************************/

type Policy struct {
	AllowUnverified []AllowUnverifiedCondition `json:"allowUnverified,omitempty"`
	Ignore          []RequestMatchPattern      `json:"ignore,omitempty"`
	Signer          []SignerMatchPattern       `json:"signer,omitempty"`
	Allow           AllowRequestCondition      `json:"allow,omitempty"`
	Mode            IntegrityEnforcerMode      `json:"mode,omitempty"`
	Plugin          []PluginPolicy             `json:"plugin,omitempty"`
	PolicyType      PolicyType                 `json:"policyType,omitempty"`
	Description     string                     `json:"description,omitempty"`
}

type PolicyList struct {
	Items []*Policy `json:"items,omitempty"`
}

func (self *PolicyList) Add(pol *Policy) {
	self.Items = append(self.Items, pol)
}

func (self *PolicyList) Get(pTypeList []PolicyType) *PolicyList {
	isListed := map[PolicyType]bool{}
	for _, pType := range pTypeList {
		isListed[pType] = true
	}
	items := []*Policy{}
	for _, pol := range self.Items {
		if isListed[pol.PolicyType] {
			items = append(items, pol)
		}
	}
	return &PolicyList{
		Items: items,
	}
}

func (self *PolicyList) Policy() *Policy {
	pol := &Policy{}
	for _, iPol := range self.Items {
		pol = pol.Merge(iPol)
	}
	return pol
}

func (self *PolicyList) GetMode() (IntegrityEnforcerMode, *Policy) {
	mode := defaultIntegrityEnforcerMode
	var matchedPolicy *Policy
	// priority := 0
	iePolicyList := self.Get([]PolicyType{IEPolicy})
	for _, pol := range iePolicyList.Items {
		if pol.Mode != UnknownMode {
			mode = pol.Mode
			matchedPolicy = pol
		}
	}
	return mode, matchedPolicy
}

func (self *PolicyList) CheckPluginEnabled(name string) bool {
	enabled := false
	found := false
	for _, pol := range self.Items {
		if found {
			break
		}
		for _, plg := range pol.Plugin {
			if plg.Name == name {
				if plg.Enabled {
					enabled = true
				}
				found = true
			}
		}
	}
	return enabled
}

func (self *PolicyList) GetEnabledPlugins() map[string]bool {
	plugins := map[string]bool{}
	iePolicyList := self.Get([]PolicyType{IEPolicy})
	for _, pol := range iePolicyList.Items {
		for _, plg := range pol.Plugin {
			if plg.Enabled {
				plugins[plg.Name] = true
			}
		}
	}
	return plugins
}

func (self *PolicyList) GetAllowChange() []AllowedChangeCondition {
	policyList := self.Get([]PolicyType{IEPolicy, DefaultPolicy, CustomPolicy})
	policy := policyList.Policy()
	return policy.Allow.Change
}

func (self *PolicyList) GetSigner() []SignerMatchPattern {
	policyList := self.Get([]PolicyType{IEPolicy, SignerPolicy, CustomPolicy})
	policy := policyList.Policy()
	return policy.Signer
}

func (self *PolicyList) FindMatchedChangePolicy(reqc *common.ReqContext, matchedKeys []string) *PolicyList {
	matched := &PolicyList{}

	isMatchedKey := map[string]bool{}
	for _, k := range matchedKeys {
		isMatchedKey[k] = true
	}

	policyList := self.Get([]PolicyType{IEPolicy, DefaultPolicy, CustomPolicy})
	for _, pol := range policyList.Items {
		polMatched := false
		for _, change := range pol.Allow.Change {
			if polMatched {
				break
			}
			if change.Request.Match(reqc) {
				for _, key := range change.Key {
					if isMatchedKey[key] {
						polMatched = true
						break
					}
				}
			}
		}
		if polMatched {
			matched.Add(pol)
		}
	}
	return matched
}

func (self *PolicyList) FindMatchedSignerPolicy(reqc *common.ReqContext, matchedRule SignerMatchPattern) *Policy {
	policyList := self.Get([]PolicyType{IEPolicy, SignerPolicy, CustomPolicy})
	for _, pol := range policyList.Items {
		for _, signer := range pol.Signer {
			if signer.Request.Match(reqc) {
				if reflect.DeepEqual(signer, matchedRule) {
					return pol
				}
			}
		}
	}
	return nil
}

func (self *PolicyList) String() string {
	strList := []string{}
	for _, pol := range self.Items {
		strList = append(strList, pol.String())
	}
	return strings.Join(strList, ",")
}

type IEDefaultPolicy struct {
	Allow       AllowRequestCondition `json:"allow,omitempty"`
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
	Sign        *VSignPolicy          `json:"sign,omitempty"`
	Ignore      []RequestMatchPattern `json:"ignore,omitempty"`
	Mode        IntegrityEnforcerMode `json:"mode,omitempty"`
	Plugin      []PluginPolicy        `json:"plugin,omitempty"`
	Description string                `json:"description,omitempty"`
}

func (self *IntegrityEnforcerPolicy) Policy() *Policy {
	return &Policy{
		Allow:       self.Allow,
		Signer:      self.Sign.Policy().Signer,
		Ignore:      self.Ignore,
		Mode:        self.Mode,
		Plugin:      self.Plugin,
		Description: self.Description,
	}
}

func (self *IntegrityEnforcerPolicy) GetEnabledPlugins() map[string]bool {
	plugins := map[string]bool{}
	for _, plg := range self.Plugin {
		if plg.Enabled {
			plugins[plg.Name] = true
		}
	}
	return plugins
}

func (self *IntegrityEnforcerPolicy) CheckPluginEnabled(name string) bool {
	policy := self.Policy()
	pList := &PolicyList{
		Items: []*Policy{policy},
	}
	return pList.CheckPluginEnabled(name)
}

type PluginPolicy struct {
	Name    string `json:"name,omitempty"`
	Enabled bool   `json:"enabled,omitempty"`
}

type VSignPolicy struct {
	Policies    []SignPolicyCondition `json:"policies,omitempty"`
	Signers     []SignerCondition     `json:"signers,omitempty"`
	BreakGlass  []BreakGlassCondition `json:"breakGlass,omitempty"`
	Description string                `json:"description,omitempty"`
}

func (self *VSignPolicy) GetSignerMap() map[string][]SubjectCondition {
	signerMap := map[string][]SubjectCondition{}
	for _, si := range self.Signers {
		tmpSC := []SubjectCondition{}
		for _, sj := range si.Subjects {
			sc := SubjectCondition{
				Name:    si.Name,
				Subject: sj,
			}
			tmpSC = append(tmpSC, sc)
		}
		signerMap[si.Name] = tmpSC
	}
	return signerMap
}

func (self *VSignPolicy) Merge(data *VSignPolicy) *VSignPolicy {
	merged := &VSignPolicy{}
	merged.Policies = append(self.Policies, data.Policies...)
	merged.Signers = append(self.Signers, data.Signers...)
	merged.BreakGlass = append(self.BreakGlass, data.BreakGlass...)
	merged.Description = self.Description
	return merged
}

func (self *VSignPolicy) Match(namespace string, signer *common.SignerInfo) (bool, *SignPolicyCondition) {
	signerMap := self.GetSignerMap()
	for _, spc := range self.Policies {
		included := common.MatchWithPatternArray(namespace, spc.Namespaces)
		excluded := common.MatchWithPatternArray(namespace, spc.ExcludeNamespaces)
		signerMatched := false
		for _, signerName := range spc.Signers {
			subjectConditions, ok := signerMap[signerName]
			if !ok {
				continue
			}
			for _, subjectCondition := range subjectConditions {
				if subjectCondition.Match(signer) {
					signerMatched = true
					break
				}
			}
			if signerMatched {
				break
			}
		}
		matched := included && !excluded && signerMatched
		if matched {
			return true, &spc
		}
	}
	return false, nil
}

func (self *VSignPolicy) Policy() *Policy {
	signerMap := self.GetSignerMap()

	signer := []SignerMatchPattern{}
	for _, sp := range self.Policies {
		rmp := RequestMatchPattern{
			Namespace: strings.Join(sp.Namespaces, ","),
		}
		for _, si := range sp.Signers {
			if scList, ok := signerMap[si]; ok {
				for _, sc := range scList {
					smp := SignerMatchPattern{
						Request:   rmp,
						Condition: sc,
					}
					signer = append(signer, smp)
				}
			}
		}
	}

	allowUnverified := []AllowUnverifiedCondition{}
	for _, bg := range self.BreakGlass {
		tmp := AllowUnverifiedCondition{Namespace: strings.Join(bg.Namespaces, ",")}
		allowUnverified = append(allowUnverified, tmp)
	}

	return &Policy{
		Signer:          signer,
		AllowUnverified: allowUnverified,
		Description:     self.Description,
	}
}

type SignPolicyCondition struct {
	Scope             ScopeType `json:"scope,omitempty"`
	Namespaces        []string  `json:"namespaces,omitempty"`
	ExcludeNamespaces []string  `json:"excludeNamespaces,omitempty"`
	Signers           []string  `json:"signers,omitempty"`
}

type SignerCondition struct {
	Name     string                `json:"name,omitempty"`
	Subjects []SubjectMatchPattern `json:"subjects,omitempty"`
}

type BreakGlassCondition struct {
	Scope      ScopeType `json:"scope,omitempty"`
	Namespaces []string  `json:"namespaces,omitempty"`
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

func (self *Policy) String() string {
	if self.Description == "" {
		return fmt.Sprintf("%s", self.PolicyType)
	} else {
		return fmt.Sprintf("%s(%s)", self.PolicyType, self.Description)
	}
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

func (arc1 AllowRequestCondition) Merge(arc2 AllowRequestCondition) AllowRequestCondition {
	return AllowRequestCondition{
		Request: append(arc1.Request, arc2.Request...),
		Change:  append(arc1.Change, arc2.Change...),
	}
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

type SubjectCondition struct {
	Name    string              `json:"name"`
	Subject SubjectMatchPattern `json:"subject"`
}

func (self *SubjectCondition) Match(signer *common.SignerInfo) bool {
	return common.MatchPattern(self.Subject.Email, signer.Email) &&
		common.MatchPattern(self.Subject.Uid, signer.Uid) &&
		common.MatchPattern(self.Subject.Country, signer.Country) &&
		common.MatchPattern(self.Subject.Organization, signer.Organization) &&
		common.MatchPattern(self.Subject.OrganizationalUnit, signer.OrganizationalUnit) &&
		common.MatchPattern(self.Subject.Locality, signer.Locality) &&
		common.MatchPattern(self.Subject.Province, signer.Province) &&
		common.MatchPattern(self.Subject.StreetAddress, signer.StreetAddress) &&
		common.MatchPattern(self.Subject.PostalCode, signer.PostalCode) &&
		common.MatchPattern(self.Subject.CommonName, signer.CommonName) &&
		common.MatchPattern(self.Subject.SerialNumber, signer.SerialNumber)
}

type AllowUnverifiedCondition struct {
	Namespace string `json:"namespace,omitempty"`
}

type SignerMatchPattern struct {
	Request   RequestMatchPattern `json:"request,omitempty"`
	Condition SubjectCondition    `json:"condition,omitempty"`
}

type AllowedUserPattern struct {
	AllowChangesBySignedServiceAccount bool                `json:"allowChangesBySignedServiceAccount,omitempty"`
	AuthorizedServiceAccount           []string            `json:"authorizedServiceAccount,omitempty"`
	Request                            RequestMatchPattern `json:"request,omitempty"`
}

type RequestMatchPattern struct {
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name,omitempty"`
	Operation  string `json:"operation,omitempty"`
	ApiVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	UserName   string `json:"username,omitempty"`
	Type       string `json:"type,omitempty"`
	UserGroup  string `json:"usergroup,omitempty"`
}

func (v *RequestMatchPattern) Match(reqc *common.ReqContext) bool {
	gv := schema.GroupVersion{
		Group:   reqc.ApiGroup,
		Version: reqc.ApiVersion,
	}
	apiVersion := gv.String()

	return common.MatchPattern(v.Namespace, reqc.Namespace) &&
		common.MatchPattern(v.Name, reqc.Name) &&
		common.MatchPattern(v.Operation, reqc.Operation) &&
		common.MatchPattern(v.Kind, reqc.Kind) &&
		common.MatchPattern(v.ApiVersion, apiVersion) &&
		common.MatchPattern(v.UserName, reqc.UserName) &&
		common.MatchPattern(v.Type, reqc.Type) &&
		common.MatchPatternWithArray(v.UserGroup, reqc.UserGroups)

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

func (p *VSignPolicy) DeepCopyInto(p2 *VSignPolicy) {
	copier.Copy(&p2, &p)
}

func (p *VSignPolicy) DeepCopy() *VSignPolicy {
	p2 := &VSignPolicy{}
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
	allow := p.Allow.Merge(p2.Allow)
	return &Policy{
		Ignore:          append(p.Ignore, p2.Ignore...),
		Signer:          append(p.Signer, p2.Signer...),
		Allow:           allow,
		AllowUnverified: append(p.AllowUnverified, p2.AllowUnverified...),
		Mode:            mode,
		Plugin:          append(p.Plugin, p2.Plugin...),
	}
}
