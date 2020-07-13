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

package sign

import (
	"encoding/json"
	"errors"
	"fmt"

	epolpkg "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/enforcepolicy/v1alpha1"
	rsigpkg "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourcesignature/v1alpha1"
	common "github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/logger"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/policy"
	"github.com/ghodss/yaml"
	"github.com/jinzhu/copier"
)

/**********************************************

				SignPolicy

***********************************************/

type SignPolicy interface {
	Eval(reqc *common.ReqContext) (*common.SignPolicyEvalResult, error)
}

type ConcreteSignPolicy struct {
	EnforcerNamespace string
	PolicyNamespace   string
	Patterns          []policy.SignerMatchPattern
}

/**********************************************

				EnforceRuleStore

***********************************************/

type EnforceRuleStore interface {
	Find(reqc *common.ReqContext) *EnforceRuleList
}

type EnforceRuleStoreFromPolicy struct {
	Patterns []policy.SignerMatchPattern
}

func (self *EnforceRuleStoreFromPolicy) Find(reqc *common.ReqContext) *EnforceRuleList {
	eRules := []EnforceRule{}
	for _, p := range self.Patterns {
		r := ToPolicyRule(p)
		if _, resMatched := MatchSigner(r, reqc.GroupVersion(), reqc.Kind, reqc.Name, reqc.Namespace, nil); !resMatched {
			continue
		}
		er := &EnforceRuleFromCR{Instance: r}
		eRules = append(eRules, er)
	}
	return &EnforceRuleList{Rules: eRules}
}

/**********************************************

			EnforceRule, EnforceRuleList

***********************************************/

type EnforceRule interface {
	Eval(reqc *common.ReqContext, signer *common.SignerInfo) (*EnforceRuleEvalResult, error)
}

type EnforceRuleFromCR struct {
	Instance *Rule
}

func (self *EnforceRuleFromCR) Eval(reqc *common.ReqContext, signer *common.SignerInfo) (*EnforceRuleEvalResult, error) {
	apiVersion := reqc.GroupVersion()
	kind := reqc.Kind
	name := reqc.Name
	namespace := reqc.Namespace
	ruleOk, _ := MatchSigner(self.Instance, apiVersion, kind, name, namespace, signer)
	result := &EnforceRuleEvalResult{
		Signer:  signer,
		Checked: true,
		Allow:   ruleOk,
		Error:   nil,
	}
	return result, nil
}

type EnforceRuleEvalResult struct {
	Signer  *common.SignerInfo
	Checked bool
	Allow   bool
	Error   *common.CheckError
}

type EnforceRuleList struct {
	Rules []EnforceRule
}

func (self *EnforceRuleList) Eval(reqc *common.ReqContext, signer *common.SignerInfo) (*EnforceRuleEvalResult, error) {
	if len(self.Rules) == 0 {
		return &EnforceRuleEvalResult{
			Signer:  signer,
			Allow:   true,
			Checked: true,
		}, nil
	}
	for _, rule := range self.Rules {
		if v, err := rule.Eval(reqc, signer); err != nil {
			return v, err
		} else if v != nil && v.Allow {
			return v, nil
		}
	}
	return &EnforceRuleEvalResult{
		Allow:   false,
		Checked: true,
	}, errors.New(fmt.Sprintf("No signer policies met this resource. this resource is signed by %s", signer.Email))
}

func (self *ConcreteSignPolicy) Eval(reqc *common.ReqContext) (*common.SignPolicyEvalResult, error) {

	if reqc.IsEnforcePolicyRequest() {
		var polObj *epolpkg.EnforcePolicy
		json.Unmarshal(reqc.RawObject, &polObj)
		if ok, reasonFail := polObj.Spec.Policy.Validate(reqc, self.EnforcerNamespace, self.PolicyNamespace); !ok {
			return &common.SignPolicyEvalResult{
				Allow:   false,
				Checked: true,
				Error: &common.CheckError{
					Reason: fmt.Sprintf("Schema Error for %s; %s", common.PolicyCustomResourceKind, reasonFail),
				},
			}, nil
		}
	}

	if reqc.IsResourceSignatureRequest() {
		var rsigObj *rsigpkg.ResourceSignature
		json.Unmarshal(reqc.RawObject, &rsigObj)
		if ok, reasonFail := rsigObj.Validate(); !ok {
			return &common.SignPolicyEvalResult{
				Allow:   false,
				Checked: true,
				Error: &common.CheckError{
					Reason: fmt.Sprintf("Schema Error for %s; %s", common.SignatureCustomResourceKind, reasonFail),
				},
			}, nil
		}
	}

	// eval sign policy
	ref := reqc.ResourceRef()

	// find signature
	signStore := GetSignStore()
	rsig := signStore.GetResourceSignature(ref, reqc)
	if rsig == nil {
		return &common.SignPolicyEvalResult{
			Allow:   false,
			Checked: true,
			Error: &common.CheckError{
				Reason: "No signature found",
			},
		}, nil
	}

	// create verifier
	verifier := NewVerifier(rsig.SignType, self.EnforcerNamespace)

	// verify signature
	sigVerifyResult, err := verifier.Verify(rsig, reqc)
	if err != nil {
		return &common.SignPolicyEvalResult{
			Allow:   false,
			Checked: true,
			Error: &common.CheckError{
				Error:  err,
				Reason: "Error during signature verification",
			},
		}, nil
	}

	if sigVerifyResult == nil || sigVerifyResult.Signer == nil {
		msg := ""
		if sigVerifyResult != nil && sigVerifyResult.Error != nil {
			msg = sigVerifyResult.Error.Reason
		}
		return &common.SignPolicyEvalResult{
			Allow:   false,
			Checked: true,
			Error: &common.CheckError{
				Reason: fmt.Sprintf("Failed to verify signature; %s", msg),
			},
		}, nil
	}

	// signer
	signer := sigVerifyResult.Signer

	// get enforce rule list
	var ruleStore EnforceRuleStore = &EnforceRuleStoreFromPolicy{Patterns: self.Patterns}

	reqcForEval := makeReqcForEval(reqc, reqc.RawObject)

	ruleList := ruleStore.Find(reqcForEval)

	// evaluate enforce rules
	if ruleEvalResult, err := ruleList.Eval(reqcForEval, signer); err != nil {
		return &common.SignPolicyEvalResult{
			Signer:  signer,
			Allow:   false,
			Checked: true,
			Error: &common.CheckError{
				Error:  err,
				Reason: err.Error(),
			},
		}, nil
	} else {
		return &common.SignPolicyEvalResult{
			Signer:  ruleEvalResult.Signer,
			Allow:   ruleEvalResult.Allow,
			Checked: ruleEvalResult.Checked,
			Error:   ruleEvalResult.Error,
		}, nil
	}

}

func makeReqcForEval(reqc *common.ReqContext, rawObj []byte) *common.ReqContext {
	var err error
	isEnforcePolicy := reqc.IsEnforcePolicyRequest()
	isResourceSignature := reqc.IsResourceSignatureRequest()

	if !isEnforcePolicy && !isResourceSignature {
		return reqc
	}

	reqcForEval := &common.ReqContext{}
	copier.Copy(&reqcForEval, &reqc)

	if isEnforcePolicy {
		var epolObj *epolpkg.EnforcePolicy
		err = json.Unmarshal(rawObj, &epolObj)
		if err == nil {
			// Master policies (e.g. ie-policy) do not have `Namespace` in policy spec.
			// Normal sign policy evaluation would be done in the case.
			// Other per-ns policy must have `Namespace` field.
			if epolObj.Spec.Policy.Namespace != "" {
				reqcForEval.Namespace = epolObj.Spec.Policy.Namespace
			}
		} else {
			logger.Error(err)
		}
	}

	if isResourceSignature {
		var rsigObj *rsigpkg.ResourceSignature
		err = json.Unmarshal(rawObj, &rsigObj)
		if err == nil {
			if rsigObj.Spec.Data[0].Metadata.Namespace != "" {
				reqcForEval.Namespace = rsigObj.Spec.Data[0].Metadata.Namespace
			}
			isResourceSignatureForEnforcePolicy := (rsigObj.Spec.Data[0].ApiVersion == common.PolicyCustomResourceAPIVersion && rsigObj.Spec.Data[0].Kind == common.PolicyCustomResourceKind)
			if isResourceSignatureForEnforcePolicy {
				var epolObj *epolpkg.EnforcePolicy
				rawEpolBytes := []byte(base64decode(rsigObj.Spec.Data[0].Message))
				err = yaml.Unmarshal(rawEpolBytes, &epolObj)
				if err == nil {
					reqcForEval.Namespace = epolObj.Spec.Policy.Namespace
				} else {
					logger.Error(err)
				}
			}
		} else {
			logger.Error(err)
		}
	}
	return reqcForEval
}

type EnforcerPolicyType string

const (
	Unknown EnforcerPolicyType = ""
	Allow   EnforcerPolicyType = "Allow"
	Deny    EnforcerPolicyType = "Deny"
)

type Subject struct {
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

func (v *Subject) Match(signer *common.SignerInfo) bool {
	if signer == nil {
		return false
	}

	return policy.MatchPattern(v.Email, signer.Email) &&
		policy.MatchPattern(v.Uid, signer.Uid) &&
		policy.MatchPattern(v.Country, signer.Country) &&
		policy.MatchPattern(v.Organization, signer.Organization) &&
		policy.MatchPattern(v.OrganizationalUnit, signer.OrganizationalUnit) &&
		policy.MatchPattern(v.Locality, signer.Locality) &&
		policy.MatchPattern(v.Province, signer.Province) &&
		policy.MatchPattern(v.StreetAddress, signer.StreetAddress) &&
		policy.MatchPattern(v.PostalCode, signer.PostalCode) &&
		policy.MatchPattern(v.CommonName, signer.CommonName) &&
		policy.MatchPattern(v.SerialNumber, signer.SerialNumber)
}

type Resource struct {
	ApiVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Name       string `json:"name,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
}

type Rule struct {
	Type     EnforcerPolicyType `json:"type,omitempty"`
	Resource Resource           `json:"resource,omitempty"`
	Subject  Subject            `json:"subject,omitempty"`
}

func NewSignPolicy(enforcerNamespace, policyNamespace string, patterns []policy.SignerMatchPattern) (SignPolicy, error) {
	return &ConcreteSignPolicy{
		EnforcerNamespace: enforcerNamespace,
		PolicyNamespace:   policyNamespace,
		Patterns:          patterns,
	}, nil
}

func ToPolicyRule(self policy.SignerMatchPattern) *Rule {
	return &Rule{
		Type: Allow,
		Resource: Resource{
			ApiVersion: self.Request.ApiVersion,
			Kind:       self.Request.Kind,
			Name:       self.Request.Name,
			Namespace:  self.Request.Namespace,
		},
		Subject: Subject{
			Email:              self.Subject.Email,
			Uid:                self.Subject.Uid,
			Country:            self.Subject.Country,
			Organization:       self.Subject.Organization,
			OrganizationalUnit: self.Subject.OrganizationalUnit,
			Locality:           self.Subject.Locality,
			Province:           self.Subject.Province,
			StreetAddress:      self.Subject.StreetAddress,
			PostalCode:         self.Subject.PostalCode,
			CommonName:         self.Subject.CommonName,
			SerialNumber:       self.Subject.SerialNumber,
		},
	}
}

func MatchSigner(r *Rule, apiVersion, kind, name, namespace string, signer *common.SignerInfo) (bool, bool) {
	apiVersionOk := policy.MatchPattern(r.Resource.ApiVersion, apiVersion)
	kindOk := policy.MatchPattern(r.Resource.Kind, kind)
	nameOk := policy.MatchPattern(r.Resource.Name, name)
	namespaceOk := policy.MatchPattern(r.Resource.Namespace, namespace)
	resourceMatched := false
	if apiVersionOk && kindOk && nameOk && namespaceOk {
		resourceMatched = true
	}
	if resourceMatched {
		if r.Subject.Match(signer) {
			return true, resourceMatched
		} else {
			return false, resourceMatched
		}
	}
	return false, resourceMatched
}
