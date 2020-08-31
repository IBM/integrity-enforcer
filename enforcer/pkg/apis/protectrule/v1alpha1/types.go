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
	"encoding/json"
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ProtectRuleSpec defines the desired state of AppEnforcePolicy
type ProtectRuleSpec struct {
	Rules []*Rule `json:"rules,omitempty"`
}

// ProtectRuleStatus defines the observed state of AppEnforcePolicy
type ProtectRuleStatus struct {
	Results []*Result `json:"deniedRequests,omitempty"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=protectrule,scope=Namespaced

// EnforcePolicy is the CRD. Use this command to generate deepcopy for it:
// ./k8s.io/code-generator/generate-groups.sh all github.com/IBM/pas-client-go/pkg/crd/packageadmissionsignature/v1/apis github.com/IBM/pas-client-go/pkg/crd/ "packageadmissionsignature:v1"
// For more details of code-generator, please visit https://github.com/kubernetes/code-generator
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// ProtectRule is the CRD. Use this command to generate deepcopy for it:
type ProtectRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ProtectRuleSpec   `json:"spec,omitempty"`
	Status ProtectRuleStatus `json:"status,omitempty"`
}

func (self *ProtectRule) IsEmpty() bool {
	return len(self.Spec.Rules) == 0
}

func (self *ProtectRule) Match(reqFields map[string]string) (bool, *Rule) {
	for _, rule := range self.Spec.Rules {
		if rule.match(reqFields) {
			return true, rule
		}
	}
	return false, nil
}

func (self *ProtectRule) Update(reqFields map[string]string, matchedRule *Rule) {
	results := self.Status.Results
	new_result := &Result{}
	new_result.update(reqFields, matchedRule)
	results = append(results, new_result)
	self.Status.Results = results
	return
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ProtectRuleList contains a list of ProtectRule
type ProtectRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProtectRule `json:"items"`
}

type Rule struct {
	Scope      *RulePattern `json:"scope,omitempty"`
	Namespace  *RulePattern `json:"namespace,omitempty"`
	ApiVersion *RulePattern `json:"apiVersion,omitempty"`
	Kind       *RulePattern `json:"kind,omitempty"`
	Name       *RulePattern `json:"name,omitempty"`
	User       *RulePattern `json:"user,omitempty"`
}

func (self *Rule) String() string {
	rB, _ := json.Marshal(self)
	return string(rB)
}

func (self *Rule) match(reqFields map[string]string) bool {
	v := reflect.Indirect(reflect.ValueOf(self))
	t := v.Type()
	matched := true
	patternCount := 0
	for i := 0; i < t.NumField(); i++ {
		fieldName := t.Field(i).Name
		f := v.Field(i)
		i := f.Interface()
		if value, ok := i.(*RulePattern); ok {
			if value != nil {
				pattern := value
				reqValue := reqFields[fieldName]
				patternCount += 1
				matched = matched && pattern.match(reqValue)
			}
		} else {
			continue
		}
	}
	return (patternCount > 0) && matched
}

type RulePattern string

func (self *RulePattern) match(value string) bool {
	if string(*self) == value {
		return true
	}
	return false
}

type Request struct {
	// Scope      string `json:"scope,omitempty"`
	Operation  string `json:"operation,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	ApiVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Name       string `json:"name,omitempty"`
	UserName   string `json:"userName,omitempty"`
}

func (self *Request) String() string {
	rB, _ := json.Marshal(self)
	return string(rB)
}

type Result struct {
	Request     string `json:"request,omitempty"`
	MatchedRule string `json:"matchedRule,omitempty"`
}

func (self *Result) update(reqFields map[string]string, matchedRule *Rule) {
	tmp := &Request{}
	v := reflect.Indirect(reflect.ValueOf(tmp))
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		fieldName := t.Field(i).Name
		f := v.Field(i)
		itf := f.Interface()
		if _, ok := itf.(string); ok {
			reqValue, ok2 := reqFields[fieldName]
			if ok2 {
				v.Field(i).SetString(reqValue)
			}
		} else {
			continue
		}
	}
	self.Request = tmp.String()
	self.MatchedRule = matchedRule.String()
	return
}
