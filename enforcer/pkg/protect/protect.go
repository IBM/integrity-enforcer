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

package protect

import (
	"encoding/json"
	"reflect"

	"github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
	"github.com/jinzhu/copier"
)

type Rule struct {
	Match   []*RequestPattern `json:"match,omitempty"`
	Exclude []*RequestPattern `json:"exclude,omitempty"`
}

type RequestPattern struct {
	Scope      *RulePattern `json:"scope,omitempty"`
	Namespace  *RulePattern `json:"namespace,omitempty"`
	ApiGroup   *RulePattern `json:"apiGroup,omitempty"`
	ApiVersion *RulePattern `json:"apiVersion,omitempty"`
	Kind       *RulePattern `json:"kind,omitempty"`
	Name       *RulePattern `json:"name,omitempty"`
	Operation  *RulePattern `json:"operation,omitempty"`
	UserName   *RulePattern `json:"username,omitempty"`
	UserGroup  *RulePattern `json:"usergroup,omitempty"`
}

func (self *Rule) String() string {
	rB, _ := json.Marshal(self)
	return string(rB)
}

func (self *Rule) MatchWithRequest(reqFields map[string]string) bool {
	matched := false
	for _, m := range self.Match {
		if m.Match(reqFields) {
			matched = true
			break
		}
	}
	excluded := false
	if matched {
		for _, ex := range self.Exclude {
			if ex.Match(reqFields) {
				excluded = true
				break
			}
		}
	}

	return matched && !excluded
}

func (self *RequestPattern) Match(reqFields map[string]string) bool {
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
	return common.MatchPattern(string(*self), value)
}

type ServieAccountPattern struct {
	Match              *RequestPattern `json:"match,omitempty"`
	ServiceAccountName []string        `json:"serviceAccountName,omitempty"`
}

type AttrsPattern struct {
	Match *RequestPattern `json:"match,omitempty"`
	Attrs []string        `json:"attrs,omitempty"`
}

type Request struct {
	// Scope      string `json:"scope,omitempty"`
	Operation  string `json:"operation,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	ApiGroup   string `json:"apiGroup,omitempty"`
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

func (self *Result) Update(reqFields map[string]string, matchedRule *Rule) {
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

func (p *Rule) DeepCopyInto(p2 *Rule) {
	copier.Copy(&p2, &p)
}

func (p *Rule) DeepCopy() *Rule {
	p2 := &Rule{}
	p.DeepCopyInto(p2)
	return p2
}

func (p *RequestPattern) DeepCopyInto(p2 *RequestPattern) {
	copier.Copy(&p2, &p)
}

func (p *RequestPattern) DeepCopy() *RequestPattern {
	p2 := &RequestPattern{}
	p.DeepCopyInto(p2)
	return p2
}

func (p *ServieAccountPattern) DeepCopyInto(p2 *ServieAccountPattern) {
	copier.Copy(&p2, &p)
}

func (p *ServieAccountPattern) DeepCopy() *ServieAccountPattern {
	p2 := &ServieAccountPattern{}
	p.DeepCopyInto(p2)
	return p2
}

func (p *AttrsPattern) DeepCopyInto(p2 *AttrsPattern) {
	copier.Copy(&p2, &p)
}

func (p *AttrsPattern) DeepCopy() *AttrsPattern {
	p2 := &AttrsPattern{}
	p.DeepCopyInto(p2)
	return p2
}

func (p *Result) DeepCopyInto(p2 *Result) {
	copier.Copy(&p2, &p)
}

func (p *Result) DeepCopy() *Result {
	p2 := &Result{}
	p.DeepCopyInto(p2)
	return p2
}
