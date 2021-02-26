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
	"encoding/json"
	"reflect"
	"regexp"
	"strings"

	"github.com/jinzhu/copier"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type CommonProfile struct {
	IgnoreRules []*Rule         `json:"ignoreRules,omitempty"`
	IgnoreAttrs []*AttrsPattern `json:"ignoreAttrs,omitempty"`
}

type Rule struct {
	Match   []*RequestPattern `json:"match,omitempty"`
	Exclude []*RequestPattern `json:"exclude,omitempty"`
}

type RequestPattern struct {
	Scope *RulePattern `json:"scope,omitempty"`
	// Namespace  *RulePattern `json:"namespace,omitempty"`
	ApiGroup   *RulePattern `json:"apiGroup,omitempty"`
	ApiVersion *RulePattern `json:"apiVersion,omitempty"`
	Kind       *RulePattern `json:"kind,omitempty"`
	Name       *RulePattern `json:"name,omitempty"`
	Operation  *RulePattern `json:"operation,omitempty"`
	UserName   *RulePattern `json:"username,omitempty"`
	UserGroup  *RulePattern `json:"usergroup,omitempty"`
}

type KustomizePattern struct {
	Match      []*RequestPattern `json:"match,omitempty"`
	NamePrefix *RulePattern      `json:"namePrefix,omitempty"`
	NameSuffix *RulePattern      `json:"nameSuffix,omitempty"`
}

type RequestPatternWithNamespace struct {
	*RequestPattern `json:""`
	Namespace       *RulePattern `json:"namespace,omitempty"`
}

func (self *RequestPatternWithNamespace) Match(reqFields map[string]string) bool {
	if self.Namespace == nil && self.RequestPattern == nil {
		return false
	}
	nsMatched := true
	if self.Namespace != nil {
		if !MatchPattern(string(*self.Namespace), reqFields["Namespace"]) {
			nsMatched = false
		}
	}
	otherMatched := true
	if self.RequestPattern != nil {
		otherMatched = self.RequestPattern.Match(reqFields)
	}
	return nsMatched && otherMatched
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

func (self *Rule) StrictMatchWithRequest(reqFields map[string]string) bool {
	matched := false
	for _, m := range self.Match {
		if m.StrictMatch(reqFields) {
			matched = true
			break
		}
	}
	excluded := false
	if matched {
		for _, ex := range self.Exclude {
			if ex.StrictMatch(reqFields) {
				excluded = true
				break
			}
		}
	}

	return matched && !excluded
}

// match the input request with pattern, allow wildcard for resource name
func (self *RequestPattern) Match(reqFields map[string]string) bool {
	return self.match(reqFields, false)
}

// match the input request with pattern, exact match for resource name
func (self *RequestPattern) StrictMatch(reqFields map[string]string) bool {
	return self.match(reqFields, true)
}

func (self *RequestPattern) match(reqFields map[string]string, exactMatchForName bool) bool {
	scope := "Namespaced"
	if reqScope, ok := reqFields["ResourceScope"]; ok && reqScope == "Cluster" {
		scope = reqScope
	}

	if exactMatchForName && scope == "Cluster" && self.Name == nil {
		return false
	}

	p := reflect.ValueOf(self)
	if p.IsNil() {
		return false
	}
	v := reflect.Indirect(p)
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
				if fieldName == "Name" && exactMatchForName {
					matched = matched && pattern.exactMatch(reqValue)
				} else {
					matched = matched && pattern.match(reqValue)
				}
			}
		} else {
			continue
		}
	}
	return (patternCount > 0) && matched
}

type RulePattern string

func (self *RulePattern) match(value string) bool {
	return MatchPattern(string(*self), value)
}

func (self *RulePattern) exactMatch(value string) bool {
	return ExactMatch(string(*self), value)
}

// reverse the string
func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func (self *KustomizePattern) OverrideName(ref *ResourceRef) *ResourceRef {
	name := ref.Name
	if self.NamePrefix == nil && self.NameSuffix == nil {
		return ref
	}
	if self.NamePrefix != nil {
		namePrefix := string(*self.NamePrefix)
		if strings.HasPrefix(name, namePrefix) {
			name = strings.Replace(name, namePrefix, "", 1)
		} else if strings.Contains(namePrefix, "*") {
			// strings.HasPrefix can not match with wildcard, so use reqexp here
			if strings.Contains(namePrefix, ".") {
				namePrefix = strings.Replace(namePrefix, ".", "\\.", -1)
			}
			namePrefix = strings.Replace(namePrefix, "*", ".*", -1)
			if ok, _ := regexp.Match(namePrefix, []byte(name)); ok {
				if rep, err := regexp.Compile(namePrefix); err == nil {
					name = rep.ReplaceAllString(name, "")
				}
			}
		}
	}

	if self.NameSuffix != nil {
		nameSuffix := string(*self.NameSuffix)
		if strings.HasSuffix(name, nameSuffix) {
			revName := reverse(name)
			revSuffix := reverse(nameSuffix)
			revName = strings.Replace(revName, revSuffix, "", 1)
			name = reverse(revName)
		} else if strings.Contains(nameSuffix, "*") {
			// strings.HasSuffix can not match with wildcard, so use reqexp here
			if strings.Contains(nameSuffix, ".") {
				nameSuffix = strings.Replace(nameSuffix, ".", "\\.", -1)
			}
			nameSuffix = strings.Replace(nameSuffix, "*", ".*", -1)
			if ok, _ := regexp.Match(nameSuffix, []byte(name)); ok {
				if rep, err := regexp.Compile(nameSuffix); err == nil {
					name = rep.ReplaceAllString(name, "")
				}
			}
		}
	}
	ref.Name = name
	return ref
}

func (self *KustomizePattern) MatchWith(reqFields map[string]string) bool {
	for _, reqPattern := range self.Match {
		if reqPattern.Match(reqFields) {
			return true
		}
	}
	return false
}

type ServiceAccountPattern struct {
	Match               *RequestPatternWithNamespace `json:"match,omitempty"`
	Except              *RequestPatternWithNamespace `json:"except,omitempty"`
	ServiceAccountNames []string                     `json:"serviceAccountNames,omitempty"`
}

type AttrsPattern struct {
	Match []*RequestPattern `json:"match,omitempty"`
	Attrs []string          `json:"attrs,omitempty"`
}

func (self *AttrsPattern) MatchWith(reqFields map[string]string) bool {
	for _, reqPattern := range self.Match {
		if reqPattern.Match(reqFields) {
			return true
		}
	}
	return false
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

func (self *Request) GroupVersionKind() string {
	gvk := schema.GroupVersionKind{
		Group:   self.ApiGroup,
		Version: self.ApiVersion,
		Kind:    self.Kind,
	}
	return gvk.String()
}

func (self *Request) Equal(req *Request) bool {
	return reflect.DeepEqual(self, req)
}

func NewRequestFromReqContext(reqc *ReqContext) *Request {
	req := &Request{
		Operation:  reqc.Operation,
		Namespace:  reqc.Namespace,
		ApiGroup:   reqc.ApiGroup,
		ApiVersion: reqc.ApiVersion,
		Kind:       reqc.Kind,
		Name:       reqc.Name,
		UserName:   reqc.UserName,
	}
	return req
}

type Result struct {
	Message   string `json:"message,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
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

func (p *KustomizePattern) DeepCopyInto(p2 *KustomizePattern) {
	copier.Copy(&p2, &p)
}

func (p *KustomizePattern) DeepCopy() *KustomizePattern {
	p2 := &KustomizePattern{}
	p.DeepCopyInto(p2)
	return p2
}

func (p *ServiceAccountPattern) DeepCopyInto(p2 *ServiceAccountPattern) {
	copier.Copy(&p2, &p)
}

func (p *ServiceAccountPattern) DeepCopy() *ServiceAccountPattern {
	p2 := &ServiceAccountPattern{}
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
