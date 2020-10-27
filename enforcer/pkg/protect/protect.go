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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
	"github.com/IBM/integrity-enforcer/enforcer/pkg/kubeutil"
	"github.com/jinzhu/copier"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

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
	RequestPattern
	Namespace *RulePattern `json:"namespace,omitempty"`
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
	scope := "Namespaced"
	if reqScope, ok := reqFields["ResourceScope"]; ok && reqScope == "Cluster" {
		scope = reqScope
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
				if scope == "Cluster" && fieldName == "Name" {
					matched = matched && pattern.exactMatch(reqValue) // "*" is not allowed for Name pattern of cluster scope object
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
	return common.MatchPattern(string(*self), value)
}

func (self *RulePattern) exactMatch(value string) bool {
	return common.ExactMatch(string(*self), value)
}

// reverse the string
func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func (self *KustomizePattern) OverrideName(ref *common.ResourceRef) *common.ResourceRef {
	name := ref.Name
	if self.NamePrefix == nil && self.NameSuffix == nil {
		return ref
	}
	if self.NamePrefix != nil {
		namePrefix := string(*self.NamePrefix)
		if strings.HasPrefix(name, namePrefix) {
			name = strings.Replace(name, namePrefix, "", 1)
		}
	}

	if self.NameSuffix != nil {
		nameSuffix := string(*self.NameSuffix)
		if strings.HasSuffix(name, nameSuffix) {
			revName := reverse(name)
			revSuffix := reverse(nameSuffix)
			revName = strings.Replace(revName, revSuffix, "", 1)
			name = reverse(revName)
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

func (self *Request) Equal(req *Request) bool {
	return reflect.DeepEqual(self, req)
}

func NewRequestFromReqContext(reqc *common.ReqContext) *Request {
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

type SigningProfile interface {
	Match(reqFields map[string]string) (bool, *Rule)
	Kustomize(reqFields map[string]string) []*KustomizePattern
	ProtectAttrs(reqFields map[string]string) []*AttrsPattern
	UnprotectAttrs(reqFields map[string]string) []*AttrsPattern
	IgnoreAttrs(reqFields map[string]string) []*AttrsPattern
}

// RuleTable

const ruleTableDumpFileName = "/tmp/rule_table"

type RuleTable []RuleItem

type RuleItem struct {
	Rule   *Rule               `json:"rule,omitempty"`
	Source *v1.ObjectReference `json:"source,omitempty"`
}

func (self *RuleTable) Update(namespace, name string) error {
	rawData, err := json.Marshal(self)
	if err != nil {
		return err
	}
	fmt.Println("[RuleTable]", string(rawData))

	config, _ := kubeutil.GetKubeConfig()
	coreV1Client, err := v1client.NewForConfig(config)
	if err != nil {
		return err
	}

	cm, err := coreV1Client.ConfigMaps(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	var gzipBuffer bytes.Buffer
	writer := gzip.NewWriter(&gzipBuffer)
	writer.Write(rawData)
	writer.Close()
	zipData := gzipBuffer.Bytes()

	cm.BinaryData["table"] = zipData
	_, err = coreV1Client.ConfigMaps(namespace).Update(context.Background(), cm, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func GetRuleTable(namespace, name string) (*RuleTable, error) {
	t := NewRuleTable()
	newTable, err := t.Get(namespace, name)
	if err != nil {
		return nil, err
	}
	return newTable, nil
}

func (self *RuleTable) Get(namespace, name string) (*RuleTable, error) {

	config, _ := kubeutil.GetKubeConfig()
	coreV1Client, err := v1client.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	cm, err := coreV1Client.ConfigMaps(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	zipData := cm.BinaryData["table"]

	gzipBuffer := bytes.NewBuffer(zipData)
	reader, _ := gzip.NewReader(gzipBuffer)
	output := bytes.Buffer{}
	output.ReadFrom(reader)
	rawData := output.Bytes()

	var t *RuleTable
	err = json.Unmarshal(rawData, &t)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func NewRuleTable() *RuleTable {
	items := []RuleItem{}
	newTable := RuleTable(items)
	return &newTable
}

func (self *RuleTable) Add(rules []*Rule, source *v1.ObjectReference) *RuleTable {
	newTable := *self
	for _, rule := range rules {
		newTable = append(newTable, RuleItem{Rule: rule, Source: source})
	}
	return &newTable
}

func (self *RuleTable) Merge(data *RuleTable) *RuleTable {
	newTable := *self
	for _, item := range *data {
		newTable = append(newTable, item)
	}
	return &newTable
}

func (self *RuleTable) Remove(subject *v1.ObjectReference) *RuleTable {
	items := []RuleItem{}
	for _, item := range *self {
		if item.Source.APIVersion == subject.APIVersion &&
			item.Source.Kind == subject.Kind &&
			item.Source.Name == subject.Name &&
			item.Source.Namespace == subject.Namespace {
			continue
		}
		items = append(items, item)
	}
	newTable := RuleTable(items)
	return &newTable
}

func (self *RuleTable) Match(reqFields map[string]string) (bool, []*v1.ObjectReference) {
	matchedSources := []*v1.ObjectReference{}
	for _, item := range *self {
		if item.Match(reqFields) {
			matchedSources = append(matchedSources, item.Source)
		}
	}
	if len(matchedSources) == 0 {
		return false, matchedSources
	}
	return true, matchedSources
}

func (self *RuleItem) Match(reqFields map[string]string) bool {
	reqNamespace := ""
	if tmp, ok := reqFields["Namespace"]; ok && tmp != "" {
		reqNamespace = tmp
	}
	// if namespaced scope request, use only rules from the namespace
	if reqNamespace != "" {
		if self.Source.Namespace != reqNamespace {
			return false
		}
	}
	return self.Rule.MatchWithRequest(reqFields)
}
