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

package loader

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"

	rspapi "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourcesigningprofile/v1alpha1"
	"github.com/IBM/integrity-enforcer/enforcer/pkg/common/common"
	profile "github.com/IBM/integrity-enforcer/enforcer/pkg/common/profile"
	kubeutil "github.com/IBM/integrity-enforcer/enforcer/pkg/util/kubeutil"
	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/util/logger"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

// RuleTable
const ruleTableDumpFileName = "/tmp/rule_table"

type RuleTableType string

const (
	RuleTableTypeProtect RuleTableType = "RuleTable"
	RuleTableTypeIgnore  RuleTableType = "IgnoreRuleTable"
	RuleTableTypeForce   RuleTableType = "ForceCheckRuleTable"
)

type RuleTable []RuleItem

type RuleItem struct {
	Rule       *profile.Rule       `json:"rule,omitempty"`
	Source     *v1.ObjectReference `json:"source,omitempty"`
	Namespaces []string            `json:"namespaces,omitempty"`
}

func (self *RuleTable) Update(namespace, name string) error {
	rawData, err := json.Marshal(self)
	if err != nil {
		return err
	}

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

	currentZipData := cm.BinaryData["table"]
	if !bytes.Equal(currentZipData, zipData) {
		cm.BinaryData["table"] = zipData
		_, err = coreV1Client.ConfigMaps(namespace).Update(context.Background(), cm, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
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

func (self *RuleTable) Add(rules []*profile.Rule, source *v1.ObjectReference, namespaces []string) *RuleTable {
	newTable := *self
	for _, rule := range rules {
		newTable = append(newTable, RuleItem{Rule: rule, Source: source, Namespaces: namespaces})
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

func (self *RuleTable) NamespaceList(enforcerNamespace string) []string {
	namespaceList := []string{}
	for _, item := range *self {
		namespaceList = common.GetUnionOfArrays(namespaceList, item.Namespaces)
	}
	return namespaceList
}

func (self *RuleTable) Match(reqFields map[string]string, enforcerNS string) (bool, []*v1.ObjectReference) {
	matchedSources := []*v1.ObjectReference{}
	for _, item := range *self {
		if item.Match(reqFields, enforcerNS) {
			matchedSources = append(matchedSources, item.Source)
		}
	}
	if len(matchedSources) == 0 {
		return false, matchedSources
	}
	return true, matchedSources
}

func (self *RuleItem) Match(reqFields map[string]string, enforcerNS string) bool {
	reqNamespace := ""
	if tmp, ok := reqFields["Namespace"]; ok && tmp != "" {
		reqNamespace = tmp
	}
	// ignore this RuleItem if the namaespace is different
	if !self.CheckNamespace(reqNamespace, enforcerNS) {
		return false
	}
	// if namespace is matched, evaluate rules with the request
	return self.Rule.MatchWithRequest(reqFields)
}

func (self *RuleItem) CheckNamespace(reqNamespace, enforcerNamespace string) bool {
	namespaceMatched := false
	if reqNamespace != "" {
		namespaceMatched = common.ExactMatchWithPatternArray(reqNamespace, self.Namespaces)
	} else {
		// for cluster scope request, all RSPs are available
		namespaceMatched = true
	}
	return namespaceMatched
}

func NewRuleTableFromProfile(sProfile rspapi.ResourceSigningProfile, tableType RuleTableType, enforcerNamespace string) *RuleTable {
	gvk := sProfile.GroupVersionKind()
	source := &v1.ObjectReference{
		APIVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		Namespace:  sProfile.GetNamespace(),
		Name:       sProfile.GetName(),
	}
	table := NewRuleTable()
	var namespaces []string
	if source.Namespace == enforcerNamespace && sProfile.Spec.TargetNamespaceSelector != nil {
		targetNs := sProfile.Spec.TargetNamespaceSelector

		listOptions := metav1.ListOptions{}
		if targetNs.LabelSelector != nil {
			listOptions.LabelSelector = metav1.FormatLabelSelector(targetNs.LabelSelector)
		}

		config, _ := kubeutil.GetKubeConfig()
		coreV1Client, err := v1client.NewForConfig(config)
		if err != nil {
			logger.Error("Failed to NewForConfig(); ", err.Error())
		}

		namespaceList, err := coreV1Client.Namespaces().List(context.Background(), listOptions)
		if err != nil {
			logger.Error("Failed to get namespaces; ", err.Error())
		}

		matchedNamespaceList := []string{}
		for _, ns := range namespaceList.Items {
			if (len(targetNs.Include) == 0 && len(targetNs.Exclude) == 0) || targetNs.MatchNamespace(ns.GetName()) {
				matchedNamespaceList = append(matchedNamespaceList, ns.GetName())
			}
		}
		namespaces = matchedNamespaceList
	} else {
		namespaces = append(namespaces, source.Namespace)
	}
	if tableType == RuleTableTypeProtect {
		table = table.Add(sProfile.Spec.ProtectRules, source, namespaces)
	} else if tableType == RuleTableTypeIgnore {
		table = table.Add(sProfile.Spec.IgnoreRules, source, namespaces)
	} else if tableType == RuleTableTypeForce {
		table = table.Add(sProfile.Spec.ForceCheckRules, source, namespaces)
	}

	return table
}
