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
	"strconv"

	log "github.com/sirupsen/logrus"
	gjson "github.com/tidwall/gjson"

	logger "github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type V2ResourceContext struct {
	ResourceScope   string            `json:"resourceScope,omitempty"`
	RawObject       []byte            `json:"-"`
	Namespace       string            `json:"namespace"`
	Name            string            `json:"name"`
	ApiGroup        string            `json:"apiGroup"`
	ApiVersion      string            `json:"apiVersion"`
	Kind            string            `json:"kind"`
	ClaimedMetadata *V2ObjectMetadata `json:"claimedMetadata"`
	ObjLabels       string            `json:"objLabels"`
	ObjMetaName     string            `json:"objMetaName"`
}

type V2ObjectMetadata struct {
	Annotations *ResourceAnnotation `json:"annotations"`
	Labels      *ResourceLabel      `json:"labels"`
}

func (v2resc *V2ResourceContext) ResourceRef() *ResourceRef {
	gv := schema.GroupVersion{
		Group:   v2resc.ApiGroup,
		Version: v2resc.ApiVersion,
	}
	return &ResourceRef{
		Name:       v2resc.Name,
		Namespace:  v2resc.Namespace,
		Kind:       v2resc.Kind,
		ApiVersion: gv.String(),
	}
}

func (v2resc *V2ResourceContext) Map() map[string]string {
	m := map[string]string{}
	v := reflect.Indirect(reflect.ValueOf(v2resc))
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := v.Field(i)
		itf := f.Interface()
		if value, ok := itf.(string); ok {
			filedName := t.Field(i).Name
			m[filedName] = value
		} else {
			continue
		}
	}
	return m
}

func (v2resc *V2ResourceContext) Info(m map[string]string) string {
	if m == nil {
		m = map[string]string{}
	}
	m["kind"] = v2resc.Kind
	m["scope"] = v2resc.ResourceScope
	m["namespace"] = v2resc.Namespace
	m["name"] = v2resc.Name
	infoBytes, _ := json.Marshal(m)
	return string(infoBytes)
}

func (v2resc *V2ResourceContext) GroupVersion() string {
	return schema.GroupVersion{Group: v2resc.ApiGroup, Version: v2resc.ApiVersion}.String()
}

func (rc *V2ResourceContext) IsSecret() bool {
	return rc.Kind == "Secret" && rc.GroupVersion() == "v1"
}

func (rc *V2ResourceContext) IsServiceAccount() bool {
	return rc.Kind == "ServiceAccount" && rc.GroupVersion() == "v1"
}

func (rc *V2ResourceContext) ExcludeDiffValue() bool {
	if rc.Kind == "Secret" {
		return true
	}
	return false
}

type V2ParsedRequest struct {
	JsonStr string
}

func NewV2ParsedRequest(resource *unstructured.Unstructured) *V2ParsedRequest {
	var pr = &V2ParsedRequest{}
	if resBytes, err := json.Marshal(resource); err != nil {
		logger.WithFields(log.Fields{
			"err": err,
		}).Warn("Error when unmarshaling resource object ")

	} else {
		pr.JsonStr = string(resBytes)
	}
	return pr
}

func (pr *V2ParsedRequest) getValue(path string) string {
	var v string
	if w := gjson.Get(pr.JsonStr, path); w.Exists() {
		v = w.String()
	}
	return v
}

func (pr *V2ParsedRequest) getArrayValue(path string) []string {
	var v []string
	if w := gjson.Get(pr.JsonStr, path); w.Exists() {
		x := w.Array()
		for _, xi := range x {
			v = append(v, xi.String())
		}
	}
	return v
}

func (pr *V2ParsedRequest) getAnnotations(path string) *ResourceAnnotation {
	var r map[string]string = map[string]string{}
	if w := gjson.Get(pr.JsonStr, path); w.Exists() {
		m := w.Map()
		for k := range m {
			v := m[k]
			r[k] = v.String()
		}
	}
	return &ResourceAnnotation{
		values: r,
	}
}

func (pr *V2ParsedRequest) getLabels(path string) *ResourceLabel {
	var r map[string]string = map[string]string{}
	if w := gjson.Get(pr.JsonStr, path); w.Exists() {
		m := w.Map()
		for k := range m {
			v := m[k]
			r[k] = v.String()
		}
	}
	return &ResourceLabel{
		values: r,
	}
}

func (pr *V2ParsedRequest) getBool(path string, defaultValue bool) bool {
	if w := gjson.Get(pr.JsonStr, path); w.Exists() {
		v := w.String()
		if b, err := strconv.ParseBool(v); err != nil {
			return defaultValue
		} else {
			return b
		}
	}
	return defaultValue
}

func NewV2ResourceContext(res *unstructured.Unstructured) *V2ResourceContext {

	pr := NewV2ParsedRequest(res)

	name := pr.getValue("name")
	if name == "" {
		name = pr.getValue("metadata.name")
	}

	namespace := pr.getValue("namespace")
	if namespace == "" {
		namespace = pr.getValue("metadata.namespace")
	}

	claimedMetadata := &V2ObjectMetadata{
		Annotations: pr.getAnnotations("metadata.annotations"),
		Labels:      pr.getLabels("metadata.labels"),
	}
	metaLabelObj := claimedMetadata.Labels
	labelsBytes, _ := json.Marshal(metaLabelObj.values)
	labelsStr := ""
	if labelsBytes != nil {
		labelsStr = string(labelsBytes)
	}

	kind := pr.getValue("kind")
	groupVersion := pr.getValue("apiVersion")
	gv, _ := schema.ParseGroupVersion(groupVersion)
	apiGroup := gv.Group
	apiVersion := gv.Version

	resourceScope := "Namespaced"
	if namespace == "" {
		resourceScope = "Cluster"
	}

	resBytes, _ := json.Marshal(res)

	rc := &V2ResourceContext{
		RawObject:       resBytes,
		ResourceScope:   resourceScope,
		Name:            name,
		ApiGroup:        apiGroup,
		ApiVersion:      apiVersion,
		Kind:            kind,
		Namespace:       namespace,
		ObjLabels:       labelsStr,
		ObjMetaName:     name,
		ClaimedMetadata: claimedMetadata,
	}
	return rc

}
