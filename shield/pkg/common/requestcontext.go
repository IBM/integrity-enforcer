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
	admv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type RequestContext struct {
	ResourceScope  string   `json:"resourceScope,omitempty"`
	DryRun         bool     `json:"dryRun"`
	RequestJsonStr string   `json:"request"`
	RequestUid     string   `json:"requestUid"`
	Namespace      string   `json:"namespace"`
	Name           string   `json:"name"`
	ApiGroup       string   `json:"apiGroup"`
	ApiVersion     string   `json:"apiVersion"`
	Kind           string   `json:"kind"`
	Operation      string   `json:"operation"`
	UserInfo       string   `json:"userInfo"`
	UserName       string   `json:"userName"`
	UserGroups     []string `json:"userGroups"`
	Type           string   `json:"Type"`
}

type VRequestObject struct {
	RawObject       []byte          `json:"-"`
	RawOldObject    []byte          `json:"-"`
	OrgMetadata     *ObjectMetadata `json:"orgMetadata"`
	ClaimedMetadata *ObjectMetadata `json:"claimedMetadata"`
	ObjLabels       string          `json:"objLabels"`
	ObjMetaName     string          `json:"objMetaName"`
}

type ObjectMetadata struct {
	Annotations *ResourceAnnotation `json:"annotations"`
	Labels      *ResourceLabel      `json:"labels"`
}

func (reqc *RequestContext) ResourceRef() *ResourceRef {
	gv := schema.GroupVersion{
		Group:   reqc.ApiGroup,
		Version: reqc.ApiVersion,
	}
	return &ResourceRef{
		Name:       reqc.Name,
		Namespace:  reqc.Namespace,
		Kind:       reqc.Kind,
		ApiVersion: gv.String(),
	}
}

func (reqc *RequestContext) Map() map[string]string {
	m := map[string]string{}
	v := reflect.Indirect(reflect.ValueOf(reqc))
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

func (reqc *RequestContext) Info(m map[string]string) string {
	if m == nil {
		m = map[string]string{}
	}
	m["operation"] = reqc.Operation
	m["kind"] = reqc.Kind
	m["scope"] = reqc.ResourceScope
	m["namespace"] = reqc.Namespace
	m["name"] = reqc.Name
	m["userName"] = reqc.UserName
	m["request.uid"] = reqc.RequestUid
	infoBytes, _ := json.Marshal(m)
	return string(infoBytes)
}

func (reqc *RequestContext) GroupVersion() string {
	return schema.GroupVersion{Group: reqc.ApiGroup, Version: reqc.ApiVersion}.String()
}

func (rc *RequestContext) IsUpdateRequest() bool {
	return rc.Operation == "UPDATE"
}

func (rc *RequestContext) IsCreateRequest() bool {
	return rc.Operation == "CREATE"
}

func (rc *RequestContext) IsDeleteRequest() bool {
	return rc.Operation == "DELETE"
}

func (rc *RequestContext) IsSecret() bool {
	return rc.Kind == "Secret" && rc.GroupVersion() == "v1"
}

func (rc *RequestContext) IsServiceAccount() bool {
	return rc.Kind == "ServiceAccount" && rc.GroupVersion() == "v1"
}

func (rc *RequestContext) ExcludeDiffValue() bool {
	if rc.Kind == "Secret" {
		return true
	}
	return false
}

func AdmissionRequestToResourceContext(request *admv1.AdmissionRequest) *ResourceContext {
	var obj *unstructured.Unstructured
	_ = json.Unmarshal(request.Object.Raw, &obj)
	return NewResourceContext(obj)
}

type ParsedRequest struct {
	UID     string
	JsonStr string
}

func NewParsedRequest(request *admv1.AdmissionRequest) *ParsedRequest {
	var pr = &ParsedRequest{
		UID: string(request.UID),
	}
	if reqBytes, err := json.Marshal(request); err != nil {
		logger.WithFields(log.Fields{
			"err": err,
		}).Warn("Error when unmarshaling request object ")

	} else {
		pr.JsonStr = string(reqBytes)
	}
	return pr
}

func (pr *ParsedRequest) getValue(path string) string {
	var v string
	if w := gjson.Get(pr.JsonStr, path); w.Exists() {
		v = w.String()
	}
	return v
}

func (pr *ParsedRequest) getArrayValue(path string) []string {
	var v []string
	if w := gjson.Get(pr.JsonStr, path); w.Exists() {
		x := w.Array()
		for _, xi := range x {
			v = append(v, xi.String())
		}
	}
	return v
}

func (pr *ParsedRequest) getAnnotations(path string) *ResourceAnnotation {
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

func (pr *ParsedRequest) getLabels(path string) *ResourceLabel {
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

func (pr *ParsedRequest) getBool(path string, defaultValue bool) bool {
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

func NewRequestContext(req *admv1.AdmissionRequest) (*RequestContext, *VRequestObject) {

	pr := NewParsedRequest(req)

	name := pr.getValue("name")
	if name == "" {
		name = pr.getValue("metadata.name")
	}
	if name == "" {
		name = pr.getValue("object.metadata.name")
	}

	namespace := pr.getValue("namespace")
	if namespace == "" {
		namespace = pr.getValue("object.metdata.namespace")
	}

	orgMetadata := &ObjectMetadata{
		Annotations: pr.getAnnotations("oldObject.metadata.annotations"),
		Labels:      pr.getLabels("oldObject.metadata.labels"),
	}

	claimedMetadata := &ObjectMetadata{
		Annotations: pr.getAnnotations("object.metadata.annotations"),
		Labels:      pr.getLabels("object.metadata.labels"),
	}

	kind := pr.getValue("kind.kind")

	resourceScope := "Namespaced"
	if namespace == "" {
		resourceScope = "Cluster"
	}

	rc := &RequestContext{
		DryRun:         *req.DryRun,
		ResourceScope:  resourceScope,
		RequestUid:     pr.UID,
		RequestJsonStr: pr.JsonStr,
		Name:           name,
		Operation:      pr.getValue("operation"),
		ApiGroup:       pr.getValue("kind.group"),
		ApiVersion:     pr.getValue("kind.version"),
		Kind:           kind,
		Namespace:      namespace,
		UserInfo:       pr.getValue("userInfo"),
		UserName:       pr.getValue("userInfo.username"),
		UserGroups:     pr.getArrayValue("userInfo.groups"),
		Type:           pr.getValue("object.type"),
	}
	ro := &VRequestObject{
		RawObject:       req.Object.Raw,
		RawOldObject:    req.OldObject.Raw,
		ObjLabels:       pr.getValue("object.metadata.labels"),
		ObjMetaName:     pr.getValue("object.metadata.name"),
		OrgMetadata:     orgMetadata,
		ClaimedMetadata: claimedMetadata,
	}
	return rc, ro

}
