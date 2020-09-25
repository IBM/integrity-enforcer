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
	"fmt"
	"reflect"
	"strconv"

	log "github.com/sirupsen/logrus"
	gjson "github.com/tidwall/gjson"

	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/logger"
	v1beta1 "k8s.io/api/admission/v1beta1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	HashTypeDefault      = "default"
	HashTypeHelmSecret   = "helmSecret"
	HashTypeHelmResource = "helmResource"
)

type IntegrityValue struct {
	ServiceAccount string `json:"spec.maIntegrity.serviceAccount"`
	Signature      string `json:"spec.maIntegrity.signature"`
}

type ObjectMetadata struct {
	K8sCreatedBy          string              `json:"k8sCreatedBy"`
	K8sServiceAccountName string              `json:"k8sServiceAccountName"`
	K8sServiceAccountUid  string              `json:"k8sServiceAccountUid"`
	OwnerRef              *ResourceRef        `json:"ownerRef"`
	Annotations           *ResourceAnnotation `json:"annotations"`
	Labels                *ResourceLabel      `json:"labels"`
}

type ReqContext struct {
	ResourceScope   string          `json:"resourceScope,omitempty"`
	DryRun          bool            `json:"dryRun"`
	RawObject       []byte          `json:"-"`
	RawOldObject    []byte          `json:"-"`
	RequestJsonStr  string          `json:"request"`
	RequestUid      string          `json:"requestUid"`
	Namespace       string          `json:"namespace"`
	Name            string          `json:"name"`
	ApiGroup        string          `json:"apiGroup"`
	ApiVersion      string          `json:"apiVersion"`
	Kind            string          `json:"kind"`
	Operation       string          `json:"operation"`
	IntegrityValue  *IntegrityValue `json:"integrityValues"`
	OrgMetadata     *ObjectMetadata `json:"orgMetadata"`
	ClaimedMetadata *ObjectMetadata `json:"claimedMetadata"`
	UserInfo        string          `json:"userInfo"`
	ObjLabels       string          `json:"objLabels"`
	ObjMetaName     string          `json:"objMetaName"`
	UserName        string          `json:"userName"`
	UserGroups      []string        `json:"userGroups"`
	Type            string          `json:"Type"`
	ObjectHashType  string          `json:"objectHashType"`
	ObjectHash      string          `json:"objectHash"`
}

func (reqc *ReqContext) OwnerRef() *ResourceRef {
	if reqc.IsCreateRequest() {
		return reqc.ClaimedMetadata.OwnerRef
	} else if reqc.IsUpdateRequest() || reqc.IsDeleteRequest() {
		return reqc.OrgMetadata.OwnerRef
	} else {
		return nil
	}
}

func (reqc *ReqContext) ResourceRef() *ResourceRef {
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

func (reqc *ReqContext) Map() map[string]string {
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

func (reqc *ReqContext) GroupVersion() string {
	return schema.GroupVersion{Group: reqc.ApiGroup, Version: reqc.ApiVersion}.String()
}

func (rc *ReqContext) IsUpdateRequest() bool {
	return rc.Operation == "UPDATE"
}

func (rc *ReqContext) IsCreateRequest() bool {
	return rc.Operation == "CREATE"
}

func (rc *ReqContext) IsDeleteRequest() bool {
	return rc.Operation == "DELETE"
}

func (rc *ReqContext) IsCreator() bool {
	return rc.UserName != "" && rc.UserName == rc.OrgMetadata.Annotations.CreatedBy()
}

func (rc *ReqContext) IsEnforcePolicyRequest() bool {
	return rc.GroupVersion() == PolicyCustomResourceAPIVersion && rc.Kind == PolicyCustomResourceKind
}

func (rc *ReqContext) IsIEPolicyRequest() bool {
	return rc.GroupVersion() == IEPolicyCustomResourceAPIVersion && rc.Kind == IEPolicyCustomResourceKind
}

func (rc *ReqContext) IsIEDefaultPolicyRequest() bool {
	return rc.GroupVersion() == DefaultPolicyCustomResourceAPIVersion && rc.Kind == DefaultPolicyCustomResourceKind
}

func (rc *ReqContext) IsSignPolicyRequest() bool {
	return rc.GroupVersion() == SignerPolicyCustomResourceAPIVersion && rc.Kind == SignerPolicyCustomResourceKind
}

func (rc *ReqContext) IsAppEnforcePolicyRequest() bool {
	return rc.GroupVersion() == AppPolicyCustomResourceAPIVersion && rc.Kind == AppPolicyCustomResourceKind
}

func (rc *ReqContext) IsResourceSignatureRequest() bool {
	return rc.GroupVersion() == SignatureCustomResourceAPIVersion && rc.Kind == SignatureCustomResourceKind
}

func (rc *ReqContext) IsSecret() bool {
	return rc.Kind == "Secret" && rc.GroupVersion() == "v1"
}

func (rc *ReqContext) IsServiceAccount() bool {
	return rc.Kind == "ServiceAccount" && rc.GroupVersion() == "v1"
}

type ParsedRequest struct {
	UID     string
	JsonStr string
}

func NewParsedRequest(request *v1beta1.AdmissionRequest) *ParsedRequest {
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

func NewReqContext(req *v1beta1.AdmissionRequest) *ReqContext {

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

	integrityValues := &IntegrityValue{
		ServiceAccount: pr.getValue("object.spec.maIntegrity.serviceAccount"),
		Signature:      pr.getValue("object.spec.maIntegrity.signature"),
	}

	orgMetadata := &ObjectMetadata{
		K8sCreatedBy:          pr.getValue("oldObject.metadata.annotations.kubernetes\\.io/created-by"),
		K8sServiceAccountName: pr.getValue("oldObject.metadata.annotations.kubernetes\\.io/service-account\\.name"),
		K8sServiceAccountUid:  pr.getValue("oldObject.metadata.annotations.kubernetes\\.io/service-account\\.uid"),
		Annotations:           pr.getAnnotations("oldObject.metadata.annotations"),
		Labels:                pr.getLabels("oldObject.metadata.labels"),
		OwnerRef: &ResourceRef{
			Kind:       pr.getValue("oldObject.metadata.ownerReferences.0.kind"),
			Name:       pr.getValue("oldObject.metadata.ownerReferences.0.name"),
			Namespace:  namespace,
			ApiVersion: pr.getValue("oldObject.metadata.ownerReferences.0.apiVersion"),
		},
	}

	claimedMetadata := &ObjectMetadata{
		Annotations: pr.getAnnotations("object.metadata.annotations"),
		Labels:      pr.getLabels("object.metadata.labels"),
		OwnerRef: &ResourceRef{
			Kind:       pr.getValue("object.metadata.ownerReferences.0.kind"),
			Name:       pr.getValue("object.metadata.ownerReferences.0.name"),
			Namespace:  namespace,
			ApiVersion: pr.getValue("object.metadata.ownerReferences.0.apiVersion"),
		},
	}

	kind := pr.getValue("kind.kind")

	resourceScope := "Namespaced"
	if namespace == "" {
		resourceScope = "Cluster"
	}

	rc := &ReqContext{
		DryRun:          *req.DryRun,
		RawObject:       req.Object.Raw,
		RawOldObject:    req.OldObject.Raw,
		ResourceScope:   resourceScope,
		RequestUid:      pr.UID,
		RequestJsonStr:  pr.JsonStr,
		Name:            name,
		Operation:       pr.getValue("operation"),
		IntegrityValue:  integrityValues,
		ApiGroup:        pr.getValue("kind.group"),
		ApiVersion:      pr.getValue("kind.version"),
		Kind:            kind,
		Namespace:       namespace,
		UserInfo:        pr.getValue("userInfo"),
		ObjLabels:       pr.getValue("object.metadata.labels"),
		ObjMetaName:     pr.getValue("object.metadata.name"),
		UserName:        pr.getValue("userInfo.username"),
		UserGroups:      pr.getArrayValue("userInfo.groups"),
		Type:            pr.getValue("object.type"),
		OrgMetadata:     orgMetadata,
		ClaimedMetadata: claimedMetadata,
	}
	return rc

}

var CommonMessageMask = []string{
	fmt.Sprintf("metadata.labels.\"%s\"", ResourceIntegrityLabelKey),
	fmt.Sprintf("metadata.labels.\"%s\"", ReasonLabelKey),
	"metadata.annotations.sigOwnerApiVersion",
	"metadata.annotations.sigOwnerKind",
	"metadata.annotations.sigOwnerName",
	"metadata.annotations.signOwnerRefType",
	"metadata.annotations.resourceSignatureName",
	"metadata.annotations.message",
	"metadata.annotations.signature",
	"metadata.annotations.certificate",
	"metadata.annotations.signPaths",
	"metadata.annotations.namespace",
	"metadata.annotations.kubectl.\"kubernetes.io/last-applied-configuration\"",
	"metadata.managedFields",
	"metadata.creationTimestamp",
	"metadata.generation",
	"metadata.annotations.deprecated.daemonset.template.generation",
	"metadata.namespace",
	"metadata.resourceVersion",
	"metadata.selfLink",
	"metadata.uid",
}
