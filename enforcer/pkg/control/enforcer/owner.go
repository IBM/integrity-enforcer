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

package enforcer

import (
	common "github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
	mapnode "github.com/IBM/integrity-enforcer/enforcer/pkg/mapnode"
	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

/**********************************************

				SignPolicy

***********************************************/

type OwnerResolver interface {
	Find(reqc *common.ReqContext) (*common.ResolveOwnerResult, error)
}

type ConcreteOwnerResolver struct {
	client *dynamic.Interface
}

type FindOwnerResult struct {
	Ref   *common.ResourceRef
	Owner *common.Owner
	Error *common.CheckError
}

func (self *ConcreteOwnerResolver) Find(reqc *common.ReqContext) (*common.ResolveOwnerResult, error) {
	ref := reqc.OwnerRef()
	var arr []*common.Owner
	r, err := self.findOwners(ref, arr)
	if err == nil && r != nil {
		if r.Owners == nil || r.Owners.Owners == nil {
			r.Verified = false
		} else {
			owners := r.Owners.Owners
			r.Verified = owners[len(owners)-1].IsIntegrityVerified()
		}
	}
	return r, err
}

func NewOwnerResolver() (OwnerResolver, error) {
	var client *dynamic.Interface
	if v, err := newDynamicClient(); err != nil {
		return nil, err
	} else {
		client = v
	}

	owr := &ConcreteOwnerResolver{
		client: client,
	}

	return owr, nil
}

func newDynamicClient() (*dynamic.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	var client dynamic.Interface
	client, err = dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &client, nil
}

func (self *ConcreteOwnerResolver) findOwners(ref *common.ResourceRef, owners []*common.Owner) (*common.ResolveOwnerResult, error) {

	var updatedOwners []*common.Owner
	updatedOwners = append(updatedOwners, owners...)

	if r, err := self.findOwner(ref); err != nil {
		return nil, err
	} else if r.Owner == nil {
		return &common.ResolveOwnerResult{
			Owners: &common.OwnerList{
				Owners: updatedOwners,
			},
			Checked: true,
			Error:   r.Error,
		}, nil
	} else {
		updatedOwners = append(updatedOwners, r.Owner)
		if r.Owner.OwnerRef == nil {
			return &common.ResolveOwnerResult{
				Owners: &common.OwnerList{
					Owners: updatedOwners,
				},
				Checked: true,
				Error:   r.Error,
			}, nil
		} else {
			ownerRef := r.Owner.OwnerRef
			for i, ow := range updatedOwners {
				if ow.OwnerRef.Equals(ownerRef) && i != len(updatedOwners)-1 {
					return &common.ResolveOwnerResult{
						Checked: true,
						Error: &common.CheckError{
							Reason: "Invalid owner reference (found cycle)",
						},
					}, nil
				}
			}

		}

		if rr, err := self.findOwners(r.Owner.OwnerRef, updatedOwners); err != nil {
			return nil, err
		} else {
			updatedOwners = append(updatedOwners, rr.Owners.Owners...)
			return &common.ResolveOwnerResult{
				Owners: &common.OwnerList{
					Owners: updatedOwners,
				},
				Checked: true,
				Error:   r.Error,
			}, nil
		}
	}
}

func (owr *ConcreteOwnerResolver) findOwner(ref *common.ResourceRef) (*FindOwnerResult, error) {

	result := &FindOwnerResult{
		Ref: ref,
	}

	var group, version string
	if gv, err := schema.ParseGroupVersion(ref.ApiVersion); err != nil {
		result.Error = &common.CheckError{
			Error:  err,
			Reason: "Error when parsing group version",
		}
		return result, nil
	} else {
		group = gv.Group
		version = gv.Version
	}

	gvknd := schema.GroupVersionKind{
		Group:   group,
		Version: version,
		Kind:    ref.Kind,
	}

	gvr, _ := meta.UnsafeGuessKindToResource(gvknd)
	gvclient := (*owr.client).Resource(gvr)

	var objMap map[string]interface{}
	if v, err := gvclient.Namespace(ref.Namespace).Get(ref.Name, metav1.GetOptions{}); err != nil {
		result.Error = &common.CheckError{
			Error:  err,
			Reason: "Error when obtaing owner reference",
		}
		return result, nil
	} else {
		objMap = v.Object
	}

	values, err := mapnode.NewFromMap(objMap)
	if err != nil {
		result.Error = &common.CheckError{
			Error:  err,
			Reason: "Error when creating new map node from map",
		}
		return result, nil
	}

	annotationMap := make(map[string]string)

	vmap := values.SubNode("metadata.annotations").GetChildrenMap()
	for k := range vmap {
		v := vmap[k]
		annotationMap[k] = v.String()
	}

	annotation := common.NewResourceAnnotation(annotationMap)
	annotationStore := GetAnnotationStore()
	annotation = annotationStore.GetAnnotation(ref, annotation)

	owner := &common.Owner{
		Ref: ref,
		OwnerRef: &common.ResourceRef{
			Kind:       values.GetString("metadata.ownerReferences.0.kind"),
			Name:       values.GetString("metadata.ownerReferences.0.name"),
			ApiVersion: values.GetString("metadata.ownerReferences.0.apiVersion"),
			Namespace:  values.GetString("metadata.namespace"),
		},
		Annotation: annotation,
	}

	result.Owner = owner

	return result, nil
}
