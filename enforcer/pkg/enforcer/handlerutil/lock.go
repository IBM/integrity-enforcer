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

package handlerutil

import (
	common "github.com/IBM/integrity-enforcer/enforcer/pkg/common/common"
	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/util/logger"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func MatchLockConfig(lockConfig map[string]string, reqc *common.ReqContext) bool {
	opNS, _ := lockConfig["operatorNamespace"]
	opName, _ := lockConfig["operatorName"]
	if reqc.Kind == "Deployment" && reqc.Namespace == opNS && reqc.Name == opName {
		return true
	}

	crNS, _ := lockConfig["crNamespace"]
	crName, _ := lockConfig["crName"]
	if reqc.Kind == common.IECustomResourceKind && reqc.Namespace == crNS && reqc.Name == crName {
		return true
	}

	obj := &unstructured.Unstructured{}

	rawObject := reqc.RawObject
	if reqc.Operation == "UPDATE" || reqc.Operation == "DELETE" {
		rawObject = reqc.RawOldObject
	}

	err := obj.UnmarshalJSON(rawObject)
	if err != nil {
		logger.Warn("Failed to unmarshal for parse reqc; ", err.Error())
		return false
	}

	ownerRefs := obj.GetOwnerReferences()
	if len(ownerRefs) == 0 {
		return false
	}
	owner := ownerRefs[0]
	if owner.Kind == common.IECustomResourceKind && reqc.Namespace == crNS && owner.Name == crName {
		return true
	}
	return false
}
