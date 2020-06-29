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
)

type AnnotationStore interface {
	GetAnnotation(ref *common.ResourceRef, annotation *common.ResourceAnnotation) *common.ResourceAnnotation
}

/**********************************************

				AnnotationStore (singleton)

***********************************************/

var annotationStoreInstance AnnotationStore

func GetAnnotationStore() AnnotationStore {
	if annotationStoreInstance == nil {
		annotationStoreInstance = &ConcreteAnnotationStore{}
	}
	return annotationStoreInstance
}

type ConcreteAnnotationStore struct {
	Context *CheckContext
}

func (self *ConcreteAnnotationStore) GetAnnotation(ref *common.ResourceRef, annotation *common.ResourceAnnotation) *common.ResourceAnnotation {
	return annotation
}
