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

package verifier

import (
	common "github.com/IBM/integrity-enforcer/verifier/pkg/common/common"
	config "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/config"
	loader "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/loader"
	v1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

/**********************************************

				Handler interface

***********************************************/

type Handler interface {
	Run(req *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse
}

func NewRequestHandler(reqRef *common.ResourceRef, config *config.VerifierConfig) Handler {
	cc := InitCheckContext(config)
	ivOperatorResource := config.IVResourceCondition.IsOperatorResource(reqRef)
	ivServerResource := config.IVResourceCondition.IsServerResource(reqRef)
	if ivOperatorResource || ivServerResource {
		return &IVResourceRequestHandler{commonHandler: &commonHandler{config: config, loader: &loader.Loader{}, ctx: cc}, isOperatorResource: ivOperatorResource, isServerResource: ivServerResource}
	} else {
		return &RequestHandler{commonHandler: &commonHandler{config: config, loader: &loader.Loader{}, ctx: cc}}
	}
}

type DecisionResult struct {
	Allow      bool
	Verified   bool
	ReasonCode int
	Message    string
}

func createAdmissionResponse(allowed bool, msg string) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Allowed: allowed,
		Result: &metav1.Status{
			Message: msg,
		}}
}
