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

package shield

import (
	"fmt"

	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	config "github.com/IBM/integrity-enforcer/shield/pkg/config"
	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func createAdmissionResponse(allowed bool, msg string, reqc *common.RequestContext, reqobj *common.RequestObject, ctx *common.CheckContext, conf *config.ShieldConfig) *admv1.AdmissionResponse {
	var patchBytes []byte
	if conf.PatchEnabled(reqc.Kind, reqc.ApiGroup) {
		// `patchBytes` will be nil if no patch
		patchBytes = common.GeneratePatchBytes(reqc.Name, reqobj.RawObject, ctx)
	}
	responseMessage := fmt.Sprintf("%s (Request: %s)", msg, reqc.Info(nil))
	resp := &admv1.AdmissionResponse{
		Allowed: allowed,
		Result: &metav1.Status{
			Message: responseMessage,
		},
	}
	if patchBytes != nil {
		patchType := admv1.PatchTypeJSONPatch
		resp.Patch = patchBytes
		resp.PatchType = &patchType
	}
	return resp
}

func getBreakGlassConditions(signerConfig *common.SignerConfig) []common.BreakGlassCondition {
	conditions := []common.BreakGlassCondition{}
	if signerConfig != nil {
		conditions = append(conditions, signerConfig.BreakGlass...)
	}
	return conditions
}

func checkIfBreakGlassEnabled(reqc *common.RequestContext, signerConfig *common.SignerConfig) bool {

	conditions := getBreakGlassConditions(signerConfig)
	breakGlassEnabled := false
	if reqc.ResourceScope == "Namespaced" {
		reqNs := reqc.Namespace
		for _, d := range conditions {
			if d.Scope == common.ScopeUndefined || d.Scope == common.ScopeNamespaced {
				for _, ns := range d.Namespaces {
					if reqNs == ns {
						breakGlassEnabled = true
						break
					}
				}
			}
			if breakGlassEnabled {
				break
			}
		}
	} else {
		for _, d := range conditions {
			if d.Scope == common.ScopeCluster {
				breakGlassEnabled = true
				break
			}
		}
	}
	return breakGlassEnabled
}

func checkIfDetectOnly(sconf *config.ShieldConfig) bool {
	return (sconf.Mode == config.DetectMode)
}
