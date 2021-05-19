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
	"encoding/json"
	"time"

	"github.com/IBM/integrity-enforcer/shield/pkg/common"
	gjson "github.com/tidwall/gjson"
)

const metadataTimestampFormat = "2006-01-02T15:04:05Z"

type PatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func generatePatchBytes(reqc *common.RequestContext, reqobj *common.RequestObject, ctx *CheckContext) []byte {
	// do not patch for denying request
	if !ctx.Allow {
		return nil
	}

	sigResult := ctx.SignatureEvalResult

	verifyResultLabel := ""
	// attach `verified` label only when signature is correctly verified
	// or attach `unverified` label if allowed due to breakglass mode
	if sigResult.Checked && sigResult.Allow {
		verifyResultLabel = common.LabelValueVerified
	} else if ctx.BreakGlassModeEnabled && !(sigResult.Checked && sigResult.Allow) {
		verifyResultLabel = common.LabelValueUnverified
	}
	if verifyResultLabel == "" {
		return nil
	}

	name := reqc.Name
	reqJson := reqobj.RawObject
	labels := map[string]string{
		common.ResourceIntegrityLabelKey: verifyResultLabel,
	}
	annotations := map[string]string{}
	if verifyResultLabel == common.LabelValueVerified {
		annotations[common.LastVerifiedTimestampAnnotationKey] = time.Now().UTC().Format(metadataTimestampFormat)
		if sigResult.SignerName != "" {
			annotations[common.SignedByAnnotationKey] = sigResult.SignerName
		}
		if sigResult.ResourceSignatureUID != "" {
			annotations[common.ResourceSignatureUIDAnnotationKey] = sigResult.ResourceSignatureUID
		}
	}
	deleteKeys := []string{
		common.ResourceIntegrityLabelKey,
		common.LastVerifiedTimestampAnnotationKey,
		common.SignedByAnnotationKey,
		common.ResourceSignatureUIDAnnotationKey,
	}
	return createJSONPatchBytes(name, string(reqJson), labels, annotations, deleteKeys)
}

// Return value is a document of JSON Patch.
// JSON Patch format is specified in RFC 6902 from the IETF.
func createJSONPatchBytes(name, reqJson string, labels map[string]string, annotations map[string]string, deleteKeys []string) []byte {

	var patch []PatchOperation

	if len(labels) > 0 {

		if gjson.Get(reqJson, "metadata").Exists() {

			labelsData := gjson.Get(reqJson, "metadata.labels")

			if labelsData.Exists() {

				for _, key := range deleteKeys {
					if labelsData.Get(key).Exists() {
						patch = append(patch, PatchOperation{
							Op:   "remove",
							Path: "/metadata/labels/" + key,
						})
					}
				}

				addMap := make(map[string]string)

				if labelsDataMap, ok := labelsData.Value().(map[string]interface{}); ok {
					for key, val := range labelsDataMap {
						if valStr, ok2 := val.(string); ok2 {
							addMap[key] = valStr
						}
					}
				}
				for key, value := range labels {
					if !labelsData.Get(key).Exists() {
						addMap[key] = value
					}
				}

				if len(addMap) > 0 {
					patch = append(patch, PatchOperation{
						Op:    "add",
						Path:  "/metadata/labels",
						Value: addMap,
					})
				}
			} else {
				patch = append(patch, PatchOperation{
					Op:    "add",
					Path:  "/metadata/labels",
					Value: labels,
				})

			}

		} else {

			patch = append(patch, PatchOperation{
				Op:    "add",
				Path:  "/metadata/name",
				Value: name,
			})

			patch = append(patch, PatchOperation{
				Op:    "add",
				Path:  "/metadata/labels",
				Value: labels,
			})

		}
	}

	if len(annotations) > 0 {

		if gjson.Get(reqJson, "metadata").Exists() {

			annotationsData := gjson.Get(reqJson, "metadata.annotations")

			if annotationsData.Exists() {

				for _, key := range deleteKeys {
					if annotationsData.Get(key).Exists() {
						patch = append(patch, PatchOperation{
							Op:   "remove",
							Path: "/metadata/annotations/" + key,
						})
					}
				}

				addMap := make(map[string]string)

				if annotationsDataMap, ok := annotationsData.Value().(map[string]interface{}); ok {
					for key, val := range annotationsDataMap {
						if valStr, ok2 := val.(string); ok2 {
							addMap[key] = valStr
						}
					}
				}
				for key, value := range annotations {
					if !annotationsData.Get(key).Exists() {
						addMap[key] = value
					}
				}

				if len(addMap) > 0 {
					patch = append(patch, PatchOperation{
						Op:    "add",
						Path:  "/metadata/annotations",
						Value: addMap,
					})
				}
			} else {
				patch = append(patch, PatchOperation{
					Op:    "add",
					Path:  "/metadata/annotations",
					Value: annotations,
				})

			}
		} else {

			patch = append(patch, PatchOperation{
				Op:    "add",
				Path:  "/metadata/annotations",
				Value: annotations,
			})

		}

	}

	if len(patch) > 0 {
		patchBytes, _ := json.Marshal(patch)
		return patchBytes
	} else {
		return nil
	}

}
