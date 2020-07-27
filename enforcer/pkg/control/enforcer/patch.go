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
	"encoding/json"

	gjson "github.com/tidwall/gjson"
)

type PatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func createPatch(name, reqJson string, labels map[string]string, deleteKeys []string) []byte {

	var patch []PatchOperation

	if len(labels) > 0 {

		if gjson.Get(reqJson, "object.metadata").Exists() {

			labelsData := gjson.Get(reqJson, "object.metadata.labels")

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
	if len(patch) > 0 {
		patchBytes, _ := json.Marshal(patch)
		return patchBytes
	} else {
		return nil
	}

}
