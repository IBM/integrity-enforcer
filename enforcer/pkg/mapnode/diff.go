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

package mapnode

import (
	"encoding/json"
	"regexp"
	"strings"
)

/**********************************************

					Difference

***********************************************/

type Difference struct {
	Key    string                 `json:"key"`
	Values map[string]interface{} `json:"values"`
}

type DiffResult struct {
	Items []Difference `json:"items"`
}

func (d *DiffResult) Keys() []string {
	keys := []string{}
	for _, di := range d.Items {
		keys = append(keys, di.Key)
	}
	return keys
}

func (d *DiffResult) Values() []map[string]interface{} {
	vals := []map[string]interface{}{}
	for _, di := range d.Items {
		vals = append(vals, di.Values)
	}
	return vals
}

func (dr *DiffResult) Size() int {
	return len(dr.Items)
}

func (dr *DiffResult) Filter(maskKeys []string) (*DiffResult, *DiffResult) {
	filtered := &DiffResult{}
	unfiltered := &DiffResult{}
	for _, dri := range dr.Items {
		driKey := dri.Key
		exists := keyExistsInList(maskKeys, driKey)
		if exists {
			filtered.Items = append(filtered.Items, dri)
		} else {
			unfiltered.Items = append(unfiltered.Items, dri)
		}
	}
	return filtered, unfiltered
}

func (d *DiffResult) ToJson() string {
	dByte, err := json.Marshal(d)
	if err != nil {
		return ""
	}
	return string(dByte)
}

func (d *DiffResult) String() string {
	if d.Size() == 0 {
		return ""
	}
	return d.ToJson()
}

func keyExistsInList(slice []string, val string) bool {
	var isMatch bool
	for _, item := range slice {
		isMatch = isListed(val, item)
		if isMatch {
			return isMatch
		}
	}
	return isMatch
}

func isListed(data, rule string) bool {
	isMatch := false
	if data == rule {
		isMatch = true
	} else if rule == "*" {
		isMatch = true
	} else if rule == "" {
		isMatch = true
	} else if strings.Contains(rule, "*") {
		rule2 := strings.Replace(rule, "*", ".*", -1)
		if m, _ := regexp.MatchString(rule2, data); m {
			isMatch = true
		}
	}
	return isMatch
}
