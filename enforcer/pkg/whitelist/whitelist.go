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

package whitelist

import (
	common "github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
	mapnode "github.com/IBM/integrity-enforcer/enforcer/pkg/mapnode"
	"github.com/IBM/integrity-enforcer/enforcer/pkg/policy"
)

/**********************************************

					Rule

***********************************************/

type Rule struct {
	Namespace       string   `json:"namespace,omitempty"`
	ResourceType    string   `json:"resource_type,omitempty"`
	ResourceName    string   `json:"resource_name,omitempty"`
	UserName        string   `json:"user_name,omitempty"`
	UserGroup       string   `json:"user_group,omitempty"`
	OwnerKind       string   `json:"owner_kind,omitempty"`
	OwnerApiVersion string   `json:"owner_api_version,omitempty"`
	OwnerName       string   `json:"owner_name,omitempty"`
	Key             []string `json:"key,omitempty"`
	Enabled         bool     `json:"enabled,omitempty"`
}

/**********************************************

			EnforcePolicyWhitelist

***********************************************/

type EnforcePolicyWhitelist struct {
	Rule []policy.AllowedChangeCondition
}

func NewEPW() *EnforcePolicyWhitelist {
	wl := &EnforcePolicyWhitelist{}
	return wl
}

func (wl *EnforcePolicyWhitelist) GenerateMaskKeys(namespace, name, kind, username string, usergroups []string) []string {
	maskKey := []string{}
	for _, rule := range wl.Rule {
		// request match
		if !common.MatchPattern(rule.Request.Name, name) {
			continue
		}
		if !common.MatchPattern(rule.Request.Kind, kind) {
			continue
		}
		if !common.MatchPattern(rule.Request.UserName, username) {
			continue
		}
		if !common.MatchPattern(rule.Request.Namespace, namespace) {
			continue
		}
		if !common.MatchPatternWithArray(rule.Request.UserGroup, usergroups) {
			continue
		}
		maskKey = append(maskKey, rule.Key...)
	}
	return maskKey
}

func FilterDiff(dr *mapnode.DiffResult, maskKeys []string) (*mapnode.DiffResult, *mapnode.DiffResult, []string) {
	if dr == nil {
		return &mapnode.DiffResult{}, &mapnode.DiffResult{}, []string{}
	}
	filtered, unfiltered, matchedKeys := dr.Filter(maskKeys)
	return filtered, unfiltered, matchedKeys
}
