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

package config

import (
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ShieldConfig struct {
	InScopeNamespaceSelector NamespaceSelector `json:"inScopeNamespaceSelector,omitempty"`
	Allow                    Allow             `json:"allow,omitempty"`
	SideEffect               SideEffectConfig  `json:"sideEffect,omitempty"`
	Patch                    PatchConfig       `json:"skipObjects,omitempty"`
	Mode                     string            `json:"mode,omitempty"`
	Options                  []string          `json:"option,omitempty"`
}

type NamespaceSelector struct {
	// TODO: check how include works, match in constraint
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

type Allow struct {
	Kinds []metav1.GroupVersionKind `json:"kinds,omitempty"`
}

type SideEffectConfig struct {
	// Event
	CreateDenyEvent            bool `json:"createDenyEvent"`
	CreateIShieldResourceEvent bool `json:"createIShieldResourceEvent"`
	// MIP
	UpdateMIPStatusForDeniedRequest bool `json:"updateMIPStatusForDeniedRequest"`
}

type PatchConfig struct {
	Enabled bool `json:"enabled,omitempty"`
}

func (ns NamespaceSelector) Match(rns string) bool {
	excluded := false
	included := false
	if len(ns.Exclude) != 0 {
		excluded = k8smnfutil.MatchWithPatternArray(rns, ns.Exclude)
	}
	if len(ns.Include) != 0 {
		included = k8smnfutil.MatchWithPatternArray(rns, ns.Include)
	} else {
		included = true
	}
	if included && excluded {
		return false
	} else if !included {
		return false
	}
	return true
}

func (allow Allow) Match(kind metav1.GroupVersionKind) bool {
	for _, k := range allow.Kinds {
		var groupMatch bool
		var kindMatch bool
		var versionMatch bool
		if k.Group == "" {
			groupMatch = true
		} else if k8smnfutil.MatchSinglePattern(k.Group, kind.Group) {
			groupMatch = true
		}
		if k.Kind == "" {
			kindMatch = true
		} else if k8smnfutil.MatchSinglePattern(k.Kind, kind.Kind) {
			kindMatch = true
		}
		if k.Version == "" {
			versionMatch = true
		} else if k8smnfutil.MatchSinglePattern(k.Version, kind.Version) {
			versionMatch = true
		}
		if groupMatch && kindMatch && versionMatch {
			return true
		}
	}
	return false
}
