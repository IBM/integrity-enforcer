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
	"github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
	"github.com/IBM/integrity-enforcer/enforcer/pkg/policy"
	"github.com/jinzhu/copier"
)

type PatchConfig struct {
	Enabled bool `json:"enabled,omitempty"`
}

type SignStoreConfig struct {
	CertPoolPath       string `json:"certPoolPath"`
	ChartDir           string `json:"chartPath"`
	ChartRepo          string `json:"chartRepo"`
	SignatureNamespace string `json:"signatureNamespace"`
}

type EnforcerConfig struct {
	Patch           *PatchConfig        `json:"patch,omitempty"`
	Log             *LoggingScopeConfig `json:"log,omitempty"`
	SignStore       *SignStoreConfig    `json:"-"`
	Namespace       string              `json:"-"`
	PolicyNamespace string              `json:"-"`
}

type LoggingScopeConfig struct {
	LogLevel       string          `json:"logLevel,omitempty"`
	IncludeRequest bool            `json:"includeRequest,omitempty"`
	IncludeRelease bool            `json:"includeRelease,omitempty"`
	ConsoleLog     *LogScopeConfig `json:"consoleLog,omitempty"`
	ContextLog     *LogScopeConfig `json:"contextLog,omitempty"`
}

/**********************************************

				LogScopeConfig

***********************************************/

type LogScopeConfig struct {
	Enabled bool                         `json:"enabled,omitempty"`
	InScope []policy.RequestMatchPattern `json:"inScope,omitempty"`
	Ignore  []policy.RequestMatchPattern `json:"ignore,omitempty"`
}

func (sc *LogScopeConfig) IsInScope(reqc *common.ReqContext) bool {
	if !sc.Enabled {
		return false
	}

	isInScope := false
	if sc.InScope != nil {
		for _, v := range sc.InScope {

			if v.Match(reqc) {
				isInScope = true
				break
			}
		}
	}

	isIgnored := false
	if sc.Ignore != nil {
		for _, v := range sc.Ignore {
			if v.Match(reqc) {
				isIgnored = true
				break
			}
		}
	}
	return isInScope && !isIgnored
}

func (ec *EnforcerConfig) PatchEnabled() bool {
	if ec.Patch == nil {
		return false
	}
	return ec.Patch.Enabled
}

func (ec *EnforcerConfig) LogConfig() *LoggingScopeConfig {
	conf := ec.Log

	var lc *LoggingScopeConfig

	if conf != nil {
		lc = conf
	} else {
		lc = &LoggingScopeConfig{
			LogLevel:       "info",
			IncludeRequest: false,
			IncludeRelease: false,
		}
	}

	if lc.ConsoleLog == nil {
		lc.ConsoleLog = &LogScopeConfig{
			Enabled: true,
		}
	}

	if lc.ContextLog == nil {
		lc.ContextLog = &LogScopeConfig{
			Enabled: false,
		}
	}

	return lc

}

func (ec *EnforcerConfig) DeepCopyInto(ec2 *EnforcerConfig) {
	copier.Copy(&ec, &ec2)
}

func (ec *EnforcerConfig) DeepCopy() *EnforcerConfig {
	ec2 := &EnforcerConfig{}
	ec.DeepCopyInto(ec2)
	return ec2
}
