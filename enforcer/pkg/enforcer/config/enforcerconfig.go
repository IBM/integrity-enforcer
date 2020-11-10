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
	rspapi "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourcesigningprofile/v1alpha1"
	"github.com/IBM/integrity-enforcer/enforcer/pkg/common/common"
	"github.com/IBM/integrity-enforcer/enforcer/pkg/common/profile"
	"github.com/IBM/integrity-enforcer/enforcer/pkg/util/logger"
	"github.com/jinzhu/copier"
)

type IntegrityEnforcerMode string

const (
	UnknownMode IntegrityEnforcerMode = ""
	EnforceMode IntegrityEnforcerMode = "enforce"
	DetectMode  IntegrityEnforcerMode = "detect"
)

type PatchConfig struct {
	Enabled bool `json:"enabled,omitempty"`
}

type IEResourceCondition struct {
	References             []*common.ResourceRef `json:"references,omitempty"`
	OperatorServiceAccount string                `json:"operatorServiceAccount,omitempty"`
}

type EnforcerConfig struct {
	Patch *PatchConfig        `json:"patch,omitempty"`
	Log   *LoggingScopeConfig `json:"log,omitempty"`

	// Policy  *policy.IntegrityEnforcerPolicy `json:"policy,omitempty"`
	Allow         []profile.RequestPattern           `json:"allow,omitempty"`
	Ignore        []profile.RequestPattern           `json:"ignore,omitempty"`
	Mode          IntegrityEnforcerMode              `json:"mode,omitempty"`
	Plugin        []PluginConfig                     `json:"plugin,omitempty"`
	CommonProfile *rspapi.ResourceSigningProfileSpec `json:"commonProfile,omitempty"`

	Namespace          string   `json:"namespace,omitempty"`
	SignatureNamespace string   `json:"signatureNamespace,omitempty"`
	ProfileNamespace   string   `json:"profileNamespace,omitempty"`
	VerifyType         string   `json:"verifyType"`
	KeyPathList        []string `json:"keyPathList,omitempty"`
	ChartDir           string   `json:"chartPath,omitempty"`
	ChartRepo          string   `json:"chartRepo,omitempty"`

	IEResource          string               `json:"ieResource,omitempty"`
	IEResourceCondition *IEResourceCondition `json:"ieResourceCondition,omitempty"`
	IEAdminUserGroup    string               `json:"ieAdminUserGroup,omitempty"`
	IEServerUserName    string               `json:"ieServerUserName,omitempty"`
}

type LoggingScopeConfig struct {
	LogLevel             string          `json:"logLevel,omitempty"`
	IncludeRequest       bool            `json:"includeRequest,omitempty"`
	IncludeRelease       bool            `json:"includeRelease,omitempty"`
	ConsoleLog           *LogScopeConfig `json:"consoleLog,omitempty"`
	ContextLog           *LogScopeConfig `json:"contextLog,omitempty"`
	ConsoleLogFormat     string          `json:"consoleLogFormat,omitempty"`
	ConsoleLogFile       string          `json:"consoleLogFile,omitempty"`
	ContextLogFile       string          `json:"contextLogFile,omitempty"`
	ContextLogRotateSize int64           `json:"contextLogRotateSize,omitempty"`
}

type PluginConfig struct {
	Name    string `json:"name,omitempty"`
	Enabled bool   `json:"enabled,omitempty"`
}

func (self *IEResourceCondition) Match(reqc *common.ReqContext) bool {
	ref := reqc.ResourceRef()
	for _, refi := range self.References {
		if refi.Equals(ref) {
			return true
		}
	}
	return false
}

/**********************************************

				LogScopeConfig

***********************************************/

type LogScopeConfig struct {
	Enabled bool                     `json:"enabled,omitempty"`
	InScope []profile.RequestPattern `json:"inScope,omitempty"`
	Ignore  []profile.RequestPattern `json:"ignore,omitempty"`
}

func (sc *LogScopeConfig) IsInScope(reqc *common.ReqContext) bool {
	if !sc.Enabled {
		return false
	}
	reqFields := reqc.Map()
	isInScope := false
	if sc.InScope != nil {
		for _, v := range sc.InScope {
			if v.Match(reqFields) {
				isInScope = true
				break
			}
		}
	}

	isIgnored := false
	if sc.Ignore != nil {
		for _, v := range sc.Ignore {
			if v.Match(reqFields) {
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

	defaultFormat := "json"
	defaultLogOutput := "" // console
	defaultFilePath := "/ie-app/public/events.txt"
	defaultRotateSize := int64(10485760) // 10MB
	if lc.ConsoleLogFormat == "" {
		lc.ConsoleLogFormat = defaultFormat
	}
	if lc.ConsoleLogFile == "" {
		lc.ConsoleLogFile = defaultLogOutput
	}
	if lc.ContextLogFile == "" {
		lc.ContextLogFile = defaultFilePath
	}
	if lc.ContextLogRotateSize == 0 {
		lc.ContextLogRotateSize = defaultRotateSize
	}

	return lc

}

func (ec *EnforcerConfig) DeepCopyInto(ec2 *EnforcerConfig) {
	copier.Copy(&ec2, &ec)
}

func (ec *EnforcerConfig) DeepCopy() *EnforcerConfig {
	ec2 := &EnforcerConfig{}
	ec.DeepCopyInto(ec2)
	return ec2
}

func (ec *EnforcerConfig) LoggerConfig() logger.LoggerConfig {
	lc := ec.LogConfig()
	return logger.LoggerConfig{Level: lc.LogLevel, Format: lc.ConsoleLogFormat, FileDest: lc.ConsoleLogFile}
}

func (ec *EnforcerConfig) ContextLoggerConfig() logger.ContextLoggerConfig {
	lc := ec.LogConfig()
	return logger.ContextLoggerConfig{Enabled: lc.ContextLog.Enabled, File: lc.ContextLogFile, LimitSize: lc.ContextLogRotateSize}
}

func (ec *EnforcerConfig) GetEnabledPlugins() map[string]bool {
	plugins := map[string]bool{}
	for _, plg := range ec.Plugin {
		if plg.Enabled {
			plugins[plg.Name] = true
		}
	}
	return plugins
}
