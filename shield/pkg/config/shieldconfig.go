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
	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	"github.com/jinzhu/copier"
)

type IntegrityShieldMode string

const (
	UnknownMode IntegrityShieldMode = ""
	EnforceMode IntegrityShieldMode = "enforce"
	DetectMode  IntegrityShieldMode = "detect"
)

type PatchConfig struct {
	Enabled bool `json:"enabled,omitempty"`
}

type IShieldResourceCondition struct {
	OperatorResources      []*common.ResourceRef `json:"operatorResources,omitempty"`
	ServerResources        []*common.ResourceRef `json:"serverResources,omitempty"`
	OperatorServiceAccount string                `json:"operatorServiceAccount,omitempty"`
}

type ShieldConfig struct {
	Patch      *PatchConfig        `json:"patch,omitempty"`
	Log        *LoggingScopeConfig `json:"log,omitempty"`
	SideEffect *SideEffectConfig   `json:"sideEffect,omitempty"`

	InScopeNamespaceSelector *common.NamespaceSelector `json:"inScopeNamespaceSelector,omitempty"`
	Allow                    []common.RequestPattern   `json:"allow,omitempty"`
	Ignore                   []common.RequestPattern   `json:"ignore,omitempty"`
	Mode                     IntegrityShieldMode       `json:"mode,omitempty"`
	Plugin                   []PluginConfig            `json:"plugin,omitempty"`
	SigStoreConfig           SigStoreConfig            `json:"sigstoreConfig,omitempty"`
	ImageVerificationConfig  ImageVerificationConfig   `json:"imageVerificationConfig,omitempty"`
	CommonProfile            *common.CommonProfile     `json:"commonProfile,omitempty"`

	Namespace          string   `json:"namespace,omitempty"`
	SignatureNamespace string   `json:"signatureNamespace,omitempty"`
	ProfileNamespace   string   `json:"profileNamespace,omitempty"`
	KeyPathList        []string `json:"keyPathList,omitempty"`
	ChartDir           string   `json:"chartPath,omitempty"`
	ChartRepo          string   `json:"chartRepo,omitempty"`

	IShieldResource          string                    `json:"iShieldResource,omitempty"`
	IShieldResourceCondition *IShieldResourceCondition `json:"iShieldResourceCondition,omitempty"`
	IShieldAdminUserGroup    string                    `json:"iShieldAdminUserGroup,omitempty"`
	IShieldAdminUserName     string                    `json:"iShieldAdminUserName,omitempty"`
	IShieldCRName            string                    `json:"iShieldCRName,omitempty"`
	IShieldServerUserName    string                    `json:"iShieldServerUserName,omitempty"`
	Options                  []string                  `json:"options,omitempty"`
}

type LoggingScopeConfig struct {
	LogLevel             string          `json:"logLevel,omitempty"`
	LogAllResponse       bool            `json:"logAllResponse,omitempty"`
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

type SigStoreConfig struct {
	Enabled            bool   `json:"enabled,omitempty"`
	RekorServerURL     string `json:"rekorServerURL,omitempty"`
	UseDefaultRootCert bool   `json:"useDefaultRootCert,omitempty"`
	DefaultRootCertURL string `json:"defaultRootCertURL,omitempty"`
}

type ImageVerificationConfig struct {
	Enabled bool              `json:"enabled,omitempty"`
	Options map[string]string `json:"options,omitempty"`
}

func (self *IShieldResourceCondition) IsOperatorResource(ref *common.ResourceRef) bool {
	for _, refi := range self.OperatorResources {
		if refi.EqualsWithoutVersionCheck(ref) {
			return true
		}
	}
	return false
}

func (self *IShieldResourceCondition) IsServerResource(ref *common.ResourceRef) bool {
	for _, refi := range self.ServerResources {
		if refi.EqualsWithoutVersionCheck(ref) {
			return true
		}
	}
	return false
}

type LogRequestPattern struct {
	*common.RequestPatternWithNamespace `json:""`
	LogLevel                            string `json:"logLevel,omitempty"`
}

/**********************************************

				LogScopeConfig

***********************************************/

type LogScopeConfig struct {
	Enabled bool                `json:"enabled,omitempty"`
	InScope []LogRequestPattern `json:"inScope,omitempty"`
	Ignore  []LogRequestPattern `json:"ignore,omitempty"`
}

func (sc *LogScopeConfig) IsInScope(resc *common.ResourceContext) (bool, string) {
	if !sc.Enabled {
		return false, ""
	}
	reqFields := resc.Map()
	isInScope := false
	level := ""
	if sc.InScope != nil {
		for _, v := range sc.InScope {
			if v.Match(reqFields) {
				isInScope = true
				level = logger.GetGreaterLevel(level, v.LogLevel)
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
	return (isInScope && !isIgnored), level
}

func (ec *ShieldConfig) PatchEnabled(reqc *common.RequestContext) bool {
	// TODO: make this configurable
	if reqc.Kind == "Policy" && reqc.ApiGroup == "policy.open-cluster-management.io" {
		return false
	}
	if ec.Patch == nil {
		return false
	}
	return ec.Patch.Enabled
}

func (ec *ShieldConfig) LogConfig() *LoggingScopeConfig {
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
	defaultFilePath := "/ishield-app/public/events.txt"
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

func (ec *ShieldConfig) DeepCopyInto(ec2 *ShieldConfig) {
	copier.Copy(&ec2, &ec)
}

func (ec *ShieldConfig) DeepCopy() *ShieldConfig {
	ec2 := &ShieldConfig{}
	ec.DeepCopyInto(ec2)
	return ec2
}

func (ec *ShieldConfig) LoggerConfig() logger.LoggerConfig {
	lc := ec.LogConfig()
	return logger.LoggerConfig{Level: lc.LogLevel, Format: lc.ConsoleLogFormat, FileDest: lc.ConsoleLogFile}
}

func (ec *ShieldConfig) ContextLoggerConfig() logger.ContextLoggerConfig {
	lc := ec.LogConfig()
	return logger.ContextLoggerConfig{Enabled: lc.ContextLog.Enabled, File: lc.ContextLogFile, LimitSize: lc.ContextLogRotateSize}
}

func (ec *ShieldConfig) ConsoleLogEnabled(resc *common.ResourceContext) (bool, string) {
	enabled, level := ec.Log.ConsoleLog.IsInScope(resc)
	level = logger.GetGreaterLevel(ec.Log.LogLevel, level)
	return enabled, level
}

func (ec *ShieldConfig) ContextLogEnabled(resc *common.ResourceContext) bool {
	enabled, _ := ec.Log.ContextLog.IsInScope(resc)
	return enabled
}

func (ec *ShieldConfig) GetEnabledPlugins() map[string]bool {
	plugins := map[string]bool{}
	for _, plg := range ec.Plugin {
		if plg.Enabled {
			plugins[plg.Name] = true
		}
	}
	return plugins
}

func (ec *ShieldConfig) SigStoreEnabled() bool {
	return ec.SigStoreConfig.Enabled
}

func (ec *ShieldConfig) ImageVerificationEnabled() bool {
	return ec.ImageVerificationConfig.Enabled
}

/**********************************************

				SideEffectConfig

***********************************************/

type SideEffectConfig struct {

	// Event
	CreateDenyEvent            bool `json:"createDenyEvent"`
	CreateIShieldResourceEvent bool `json:"createIShieldResourceEvent"`

	// RSP
	UpdateRSPStatusForDeniedRequest bool `json:"updateRSPStatusForDeniedRequest"`
}

func (sc *SideEffectConfig) Enabled() bool {
	return sc.CreateEventEnabled() || sc.UpdateRSPStatusEnabled()
}

func (sc *SideEffectConfig) CreateEventEnabled() bool {
	return (sc.CreateDenyEvent || sc.CreateIShieldResourceEvent)
}

func (sc *SideEffectConfig) CreateDenyEventEnabled() bool {
	return sc.CreateDenyEvent
}

func (sc *SideEffectConfig) CreateIShieldResourceEventEnabled() bool {
	return sc.CreateIShieldResourceEvent
}

func (sc *SideEffectConfig) UpdateRSPStatusEnabled() bool {
	return sc.UpdateRSPStatusForDeniedRequest
}
