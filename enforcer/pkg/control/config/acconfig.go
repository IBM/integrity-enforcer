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
	"fmt"
	"os"
	"reflect"
	"strconv"
	"time"

	cfg "github.com/IBM/integrity-enforcer/enforcer/pkg/config"
	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/logger"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/policy"
)

/**********************************************

		Configs for Helm Release

***********************************************/

type AdmissionControlConfig struct {
	LoggerConfig        logger.LoggerConfig
	ContextLoggerConfig logger.ContextLoggerConfig
	EnforcerConfig      *cfg.EnforcerConfig
	enforcePolicy       *policy.Policy
	lastUpdated         time.Time
	lastPolicyUpdated   time.Time
}

func NewAdmissionControlConfig() *AdmissionControlConfig {

	cxLogEnabled, err := strconv.ParseBool(os.Getenv("CX_LOG_ENABLED"))
	if err != nil {
		fmt.Println(err.Error())
	}
	cxLogFile := os.Getenv("CX_LOG_FILE")
	if cxLogFile == "" {
		cxLogFile = "/ie-app/public/events.txt"
	}

	cxLimitSizeStr := os.Getenv("CX_FILE_LIMIT_SIZE")
	if cxLimitSizeStr == "" {
		cxLimitSizeStr = "10485760" // == 10MB
	}
	cxLimitSize, err := strconv.Atoi(cxLimitSizeStr)
	if err != nil {
		fmt.Println(err.Error())
	}

	cxLoggerConfig := logger.ContextLoggerConfig{Enabled: cxLogEnabled, File: cxLogFile, LimitSize: int64(cxLimitSize)}

	if err != nil {
		fmt.Println("Could not get env includeRequest")
	}

	acConfig := &AdmissionControlConfig{
		ContextLoggerConfig: cxLoggerConfig,
	}

	return acConfig
}

func (ac *AdmissionControlConfig) LoadEnforcePolicy() *policy.Policy {

	renew := false
	t := time.Now()
	if ac.enforcePolicy != nil {

		interval := 10
		if s := os.Getenv("ENFORCE_POLICY_RELOAD_SEC"); s != "" {
			if v, err := strconv.Atoi(s); err != nil {
				interval = v
			}
		}

		duration := t.Sub(ac.lastPolicyUpdated)
		if int(duration.Seconds()) > interval {
			renew = true
		}
	} else {
		renew = true
	}

	if renew {
		enforcerNs := os.Getenv("ENFORCER_NS")
		policyNs := os.Getenv("POLICY_NS")
		enforcePolicy := LoadEnforcePolicy(enforcerNs, policyNs)

		if enforcePolicy != nil {
			changed := reflect.DeepEqual(enforcePolicy, ac.enforcePolicy)
			if changed {
				logger.Info("Enforce Policy update reloaded")
			}
			ac.enforcePolicy = enforcePolicy
			ac.lastPolicyUpdated = t
		}
	}

	return ac.enforcePolicy
}

func (ac *AdmissionControlConfig) InitEnforcerConfig() bool {

	renew := false
	t := time.Now()
	if ac.EnforcerConfig != nil {

		interval := 20
		if s := os.Getenv("ENFORCER_CM_RELOAD_SEC"); s != "" {
			if v, err := strconv.Atoi(s); err != nil {
				interval = v
			}
		}

		duration := t.Sub(ac.lastUpdated)
		if int(duration.Seconds()) > interval {
			renew = true
		}
	} else {
		renew = true
	}

	if renew {
		enforcerNs := os.Getenv("ENFORCER_NS")
		signatureNs := os.Getenv("SIGNATURE_NS")
		policyNs := os.Getenv("POLICY_NS")
		enforcerConfigName := os.Getenv("ENFORCER_CONFIG_NAME")
		enforcerConfig := LoadEnforceConfig(enforcerNs, enforcerConfigName)

		ssconfig := loadSingStoreConfig(signatureNs)

		if enforcerConfig != nil {
			enforcerConfig.SignStore = ssconfig
			enforcerConfig.Namespace = enforcerNs
			enforcerConfig.PolicyNamespace = policyNs
			ac.EnforcerConfig = enforcerConfig
			ac.lastUpdated = t
			logLevel := enforcerConfig.LogConfig().LogLevel
			ac.LoggerConfig = logger.LoggerConfig{Level: logLevel, Format: "json"}
		}
	}

	return renew
}

func (ac *AdmissionControlConfig) HelmIntegrityEnabled() bool {
	return true
}

func loadSingStoreConfig(signatureNs string) *cfg.SignStoreConfig {
	certPoolPath := os.Getenv("CERT_POOL_PATH")
	if certPoolPath == "" {
		certPoolPath = "/ie-certpool-secret/" // default value
	}
	chartDir := os.Getenv("CHART_DIR")
	if chartDir == "" {
		chartDir = "/tmp/"
	}
	chartRepo := os.Getenv("CHART_BASE_URL")
	if chartRepo == "" {
		chartRepo = ""
	}
	ssconfig := &cfg.SignStoreConfig{
		CertPoolPath:       certPoolPath,
		ChartDir:           chartDir,
		ChartRepo:          chartRepo,
		SignatureNamespace: signatureNs,
	}
	return ssconfig
}
