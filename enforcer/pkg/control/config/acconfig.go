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
	"os"
	"strconv"
	"time"

	cfg "github.com/IBM/integrity-enforcer/enforcer/pkg/config"
)

/**********************************************

		Configs for Helm Release

***********************************************/

type AdmissionControlConfig struct {
	EnforcerConfig *cfg.EnforcerConfig
	lastUpdated    time.Time
}

func NewAdmissionControlConfig() *AdmissionControlConfig {
	acConfig := &AdmissionControlConfig{}
	return acConfig
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
	keyringPath := os.Getenv("KEYRING_PATH")
	if keyringPath == "" {
		keyringPath = "/keyring/pubring.gpg" // default value
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
		KeyringPath:        keyringPath,
		ChartDir:           chartDir,
		ChartRepo:          chartRepo,
		SignatureNamespace: signatureNs,
	}
	return ssconfig
}
