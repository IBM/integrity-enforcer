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

package main

import (
	"context"
	"os"
	"strconv"
	"time"

	ecfgclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/enforcerconfig/clientset/versioned/typed/enforcerconfig/v1alpha1"
	cfg "github.com/IBM/integrity-enforcer/enforcer/pkg/enforcer/config"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

/**********************************************

					Config

***********************************************/

type Config struct {
	EnforcerConfig *cfg.EnforcerConfig
	lastUpdated    time.Time
}

func NewConfig() *Config {
	config := &Config{}
	return config
}

func (conf *Config) InitEnforcerConfig() bool {

	renew := false
	t := time.Now()
	if conf.EnforcerConfig != nil {

		interval := 20
		if s := os.Getenv("ENFORCER_CM_RELOAD_SEC"); s != "" {
			if v, err := strconv.Atoi(s); err != nil {
				interval = v
			}
		}

		duration := t.Sub(conf.lastUpdated)
		if int(duration.Seconds()) > interval {
			renew = true
		}
	} else {
		renew = true
	}

	if renew {
		enforcerNs := os.Getenv("ENFORCER_NS")
		enforcerConfigName := os.Getenv("ENFORCER_CONFIG_NAME")
		enforcerConfig := LoadEnforceConfig(enforcerNs, enforcerConfigName)
		if enforcerConfig == nil {
			if conf.EnforcerConfig == nil {
				log.Fatal("Failed to initialize EnforcerConfig. Exiting...")
			} else {
				enforcerConfig = conf.EnforcerConfig
				log.Warn("The loaded EnforcerConfig is nil, re-use the existing one.")
			}
		}

		chartRepo := os.Getenv("CHART_BASE_URL")
		if chartRepo == "" {
			chartRepo = ""
		}

		if enforcerConfig != nil {
			enforcerConfig.ChartRepo = chartRepo
			conf.EnforcerConfig = enforcerConfig
			conf.lastUpdated = t
		}
	}

	return renew
}

func (conf *Config) HelmIntegrityEnabled() bool {
	return true
}

func LoadEnforceConfig(namespace, cmname string) *cfg.EnforcerConfig {

	config, err := rest.InClusterConfig()
	if err != nil {
		return nil
	}
	clientset, err := ecfgclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return nil
	}
	ecres, err := clientset.EnforcerConfigs(namespace).Get(context.Background(), cmname, metav1.GetOptions{})
	if err != nil {
		log.Error("failed to get EnforcerConfig:", err.Error())
		return nil
	}

	ec := ecres.Spec.EnforcerConfig
	return ec
}
