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

	ecfgclient "github.com/IBM/integrity-enforcer/verifier/pkg/client/verifierconfig/clientset/versioned/typed/verifierconfig/v1alpha1"
	cfg "github.com/IBM/integrity-enforcer/verifier/pkg/verifier/config"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

type Config struct {
	VerifierConfig *cfg.VerifierConfig
	lastUpdated    time.Time
}

func NewConfig() *Config {
	config := &Config{}
	return config
}

func (conf *Config) InitVerifierConfig() bool {

	renew := false
	t := time.Now()
	if conf.VerifierConfig != nil {

		interval := 20
		if s := os.Getenv("VERIFIER_CM_RELOAD_SEC"); s != "" {
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
		verifierNs := os.Getenv("VERIFIER_NS")
		verifierConfigName := os.Getenv("VERIFIER_CONFIG_NAME")
		verifierConfig := LoadEnforceConfig(verifierNs, verifierConfigName)
		if verifierConfig == nil {
			if conf.VerifierConfig == nil {
				log.Fatal("Failed to initialize VerifierConfig. Exiting...")
			} else {
				verifierConfig = conf.VerifierConfig
				log.Warn("The loaded VerifierConfig is nil, re-use the existing one.")
			}
		}

		chartRepo := os.Getenv("CHART_BASE_URL")
		if chartRepo == "" {
			chartRepo = ""
		}

		if verifierConfig != nil {
			verifierConfig.ChartRepo = chartRepo
			conf.VerifierConfig = verifierConfig
			conf.lastUpdated = t
		}
	}

	return renew
}

func LoadEnforceConfig(namespace, cmname string) *cfg.VerifierConfig {

	config, err := rest.InClusterConfig()
	if err != nil {
		return nil
	}
	clientset, err := ecfgclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return nil
	}
	ecres, err := clientset.VerifierConfigs(namespace).Get(context.Background(), cmname, metav1.GetOptions{})
	if err != nil {
		log.Error("failed to get VerifierConfig:", err.Error())
		return nil
	}

	ec := ecres.Spec.VerifierConfig
	return ec
}
